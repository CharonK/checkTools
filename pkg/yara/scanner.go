package yara

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	yaraLib "github.com/hillu/go-yara/v4"
	"golang.org/x/sys/windows"
)

// Scanner Yara进程内存扫描器
type Scanner struct {
	rules *yaraLib.Rules
}

// matchCollector 匹配结果收集器，实现 ScanCallback 接口
type matchCollector struct {
	matchedRules []string
}

// RuleMatching 命中规则时触发，未使用参数用下划线占位
func (m *matchCollector) RuleMatching(_ *yaraLib.ScanContext, rule *yaraLib.Rule) (bool, error) {
	m.matchedRules = append(m.matchedRules, rule.Identifier())
	return true, nil
}

// NewYaraScanner 加载指定目录下所有.yar/.yara规则
func NewYaraScanner(ruleDir string) (*Scanner, error) {
	var ruleFiles []string

	// 递归遍历目录，同时支持.yar和.yara后缀，不区分大小写
	err := filepath.Walk(ruleDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			nameLower := strings.ToLower(info.Name())
			if strings.HasSuffix(nameLower, ".yar") || strings.HasSuffix(nameLower, ".yara") {
				ruleFiles = append(ruleFiles, path)
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("遍历规则目录失败: %w", err)
	}

	if len(ruleFiles) == 0 {
		return nil, fmt.Errorf("目录 %s 下未找到任何规则文件", ruleDir)
	}

	compiler, err := yaraLib.NewCompiler()
	if err != nil {
		return nil, fmt.Errorf("创建Yara编译器失败: %w", err)
	}
	defer compiler.Destroy()

	for _, filePath := range ruleFiles {
		content, readErr := os.ReadFile(filePath)
		if readErr != nil {
			return nil, fmt.Errorf("读取规则文件 %s 失败: %w", filePath, readErr)
		}
		// 以文件名作为命名空间，避免规则重名冲突
		addErr := compiler.AddString(string(content), filepath.Base(filePath))
		if addErr != nil {
			return nil, fmt.Errorf("编译规则 %s 失败: %w", filePath, addErr)
		}
	}

	rules, getErr := compiler.GetRules()
	if getErr != nil {
		return nil, fmt.Errorf("生成规则集合失败: %w", getErr)
	}

	return &Scanner{rules: rules}, nil
}

// ScanProcess 扫描指定PID的进程内存，仅扫描可执行内存页
func (s *Scanner) ScanProcess(pid int32) ([]string, error) {
	collector := &matchCollector{}
	var flags yaraLib.ScanFlags = yaraLib.ScanFlagsFastMode
	// 修正：使用 time.Duration 类型，单块内存扫描超时10秒
	timeout := 10 * time.Second

	// 打开进程，获取查询和读内存权限
	handle, err := windows.OpenProcess(
		windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ,
		false,
		uint32(pid),
	)
	if err != nil {
		return nil, fmt.Errorf("打开进程失败: %w", err)
	}
	defer func() {
		_ = windows.CloseHandle(handle)
	}()

	var addr uintptr
	var mbi windows.MemoryBasicInformation

	// 遍历进程所有内存页
	for {
		queryErr := windows.VirtualQueryEx(handle, addr, &mbi, unsafe.Sizeof(mbi))
		if queryErr != nil {
			break
		}

		// 仅扫描已提交的可执行内存段
		if mbi.State == windows.MEM_COMMIT && isExecutable(mbi.Protect) {
			buf := make([]byte, mbi.RegionSize)
			var bytesRead uintptr
			readErr := windows.ReadProcessMemory(handle, addr, &buf[0], mbi.RegionSize, &bytesRead)
			if readErr == nil && bytesRead > 0 {
				// 对当前内存块执行YARA扫描，单块失败不中断整体流程
				scanErr := s.rules.ScanMem(buf[:bytesRead], flags, timeout, collector)
				if scanErr != nil {
					continue
				}
			}
		}

		addr += mbi.RegionSize
		// 64位用户态地址空间上限，防止溢出
		if addr >= 0x00007fffffffffff {
			break
		}
	}

	// 去重：同一条规则可能在多个内存段命中
	return uniqueStrings(collector.matchedRules), nil
}

// Destroy 释放YARA资源
func (s *Scanner) Destroy() {
	if s.rules != nil {
		s.rules.Destroy()
	}
}

// isExecutable 判断内存保护属性是否包含可执行权限
func isExecutable(protect uint32) bool {
	// 可执行页 + 可读可写页，对抗无权限修改的隐匿场景
	return protect&windows.PAGE_EXECUTE != 0 ||
		protect&windows.PAGE_EXECUTE_READ != 0 ||
		protect&windows.PAGE_EXECUTE_READWRITE != 0 ||
		protect&windows.PAGE_EXECUTE_WRITECOPY != 0 ||
		protect&windows.PAGE_READWRITE != 0
}

// uniqueStrings 字符串去重
func uniqueStrings(slice []string) []string {
	seen := make(map[string]struct{})
	var result []string
	for _, s := range slice {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			result = append(result, s)
		}
	}
	return result
}
