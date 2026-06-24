package yara

import (
	"context"
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

// MatchedRules 对外导出获取命中规则列表
func (m *matchCollector) MatchedRules() []string {
	return m.matchedRules
}

// NewYaraScanner 加载指定目录下所有.yar/.yara规则
func NewYaraScanner(ruleDir string) (*Scanner, error) {
	var ruleFiles []string

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

// Rules 导出内部规则集
func (s *Scanner) Rules() *yaraLib.Rules {
	return s.rules
}

// ScanProcess 扫描指定PID进程内存
func (s *Scanner) ScanProcess(pid int32) ([]string, error) {
	collector := &matchCollector{}
	var flags yaraLib.ScanFlags = yaraLib.ScanFlagsFastMode
	timeout := 10 * time.Second

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

	for {
		queryErr := windows.VirtualQueryEx(handle, addr, &mbi, unsafe.Sizeof(mbi))
		if queryErr != nil {
			break
		}

		if mbi.State == windows.MEM_COMMIT && isExecutable(mbi.Protect) {
			buf := make([]byte, mbi.RegionSize)
			var bytesRead uintptr
			readErr := windows.ReadProcessMemory(handle, addr, &buf[0], mbi.RegionSize, &bytesRead)
			if readErr == nil && bytesRead > 0 {
				scanErr := s.rules.ScanMem(buf[:bytesRead], flags, timeout, collector)
				if scanErr != nil {
					continue
				}
			}
		}

		addr += mbi.RegionSize
		if addr >= 0x00007fffffffffff {
			break
		}
	}

	return uniqueStrings(collector.matchedRules), nil
}

// ScanFile 新增：扫描本地exe文件，支持ctx中断，返回是否命中恶意规则
func (s *Scanner) ScanFile(ctx context.Context, filePath string) (bool, error) {
	select {
	case <-ctx.Done():
		return false, fmt.Errorf("scan canceled")
	default:
	}

	statInfo, err := os.Stat(filePath)
	if err != nil {
		return false, nil
	}
	if statInfo.IsDir() {
		return false, nil
	}

	fileData, err := os.ReadFile(filePath)
	if err != nil {
		return false, nil
	}

	collector := &matchCollector{}
	scanErr := s.rules.ScanMem(fileData, 0, 0, collector)
	if scanErr != nil {
		return false, scanErr
	}

	return len(collector.MatchedRules()) > 0, nil
}

// Destroy 释放YARA资源
func (s *Scanner) Destroy() {
	if s.rules != nil {
		s.rules.Destroy()
	}
}

// isExecutable 判断内存页是否可执行
func isExecutable(protect uint32) bool {
	return protect&windows.PAGE_EXECUTE != 0 ||
		protect&windows.PAGE_EXECUTE_READ != 0 ||
		protect&windows.PAGE_EXECUTE_READWRITE != 0 ||
		protect&windows.PAGE_EXECUTE_WRITECOPY != 0 ||
		protect&windows.PAGE_READWRITE != 0
}

// uniqueStrings 字符串数组去重
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
