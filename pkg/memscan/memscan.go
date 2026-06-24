//go:build windows

package memscan

import (
	"context"
	"encoding/binary"
	"sort"
	"syscall"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ===================== 系统API声明 =====================
var (
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")

	createProcessSnapProc = kernel32.NewProc("CreateToolhelp32Snapshot")
	processFirstProc      = kernel32.NewProc("Process32FirstW")
	processNextProc       = kernel32.NewProc("Process32NextW")
)

const (
	snapProcessFlag = 0x00000002
	maxPathLen      = 260
)

// processSnapEntry 进程快照信息结构体
type processSnapEntry struct {
	size            uint32
	cntUsage        uint32
	processID       uint32
	defaultHeapID   uintptr
	moduleID        uint32
	cntThreads      uint32
	parentProcessID uint32
	priClassBase    int32
	flags           uint32
	exeFile         [maxPathLen]uint16
}

// procItem 用于排序的进程基础信息
type procItem struct {
	pid  uint32
	name string
}

// MemMatch 内存匹配结果
type MemMatch struct {
	Pid         uint32
	ProcessName string
	MatchString string
	Address     uintptr
	MatchType   string
}

// ===================== 工具函数 =====================

// stringToUTF16LEBytes 字符串转UTF-16小端字节数组，兼容中文检索
func stringToUTF16LEBytes(s string) []byte {
	u16 := utf16.Encode([]rune(s))
	b := make([]byte, len(u16)*2)
	for i, r := range u16 {
		binary.LittleEndian.PutUint16(b[i*2:], r)
	}
	return b
}

// bytesIndex 字节序列查找，返回首次匹配位置
func bytesIndex(haystack, needle []byte) int {
	n := len(needle)
	if n == 0 {
		return 0
	}
	maxOffset := len(haystack) - n
	for i := 0; i <= maxOffset; i++ {
		if haystack[i] == needle[0] {
			match := true
			for j := 1; j < n; j++ {
				if haystack[i+j] != needle[j] {
					match = false
					break
				}
			}
			if match {
				return i
			}
		}
	}
	return -1
}

// ===================== 核心扫描函数 =====================

// GetMemMatchStream 按PID从小到大顺序检索全进程内存，找到匹配即推送结果
func GetMemMatchStream(ctx context.Context, keyword string) <-chan MemMatch {
	outCh := make(chan MemMatch, 10)
	go func() {
		defer close(outCh)
		if keyword == "" {
			return
		}

		utf8Key := []byte(keyword)
		utf16Key := stringToUTF16LEBytes(keyword)

		// 1. 创建进程快照，收集所有进程信息
		snap, _, _ := createProcessSnapProc.Call(snapProcessFlag, 0)
		if snap == ^uintptr(0) {
			return
		}
		defer func() {
			_ = syscall.CloseHandle(syscall.Handle(snap))
		}()

		var pe processSnapEntry
		pe.size = uint32(unsafe.Sizeof(pe))
		var procList []procItem

		// 遍历首个进程
		ret, _, _ := processFirstProc.Call(snap, uintptr(unsafe.Pointer(&pe)))
		if ret != 0 {
			for {
				pid := pe.processID
				// 跳过系统空闲进程
				if pid != 0 && pid != 4 {
					procName := windows.UTF16ToString(pe.exeFile[:])
					procList = append(procList, procItem{
						pid:  pid,
						name: procName,
					})
				}
				// 取下一个进程
				ret, _, _ = processNextProc.Call(snap, uintptr(unsafe.Pointer(&pe)))
				if ret == 0 {
					break
				}
			}
		}

		// 2. 按PID从小到大排序
		sort.Slice(procList, func(i, j int) bool {
			return procList[i].pid < procList[j].pid
		})

		// 3. 按排序后的顺序逐个扫描进程内存
		for _, proc := range procList {
			select {
			case <-ctx.Done():
				return
			default:
			}

			hProc, openErr := windows.OpenProcess(
				windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ,
				false, proc.pid,
			)
			if openErr != nil {
				continue
			}

			_ = scanSingleProcess(hProc, proc.pid, proc.name, keyword, utf8Key, utf16Key, outCh, ctx)
			_ = windows.CloseHandle(hProc)
		}
	}()
	return outCh
}

// scanSingleProcess 扫描单个进程的所有可读内存页
func scanSingleProcess(
	hProc windows.Handle,
	pid uint32,
	procName string,
	keyword string,
	utf8Key, utf16Key []byte,
	outCh chan<- MemMatch,
	ctx context.Context,
) bool {
	var addr uintptr = 0
	var mbi windows.MemoryBasicInformation

	for {
		select {
		case <-ctx.Done():
			return false
		default:
		}

		// 查询内存页信息
		queryErr := windows.VirtualQueryEx(hProc, addr, &mbi, uintptr(unsafe.Sizeof(mbi)))
		if queryErr != nil {
			break
		}

		// 只扫描已提交内存
		if mbi.State != windows.MEM_COMMIT {
			addr = mbi.BaseAddress + mbi.RegionSize
			continue
		}

		// 跳过不可访问、守护页
		if mbi.Protect == windows.PAGE_NOACCESS || mbi.Protect&windows.PAGE_GUARD != 0 {
			addr = mbi.BaseAddress + mbi.RegionSize
			continue
		}

		// 读取内存内容
		buf := make([]byte, mbi.RegionSize)
		var readBytes uintptr
		readErr := windows.ReadProcessMemory(hProc, mbi.BaseAddress, &buf[0], mbi.RegionSize, &readBytes)
		if readErr != nil || readBytes == 0 {
			addr = mbi.BaseAddress + mbi.RegionSize
			continue
		}
		buf = buf[:readBytes]

		// UTF-8 匹配
		if idx := bytesIndex(buf, utf8Key); idx != -1 {
			outCh <- MemMatch{
				Pid:         pid,
				ProcessName: procName,
				MatchString: keyword,
				Address:     mbi.BaseAddress + uintptr(idx),
				MatchType:   "UTF-8",
			}
			return true
		}

		// UTF-16 匹配（中文、系统字符串）
		if idx := bytesIndex(buf, utf16Key); idx != -1 {
			outCh <- MemMatch{
				Pid:         pid,
				ProcessName: procName,
				MatchString: keyword,
				Address:     mbi.BaseAddress + uintptr(idx),
				MatchType:   "UTF-16",
			}
			return true
		}

		addr = mbi.BaseAddress + mbi.RegionSize
	}
	return false
}
