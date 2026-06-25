//go:build windows

package memscan

import (
	"context"
	"encoding/binary"
	"os"
	"sort"
	"syscall"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ===================== 常量定义 =====================
const (
	snapProcessFlag = 0x00000002
	maxPathLen      = 260
	memPrivate      = 0x20000 // MEM_PRIVATE：私有内存类型
)

// ===================== 系统API声明 =====================
var (
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")

	procCreateToolhelp32Snapshot = kernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32FirstW          = kernel32.NewProc("Process32FirstW")
	procProcess32NextW           = kernel32.NewProc("Process32NextW")
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

// stringToUTF16LEBytes 字符串转UTF-16小端字节数组
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
	if maxOffset < 0 {
		return -1
	}
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

// GetMemMatchStream 检索全进程私有内存，匹配指定字符串
func GetMemMatchStream(ctx context.Context, keyword string) <-chan MemMatch {
	outCh := make(chan MemMatch, 10)
	go func() {
		defer close(outCh)
		if keyword == "" {
			return
		}

		selfPid := uint32(os.Getpid())
		utf8Key := []byte(keyword)
		utf16Key := stringToUTF16LEBytes(keyword)

		// 创建进程快照
		snap, _, _ := procCreateToolhelp32Snapshot.Call(snapProcessFlag, 0)
		if snap == ^uintptr(0) {
			return
		}
		defer func() {
			_ = syscall.CloseHandle(syscall.Handle(snap))
		}()

		var pe processSnapEntry
		pe.size = uint32(unsafe.Sizeof(pe))
		var procList []procItem

		// 遍历进程
		ret, _, _ := procProcess32FirstW.Call(snap, uintptr(unsafe.Pointer(&pe)))
		if ret != 0 {
			for {
				pid := pe.processID
				if pid != 0 && pid != 4 && pid != selfPid {
					procName := windows.UTF16ToString(pe.exeFile[:])
					procList = append(procList, procItem{
						pid:  pid,
						name: procName,
					})
				}
				ret, _, _ = procProcess32NextW.Call(snap, uintptr(unsafe.Pointer(&pe)))
				if ret == 0 {
					break
				}
			}
		}

		// 按PID排序
		sort.Slice(procList, func(i, j int) bool {
			return procList[i].pid < procList[j].pid
		})

		// 逐个扫描进程
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

			scanSingleProcess(hProc, proc.pid, proc.name, keyword, utf8Key, utf16Key, outCh, ctx)
			_ = windows.CloseHandle(hProc)
		}
	}()
	return outCh
}

// scanSingleProcess 扫描单个进程的私有内存页
func scanSingleProcess(
	hProc windows.Handle,
	pid uint32,
	procName string,
	keyword string,
	utf8Key, utf16Key []byte,
	outCh chan<- MemMatch,
	ctx context.Context,
) {
	var addr uintptr
	var mbi windows.MemoryBasicInformation
	mbiSize := unsafe.Sizeof(mbi)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// 修复1：VirtualQueryEx 只返回 error，不返回字节数
		queryErr := windows.VirtualQueryEx(hProc, addr, &mbi, uintptr(mbiSize))
		if queryErr != nil {
			break
		}

		// 修复2：使用自定义 memPrivate 常量，只扫描已提交的私有内存
		if mbi.State != windows.MEM_COMMIT || mbi.Type != memPrivate {
			addr = mbi.BaseAddress + mbi.RegionSize
			continue
		}

		// 跳过不可访问、守护页
		if mbi.Protect == windows.PAGE_NOACCESS || mbi.Protect&windows.PAGE_GUARD != 0 {
			addr = mbi.BaseAddress + mbi.RegionSize
			continue
		}

		// 读取内存
		buf := make([]byte, mbi.RegionSize)
		var readBytes uintptr
		readErr := windows.ReadProcessMemory(hProc, mbi.BaseAddress, &buf[0], mbi.RegionSize, &readBytes)
		if readErr != nil || readBytes < uintptr(len(utf8Key)) {
			addr = mbi.BaseAddress + mbi.RegionSize
			continue
		}
		buf = buf[:readBytes]

		// UTF-8 匹配 + 二次校验
		if idx := bytesIndex(buf, utf8Key); idx != -1 {
			matchAddr := mbi.BaseAddress + uintptr(idx)
			if verifyMatch(hProc, matchAddr, utf8Key) {
				outCh <- MemMatch{
					Pid:         pid,
					ProcessName: procName,
					MatchString: keyword,
					Address:     matchAddr,
					MatchType:   "UTF-8",
				}
				return
			}
		}

		// UTF-16 匹配 + 二次校验
		if idx := bytesIndex(buf, utf16Key); idx != -1 {
			matchAddr := mbi.BaseAddress + uintptr(idx)
			if verifyMatch(hProc, matchAddr, utf16Key) {
				outCh <- MemMatch{
					Pid:         pid,
					ProcessName: procName,
					MatchString: keyword,
					Address:     matchAddr,
					MatchType:   "UTF-16",
				}
				return
			}
		}

		addr = mbi.BaseAddress + mbi.RegionSize
	}
}

// verifyMatch 二次校验匹配地址，排除读取异常导致的假阳性
func verifyMatch(hProc windows.Handle, addr uintptr, needle []byte) bool {
	buf := make([]byte, len(needle))
	var readBytes uintptr
	err := windows.ReadProcessMemory(hProc, addr, &buf[0], uintptr(len(needle)), &readBytes)
	if err != nil || readBytes != uintptr(len(needle)) {
		return false
	}
	return bytesIndex(buf, needle) == 0
}
