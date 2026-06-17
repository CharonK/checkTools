//go:build windows

package process

import (
	"errors"
	"strconv"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	maxModuleName      = 256 // 模块名缓冲区长度，Windows API 标准值
	maxPath            = 260 // 文件路径缓冲区长度
	th32CsSnapModule   = 0x00000008
	th32CsSnapModule32 = 0x00000010
)

// MODULEENTRY32 严格对齐 Windows 原生 API 内存布局
type MODULEENTRY32 struct {
	Size         uint32
	ModuleID     uint32
	ProcessID    uint32
	GlblcntUsage uint32
	ProccntUsage uint32
	ModBaseAddr  *byte
	ModBaseSize  uint32
	HModule      windows.Handle
	SzModule     [maxModuleName]uint16
	SzExePath    [maxPath]uint16
}

// ModuleInfo DLL 模块信息
type ModuleInfo struct {
	Name string
	Path string
	Size uint32
	Base uintptr
}

var (
	kernel32Dll        = windows.NewLazySystemDLL("kernel32.dll")
	procModule32FirstW = kernel32Dll.NewProc("Module32FirstW")
	procModule32NextW  = kernel32Dll.NewProc("Module32NextW")
)

// GetProcessModules 获取指定进程加载的所有 DLL 模块
func GetProcessModules(pid int32) ([]ModuleInfo, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(
		th32CsSnapModule|th32CsSnapModule32,
		uint32(pid),
	)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = windows.CloseHandle(snapshot)
	}()

	var me MODULEENTRY32
	me.Size = uint32(unsafe.Sizeof(me))

	// 读取第一个模块，Call 返回的第三个值已封装系统错误
	ret, _, err := procModule32FirstW.Call(
		uintptr(snapshot),
		uintptr(unsafe.Pointer(&me)),
	)
	if ret == 0 {
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return nil, errors.New("权限不足，无法读取该进程模块")
		}
		// 类型断言提取错误码
		if errno, ok := err.(syscall.Errno); ok {
			return nil, errors.New("读取模块列表失败，错误码：" + strconv.Itoa(int(errno)))
		}
		return nil, errors.New("读取模块列表失败")
	}

	var modules []ModuleInfo
	for {
		modules = append(modules, ModuleInfo{
			Name: windows.UTF16ToString(me.SzModule[:]),
			Path: windows.UTF16ToString(me.SzExePath[:]),
			Size: me.ModBaseSize,
			Base: uintptr(unsafe.Pointer(me.ModBaseAddr)),
		})

		// 读取下一个模块
		ret, _, _ = procModule32NextW.Call(
			uintptr(snapshot),
			uintptr(unsafe.Pointer(&me)),
		)
		if ret == 0 {
			break
		}
	}

	return modules, nil
}
