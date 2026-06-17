//go:build windows

package winapi

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	shell32          = windows.NewLazySystemDLL("shell32.dll")
	procShellExecute = shell32.NewProc("ShellExecuteW")
)

// OpenFileLocation 打开资源管理器并选中指定文件
func OpenFileLocation(filePath string) error {
	verb, _ := windows.UTF16PtrFromString("open")
	explorer, _ := windows.UTF16PtrFromString("explorer.exe")
	args, _ := windows.UTF16PtrFromString("/select," + filePath)

	ret, _, _ := procShellExecute.Call(
		0,
		uintptr(unsafe.Pointer(verb)),
		uintptr(unsafe.Pointer(explorer)),
		uintptr(unsafe.Pointer(args)),
		0,
		windows.SW_SHOWNORMAL,
	)
	if ret <= 32 {
		return errors.New("打开文件路径失败")
	}
	return nil
}
