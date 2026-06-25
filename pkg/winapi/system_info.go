//go:build windows

package winapi

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32           = windows.NewLazySystemDLL("kernel32.dll")
	procGetSystemTimes = kernel32.NewProc("GetSystemTimes")
)

var (
	lastIdle    int64
	lastKernel  int64
	lastUser    int64
	firstSample = true
	smoothed    float64
)

const alpha = 0.3

// GetSystemCPUUsage 获取系统全局CPU使用率（0-100）
// 需间隔1秒连续调用，首次返回0作为基准值
func GetSystemCPUUsage() float64 {
	var idle, kernel, user windows.Filetime
	ret, _, _ := procGetSystemTimes.Call(
		uintptr(unsafe.Pointer(&idle)),
		uintptr(unsafe.Pointer(&kernel)),
		uintptr(unsafe.Pointer(&user)),
	)
	if ret == 0 {
		return 0
	}

	idleVal := int64(uint64(idle.HighDateTime)<<32 | uint64(idle.LowDateTime))
	kernelVal := int64(uint64(kernel.HighDateTime)<<32 | uint64(kernel.LowDateTime))
	userVal := int64(uint64(user.HighDateTime)<<32 | uint64(user.LowDateTime))

	if firstSample {
		lastIdle = idleVal
		lastKernel = kernelVal
		lastUser = userVal
		firstSample = false
		return 0
	}

	idleDelta := idleVal - lastIdle
	kernelDelta := kernelVal - lastKernel
	userDelta := userVal - lastUser
	totalDelta := kernelDelta + userDelta

	lastIdle = idleVal
	lastKernel = kernelVal
	lastUser = userVal

	if totalDelta <= 0 {
		return smoothed
	}

	raw := (1.0 - float64(idleDelta)/float64(totalDelta)) * 100

	if smoothed == 0 {
		smoothed = raw
	} else {
		smoothed = alpha*raw + (1-alpha)*smoothed
	}

	return smoothed
}
