//go:build windows

package winapi

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32                 = windows.NewLazySystemDLL("kernel32.dll")
	procGetSystemTimes       = kernel32.NewProc("GetSystemTimes")
	procGlobalMemoryStatusEx = kernel32.NewProc("GlobalMemoryStatusEx")
)

type memoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

// 缓存上一次采样的系统时间，用于差值计算
var (
	lastIdleTime   int64
	lastKernelTime int64
	lastUserTime   int64
	isFirstSample  = true
)

// GetSystemCPUUsage 获取系统整体CPU使用率，与任务管理器对齐
// 需间隔1秒连续调用，首次调用返回0作为基准值
func GetSystemCPUUsage() float64 {
	var idleTime, kernelTime, userTime windows.Filetime
	ret, _, _ := procGetSystemTimes.Call(
		uintptr(unsafe.Pointer(&idleTime)),
		uintptr(unsafe.Pointer(&kernelTime)),
		uintptr(unsafe.Pointer(&userTime)),
	)
	if ret == 0 {
		return 0
	}

	// FILETIME 转 64 位整数（单位：100纳秒）
	idle := int64(uint64(idleTime.HighDateTime)<<32 | uint64(idleTime.LowDateTime))
	kernel := int64(uint64(kernelTime.HighDateTime)<<32 | uint64(kernelTime.LowDateTime))
	user := int64(uint64(userTime.HighDateTime)<<32 | uint64(userTime.LowDateTime))

	// 首次采样仅初始化基准值
	if isFirstSample {
		lastIdleTime = idle
		lastKernelTime = kernel
		lastUserTime = user
		isFirstSample = false
		return 0
	}

	// 计算两次采样的差值
	idleDelta := idle - lastIdleTime
	kernelDelta := kernel - lastKernelTime
	userDelta := user - lastUserTime
	totalDelta := kernelDelta + userDelta

	// 更新基准值
	lastIdleTime = idle
	lastKernelTime = kernel
	lastUserTime = user

	if totalDelta <= 0 {
		return 0
	}

	// CPU使用率 = 1 - 空闲时间增量 / 系统总时间增量
	usage := 1.0 - float64(idleDelta)/float64(totalDelta)
	return usage * 100
}

// GetSystemMemoryInfo 获取系统整体内存信息
// 返回：内存使用率百分比、总物理内存(MB)、已用物理内存(MB)
func GetSystemMemoryInfo() (loadPercent uint32, totalMB, usedMB uint64) {
	var msx memoryStatusEx
	msx.Length = uint32(unsafe.Sizeof(msx))
	ret, _, _ := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&msx)))
	if ret == 0 {
		return 0, 0, 0
	}
	totalMB = msx.TotalPhys / 1024 / 1024
	usedMB = (msx.TotalPhys - msx.AvailPhys) / 1024 / 1024
	return msx.MemoryLoad, totalMB, usedMB
}
