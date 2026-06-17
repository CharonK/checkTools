//go:build windows

package winapi

import (
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// GetFileTimes 获取文件的创建时间和修改时间（Windows本地时间）
func GetFileTimes(filePath string) (time.Time, time.Time, error) {
	if filePath == "" {
		return time.Time{}, time.Time{}, nil
	}

	pathPtr, err := windows.UTF16PtrFromString(filePath)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}

	var data windows.Win32FileAttributeData
	err = windows.GetFileAttributesEx(
		pathPtr,
		windows.GetFileExInfoStandard,
		(*byte)(unsafe.Pointer(&data)),
	)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}

	// FILETIME 转本地时间
	createTime := time.Unix(0, data.CreationTime.Nanoseconds()).Local()
	modifyTime := time.Unix(0, data.LastWriteTime.Nanoseconds()).Local()

	return createTime, modifyTime, nil
}
