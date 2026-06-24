//go:build windows

package trace

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	"golang.org/x/sys/windows"
)

// ===================== 系统API声明 =====================
var (
	advapi32          = windows.NewLazySystemDLL("advapi32.dll")
	procRegEnumValueW = advapi32.NewProc("RegEnumValueW")
)

func regEnumValue(
	hKey windows.Handle,
	dwIndex uint32,
	lpValueName *uint16,
	lpcchValueName *uint32,
	lpReserved *uint32,
	lpType *uint32,
	lpData *byte,
	lpcbData *uint32,
) error {
	ret, _, _ := procRegEnumValueW.Call(
		uintptr(hKey),
		uintptr(dwIndex),
		uintptr(unsafe.Pointer(lpValueName)),
		uintptr(unsafe.Pointer(lpcchValueName)),
		0,
		uintptr(unsafe.Pointer(lpType)),
		uintptr(unsafe.Pointer(lpData)),
		uintptr(unsafe.Pointer(lpcbData)),
	)
	if ret != 0 {
		return windows.Errno(ret)
	}
	return nil
}

// ===================== 公共工具 =====================

// rot13 ROT13加解密，用于UserAssist名称解析
func rot13(s string) string {
	var res strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			res.WriteRune('a' + (r-'a'+13)%26)
		case r >= 'A' && r <= 'Z':
			res.WriteRune('A' + (r-'A'+13)%26)
		default:
			res.WriteRune(r)
		}
	}
	return res.String()
}

// filetimeToTime 安全转换Windows FILETIME到Go标准时间
func filetimeToTime(ft windows.Filetime) time.Time {
	const epochDiff100ns uint64 = 116444736000000000
	ftValue := uint64(ft.HighDateTime)<<32 | uint64(ft.LowDateTime)
	if ftValue < epochDiff100ns {
		return time.Time{}
	}
	nsec := int64(ftValue-epochDiff100ns) * 100
	if nsec < 0 {
		return time.Time{}
	}
	return time.Unix(0, nsec)
}

// ===================== 1. Prefetch 预读取记录 =====================

type PrefetchInfo struct {
	RunTime time.Time
	ExeName string
	ExePath string
}

// GetPrefetchListStream 按时间从近到远排序后流式输出
func GetPrefetchListStream(ctx context.Context) <-chan PrefetchInfo {
	outCh := make(chan PrefetchInfo, 10)
	go func() {
		defer close(outCh)

		var list []PrefetchInfo
		prefetchDir := `C:\Windows\Prefetch`
		_ = filepath.Walk(prefetchDir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			if !strings.HasSuffix(strings.ToLower(info.Name()), ".pf") {
				return nil
			}

			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			baseName := strings.TrimSuffix(info.Name(), ".pf")
			exeName := baseName
			if idx := strings.LastIndex(baseName, "-"); idx > 0 {
				exeName = baseName[:idx]
			}

			list = append(list, PrefetchInfo{
				RunTime: info.ModTime(),
				ExeName: exeName,
				ExePath: path,
			})
			return nil
		})

		// 按时间降序：最近的在前
		sort.Slice(list, func(i, j int) bool {
			return list[i].RunTime.After(list[j].RunTime)
		})

		// 逐条推送
		for _, item := range list {
			select {
			case <-ctx.Done():
				return
			default:
			}
			outCh <- item
			time.Sleep(5 * time.Millisecond)
		}
	}()
	return outCh
}

// ===================== 2. UserAssist 用户活动记录 =====================

type UserAssistInfo struct {
	LastRunTime time.Time
	ExeName     string
	ExePath     string
	RunCount    int
	FocusCount  int
}

// GetUserAssistListStream 按最后运行时间从近到远排序后流式输出
func GetUserAssistListStream(ctx context.Context) <-chan UserAssistInfo {
	outCh := make(chan UserAssistInfo, 10)
	go func() {
		defer close(outCh)

		var list []UserAssistInfo
		baseRegPath := `Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist`
		pathPtr, _ := windows.UTF16PtrFromString(baseRegPath)

		var hRoot windows.Handle
		if err := windows.RegOpenKeyEx(windows.HKEY_CURRENT_USER, pathPtr, 0, windows.KEY_READ, &hRoot); err != nil {
			return
		}
		defer func() { _ = windows.RegCloseKey(hRoot) }()

		var subKeyCount, maxNameLen uint32
		_ = windows.RegQueryInfoKey(hRoot, nil, nil, nil, &subKeyCount, &maxNameLen, nil, nil, nil, nil, nil, nil)

		for i := uint32(0); i < subKeyCount; i++ {
			select {
			case <-ctx.Done():
				return
			default:
			}

			nameBuf := make([]uint16, maxNameLen+1)
			nameLen := maxNameLen + 1
			if err := windows.RegEnumKeyEx(hRoot, i, &nameBuf[0], &nameLen, nil, nil, nil, nil); err != nil {
				continue
			}
			guidName := windows.UTF16ToString(nameBuf[:nameLen])

			countPath := baseRegPath + `\` + guidName + `\Count`
			countPtr, _ := windows.UTF16PtrFromString(countPath)
			var hCount windows.Handle
			if err := windows.RegOpenKeyEx(windows.HKEY_CURRENT_USER, countPtr, 0, windows.KEY_READ, &hCount); err != nil {
				continue
			}

			var valCount, maxValName, maxValData uint32
			_ = windows.RegQueryInfoKey(hCount, nil, nil, nil, nil, nil, nil, &valCount, &maxValName, &maxValData, nil, nil)

			for j := uint32(0); j < valCount; j++ {
				select {
				case <-ctx.Done():
					_ = windows.RegCloseKey(hCount)
					return
				default:
				}

				vNameBuf := make([]uint16, maxValName+1)
				vNameLen := maxValName + 1
				vDataBuf := make([]byte, maxValData)
				vDataLen := maxValData
				var vType uint32

				if err := regEnumValue(hCount, j, &vNameBuf[0], &vNameLen, nil, &vType, &vDataBuf[0], &vDataLen); err != nil {
					continue
				}

				encryptedPath := windows.UTF16ToString(vNameBuf[:vNameLen])
				fullPath := rot13(encryptedPath)
				exeName := filepath.Base(fullPath)

				runCount, focusCount := 0, 0
				lastRun := time.Time{}
				if len(vDataBuf) >= 72 {
					runCount = int(binary.LittleEndian.Uint32(vDataBuf[4:8]))
					focusCount = int(binary.LittleEndian.Uint32(vDataBuf[8:12]))
					low := binary.LittleEndian.Uint32(vDataBuf[60:64])
					high := binary.LittleEndian.Uint32(vDataBuf[64:68])
					lastRun = filetimeToTime(windows.Filetime{LowDateTime: low, HighDateTime: high})
				}

				list = append(list, UserAssistInfo{
					LastRunTime: lastRun,
					ExeName:     exeName,
					ExePath:     fullPath,
					RunCount:    runCount,
					FocusCount:  focusCount,
				})
			}
			_ = windows.RegCloseKey(hCount)
		}

		// 按时间降序：最近的在前，无时间的放最后
		sort.Slice(list, func(i, j int) bool {
			if list[i].LastRunTime.IsZero() {
				return false
			}
			if list[j].LastRunTime.IsZero() {
				return true
			}
			return list[i].LastRunTime.After(list[j].LastRunTime)
		})

		for _, item := range list {
			select {
			case <-ctx.Done():
				return
			default:
			}
			outCh <- item
			time.Sleep(5 * time.Millisecond)
		}
	}()
	return outCh
}

// ===================== 3. Recent File 最近文件记录 =====================

type RecentFileInfo struct {
	FileName   string
	FilePath   string
	CreateTime time.Time
	ModifyTime time.Time
	TargetPath string
}

// resolveLnkTarget 解析快捷方式目标路径
func resolveLnkTarget(shell *ole.IDispatch, lnkPath string) string {
	if shell == nil {
		return "无法解析"
	}
	scRes, err := oleutil.CallMethod(shell, "CreateShortcut", lnkPath)
	if err != nil {
		return "无法解析"
	}
	shortcut := scRes.ToIDispatch()
	defer shortcut.Release()
	target, _ := oleutil.GetProperty(shortcut, "TargetPath")
	return target.ToString()
}

// GetRecentFilesStream 按修改时间从近到远排序后流式输出
func GetRecentFilesStream(ctx context.Context) <-chan RecentFileInfo {
	outCh := make(chan RecentFileInfo, 10)
	go func() {
		defer close(outCh)

		_ = ole.CoInitializeEx(0, ole.COINIT_APARTMENTTHREADED)
		defer ole.CoUninitialize()

		var shell *ole.IDispatch
		unk, err := oleutil.CreateObject("WScript.Shell")
		if err == nil {
			shell, _ = unk.QueryInterface(ole.IID_IDispatch)
			defer shell.Release()
		}

		var list []RecentFileInfo
		recentDir := filepath.Join(os.Getenv("APPDATA"), `Microsoft\Windows\Recent`)
		_ = filepath.Walk(recentDir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}

			nameLower := strings.ToLower(info.Name())
			if nameLower == "desktop.ini" || nameLower == "thumbs.db" {
				return nil
			}

			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			createTime := time.Time{}
			if sysAttr, ok := info.Sys().(*syscall.Win32FileAttributeData); ok {
				createTime = time.Unix(0, sysAttr.CreationTime.Nanoseconds())
			}

			targetPath := "非快捷方式"
			if strings.HasSuffix(nameLower, ".lnk") {
				targetPath = resolveLnkTarget(shell, path)
			}

			list = append(list, RecentFileInfo{
				FileName:   info.Name(),
				FilePath:   path,
				CreateTime: createTime,
				ModifyTime: info.ModTime(),
				TargetPath: targetPath,
			})
			return nil
		})

		// 按修改时间降序：最近的在前
		sort.Slice(list, func(i, j int) bool {
			return list[i].ModifyTime.After(list[j].ModifyTime)
		})

		for _, item := range list {
			select {
			case <-ctx.Done():
				return
			default:
			}
			outCh <- item
			time.Sleep(5 * time.Millisecond)
		}
	}()
	return outCh
}
