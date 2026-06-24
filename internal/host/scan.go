//go:build windows
// +build windows

package host

import (
	"bytes"
	"context"
	"io"
	"os/exec"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"

	"Scan/pkg/winapi"
	"Scan/pkg/yara"
)

// ===================== 系统DLL声明 =====================
var (
	netapi32             = windows.NewLazySystemDLL("netapi32.dll")
	procNetUserEnum      = netapi32.NewProc("NetUserEnum")
	procNetApiBufferFree = netapi32.NewProc("NetApiBufferFree")

	advapi32          = windows.NewLazySystemDLL("advapi32.dll")
	procRegEnumValueW = advapi32.NewProc("RegEnumValueW")
)

// ===================== 公共工具函数 =====================

// gbkToUtf8 GBK转UTF8，仅用于命令行输出
func gbkToUtf8(raw []byte) string {
	dec := transform.NewReader(bytes.NewReader(raw), simplifiedchinese.GBK.NewDecoder())
	buf, _ := io.ReadAll(dec)
	return string(buf)
}

// ExtractExePath 从完整命令行提取纯exe路径（用于签名/YARA扫描）
func ExtractExePath(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.HasPrefix(raw, `"`) {
		idx := strings.Index(raw[1:], `"`)
		if idx > 0 {
			return raw[1 : idx+1]
		}
	}
	parts := strings.Fields(raw)
	for _, p := range parts {
		low := strings.ToLower(p)
		if strings.HasSuffix(low, ".exe") || strings.HasSuffix(low, ".dll") {
			return p
		}
	}
	return raw
}

// CheckFileSignAndYara 复用已有签名+YARA实现
func CheckFileSignAndYara(ctx context.Context, rawCmd string, scanner *yara.Scanner) (signText string, yaraHit bool) {
	exePath := ExtractExePath(rawCmd)
	if exePath == "" || !strings.HasSuffix(strings.ToLower(exePath), ".exe") {
		return "未知文件", false
	}
	signText = winapi.VerifyFileSignature(exePath)
	yaraHit, _ = scanner.ScanFile(ctx, exePath)
	return signText, yaraHit
}

// SplitCsvLine CSV分割
func SplitCsvLine(s string) []string {
	var res []string
	var buf []rune
	quote := false
	for _, r := range s {
		switch r {
		case '"':
			quote = !quote
		case ',':
			if !quote {
				res = append(res, string(buf))
				buf = buf[:0]
				continue
			}
		}
		buf = append(buf, r)
	}
	res = append(res, string(buf))
	for i := range res {
		res[i] = strings.Trim(res[i], `" `)
	}
	return res
}

func safeGetField(fields []string, idx int) string {
	if idx >= 0 && idx < len(fields) {
		return strings.TrimSpace(fields[idx])
	}
	return ""
}

// ===================== 1. 用户信息 =====================

type UserInfo struct {
	UserName string
	Status   string
	Remark   string
}

type userInfo1 struct {
	Name        *uint16
	Password    *uint16
	PasswordAge uint32
	Priv        uint32
	HomeDir     *uint16
	Comment     *uint16
	Flags       uint32
	ScriptPath  *uint16
}

const (
	filterNormalAccount = 2
	ufAccountDisable    = 0x0002
)

// GetAllUserListStream 原生API枚举用户列表
func GetAllUserListStream(ctx context.Context) <-chan UserInfo {
	outCh := make(chan UserInfo, 10)
	go func() {
		defer close(outCh)

		var entriesRead uint32
		var totalEntries uint32
		var resumeHandle uint32
		var bufptr unsafe.Pointer

		ret, _, _ := procNetUserEnum.Call(
			0,
			1,
			filterNormalAccount,
			uintptr(unsafe.Pointer(&bufptr)),
			uintptr(^uint32(0)),
			uintptr(unsafe.Pointer(&entriesRead)),
			uintptr(unsafe.Pointer(&totalEntries)),
			uintptr(unsafe.Pointer(&resumeHandle)),
		)
		if ret != 0 {
			return
		}
		defer procNetApiBufferFree.Call(uintptr(bufptr))

		users := unsafe.Slice((*userInfo1)(bufptr), entriesRead)
		for _, u := range users {
			select {
			case <-ctx.Done():
				return
			default:
			}

			userName := windows.UTF16PtrToString(u.Name)
			if userName == "" {
				continue
			}

			info := UserInfo{UserName: userName}
			if u.Flags&ufAccountDisable != 0 {
				info.Status = "禁用"
			} else {
				info.Status = "启用"
			}

			info.Remark = windows.UTF16PtrToString(u.Comment)
			if info.Remark == "" {
				info.Remark = "正常账户"
			}
			outCh <- info
		}
	}()
	return outCh
}

// ===================== 2. 计划任务【修复版：修复乱行+新增文件路径】 =====================

type TaskInfo struct {
	TaskName    string
	FilePath    string // 任务配置文件完整路径
	CmdPath     string
	Arguments   string
	RunUser     string
	TriggerTime string
	Description string
	SignInfo    string
	YaraResult  string
	Remark      string
}

// 系统计划任务配置文件根目录
const taskConfigBaseDir = `C:\Windows\System32\Tasks`

// GetAllTaskListStream 枚举根目录计划任务，字段与计算机管理完全对齐
func GetAllTaskListStream(ctx context.Context, scanner *yara.Scanner) <-chan TaskInfo {
	outCh := make(chan TaskInfo, 10)
	go func() {
		defer close(outCh)

		cmd := exec.CommandContext(ctx, "schtasks", "/query", "/v", "/fo", "csv")
		rawOut, err := cmd.CombinedOutput()
		if err != nil {
			return
		}
		out := gbkToUtf8(rawOut)
		out = strings.ReplaceAll(out, "\r\n", "\n")
		allLines := strings.Split(out, "\n")
		if len(allLines) < 2 {
			return
		}

		// 动态解析表头
		headerLine := strings.TrimSpace(allLines[0])
		headerFields := SplitCsvLine(headerLine)
		nameIdx, cmdIdx, userIdx, descIdx, triggerIdx := -1, -1, -1, -1, -1
		for i, h := range headerFields {
			h = strings.TrimSpace(h)
			switch h {
			case "任务名称":
				nameIdx = i
			case "要运行的任务":
				cmdIdx = i
			case "任务登录方式":
				userIdx = i
			case "注释":
				descIdx = i
			case "下一次运行时间":
				triggerIdx = i
			}
		}
		// 兜底兼容
		if nameIdx == -1 {
			nameIdx = 1
		}
		if cmdIdx == -1 {
			cmdIdx = 8
		}
		if userIdx == -1 {
			userIdx = 14
		}
		if descIdx == -1 {
			descIdx = 10
		}
		if triggerIdx == -1 {
			triggerIdx = 2
		}

		// 计算最大索引，过滤字段不足的行
		maxIdx := nameIdx
		if cmdIdx > maxIdx {
			maxIdx = cmdIdx
		}
		if userIdx > maxIdx {
			maxIdx = userIdx
		}
		if descIdx > maxIdx {
			maxIdx = descIdx
		}
		if triggerIdx > maxIdx {
			maxIdx = triggerIdx
		}

		// 遍历数据行
		for i := 1; i < len(allLines); i++ {
			select {
			case <-ctx.Done():
				return
			default:
			}

			line := strings.TrimSpace(allLines[i])
			if line == "" {
				continue
			}
			fields := SplitCsvLine(line)
			// 修复1：字段不足直接跳过，避免错位
			if len(fields) <= maxIdx {
				continue
			}
			// 修复2：过滤文件夹汇总行
			firstCol := strings.TrimSpace(fields[0])
			if strings.HasPrefix(firstCol, "文件夹:") {
				continue
			}

			taskFullPath := strings.TrimSpace(fields[nameIdx])
			// 修复3：合法任务路径必须以 \ 开头，过滤掉所有无效行（状态行、拆分残行）
			if !strings.HasPrefix(taskFullPath, "\\") {
				continue
			}
			// 修复4：仅保留根目录任务
			if strings.Count(taskFullPath, "\\") > 1 {
				continue
			}

			taskName := strings.TrimPrefix(taskFullPath, "\\")
			if taskName == "" {
				continue
			}

			fullCmd := strings.TrimSpace(fields[cmdIdx])
			// 过滤COM处理程序
			if fullCmd == "COM 处理程序" || fullCmd == "COM处理程序" {
				continue
			}

			// 解析命令和参数
			exePath := ExtractExePath(fullCmd)
			args := ""
			if len(fullCmd) > len(exePath) {
				args = strings.TrimSpace(fullCmd[len(exePath):])
			}

			// 描述精简
			description := strings.TrimSpace(safeGetField(fields, descIdx))
			description = strings.ReplaceAll(description, "\n", " ")
			description = strings.ReplaceAll(description, "\r", " ")
			for strings.Contains(description, "  ") {
				description = strings.ReplaceAll(description, "  ", " ")
			}
			if description == "" || strings.EqualFold(description, "N/A") {
				description = "无描述"
			}

			// 触发器时间
			triggerTime := strings.TrimSpace(safeGetField(fields, triggerIdx))
			if triggerTime == "" || strings.EqualFold(triggerTime, "N/A") {
				triggerTime = "未设置"
			}

			// 拼接任务配置文件路径
			taskFilePath := taskConfigBaseDir + taskFullPath

			task := TaskInfo{
				TaskName:    taskName,
				FilePath:    taskFilePath,
				CmdPath:     exePath,
				Arguments:   args,
				RunUser:     strings.TrimSpace(safeGetField(fields, userIdx)),
				TriggerTime: triggerTime,
				Description: description,
				Remark:      "正常",
			}

			// 签名+YARA扫描
			if exePath != "" && scanner != nil {
				sign, hit := CheckFileSignAndYara(ctx, fullCmd, scanner)
				task.SignInfo = sign
				if hit {
					task.YaraResult = "命中"
					task.Remark = "恶意程序"
				} else {
					task.YaraResult = "正常"
				}
			} else {
				task.SignInfo = "未签名"
				task.YaraResult = "正常"
			}

			outCh <- task
			time.Sleep(10 * time.Millisecond)
		}
	}()
	return outCh
}

// ===================== 3. 系统服务 =====================

type ServiceInfo struct {
	SvcName     string
	Status      string
	Description string
	BinPath     string
	SignInfo    string
	YaraResult  string
}

const (
	SC_ENUM_PROCESS_INFO = 0
)

// GetAllServiceListStream 枚举Win32系统服务
func GetAllServiceListStream(ctx context.Context, scanner *yara.Scanner) <-chan ServiceInfo {
	outChan := make(chan ServiceInfo, 2)
	go func() {
		defer close(outChan)

		scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_ENUMERATE_SERVICE|windows.SC_MANAGER_CONNECT)
		if err != nil {
			return
		}
		defer windows.CloseServiceHandle(scm)

		var bytesNeeded uint32
		var servicesReturned uint32
		var resumeHandle uint32
		_ = windows.EnumServicesStatusEx(
			scm,
			SC_ENUM_PROCESS_INFO,
			windows.SERVICE_WIN32,
			windows.SERVICE_STATE_ALL,
			nil,
			0,
			&bytesNeeded,
			&servicesReturned,
			&resumeHandle,
			nil,
		)

		if bytesNeeded == 0 {
			return
		}

		buf := make([]byte, bytesNeeded)
		err = windows.EnumServicesStatusEx(
			scm,
			SC_ENUM_PROCESS_INFO,
			windows.SERVICE_WIN32,
			windows.SERVICE_STATE_ALL,
			&buf[0],
			bytesNeeded,
			&bytesNeeded,
			&servicesReturned,
			&resumeHandle,
			nil,
		)
		if err != nil {
			return
		}

		services := unsafe.Slice((*windows.ENUM_SERVICE_STATUS_PROCESS)(unsafe.Pointer(&buf[0])), servicesReturned)

		for _, svc := range services {
			select {
			case <-ctx.Done():
				return
			default:
			}

			svcName := windows.UTF16PtrToString(svc.ServiceName)
			info := ServiceInfo{SvcName: svcName}

			switch svc.ServiceStatusProcess.CurrentState {
			case windows.SERVICE_RUNNING:
				info.Status = "服务正在运行"
			default:
				info.Status = "服务已停止"
			}

			hService, err := windows.OpenService(scm, svc.ServiceName, windows.SERVICE_QUERY_CONFIG)
			if err == nil {
				var configSize uint32
				_ = windows.QueryServiceConfig(hService, nil, 0, &configSize)
				if configSize > 0 {
					configBuf := make([]byte, configSize)
					config := (*windows.QUERY_SERVICE_CONFIG)(unsafe.Pointer(&configBuf[0]))
					if windows.QueryServiceConfig(hService, config, configSize, &configSize) == nil {
						info.BinPath = windows.UTF16PtrToString(config.BinaryPathName)
					}
				}

				var descSize uint32
				_ = windows.QueryServiceConfig2(hService, windows.SERVICE_CONFIG_DESCRIPTION, nil, 0, &descSize)
				if descSize > 0 {
					descBuf := make([]byte, descSize)
					desc := (*windows.SERVICE_DESCRIPTION)(unsafe.Pointer(&descBuf[0]))
					if windows.QueryServiceConfig2(hService, windows.SERVICE_CONFIG_DESCRIPTION, &descBuf[0], descSize, &descSize) == nil && desc.Description != nil {
						info.Description = windows.UTF16PtrToString(desc.Description)
					}
				}
				windows.CloseServiceHandle(hService)
			}

			if info.Description == "" {
				info.Description = "无描述"
			}

			sign, hit := CheckFileSignAndYara(ctx, info.BinPath, scanner)
			info.SignInfo = sign
			if hit {
				info.YaraResult = "命中"
			} else {
				info.YaraResult = "正常"
			}

			outChan <- info
		}
	}()
	return outChan
}

// ===================== 4. 开机启动项 =====================

type StartupItem struct {
	ItemName string
	ExePath  string
	SignInfo string
	YaraRes  string
}

// regEnumValue 封装原生注册表枚举API
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
		uintptr(unsafe.Pointer(lpReserved)),
		uintptr(unsafe.Pointer(lpType)),
		uintptr(unsafe.Pointer(lpData)),
		uintptr(unsafe.Pointer(lpcbData)),
	)
	if ret != 0 {
		return windows.Errno(ret)
	}
	return nil
}

// GetAllStartupListStream 枚举注册表启动项
func GetAllStartupListStream(ctx context.Context, scanner *yara.Scanner) <-chan StartupItem {
	outChan := make(chan StartupItem, 2)
	go func() {
		defer close(outChan)

		regPaths := []struct {
			hive windows.Handle
			path string
		}{
			{windows.HKEY_CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`},
			{windows.HKEY_CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\RunOnce`},
			{windows.HKEY_LOCAL_MACHINE, `Software\Microsoft\Windows\CurrentVersion\Run`},
			{windows.HKEY_LOCAL_MACHINE, `Software\Microsoft\Windows\CurrentVersion\RunOnce`},
			{windows.HKEY_LOCAL_MACHINE, `Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`},
		}

		for _, rp := range regPaths {
			select {
			case <-ctx.Done():
				return
			default:
			}

			pathPtr, err := windows.UTF16PtrFromString(rp.path)
			if err != nil {
				continue
			}

			var hKey windows.Handle
			err = windows.RegOpenKeyEx(rp.hive, pathPtr, 0, windows.KEY_READ, &hKey)
			if err != nil {
				continue
			}

			var valueCount uint32
			var maxNameLen uint32
			var maxDataLen uint32
			_ = windows.RegQueryInfoKey(hKey, nil, nil, nil, nil, nil, nil, &valueCount, &maxNameLen, &maxDataLen, nil, nil)

			for i := uint32(0); i < valueCount; i++ {
				nameBuf := make([]uint16, maxNameLen+1)
				nameLen := maxNameLen + 1
				dataBuf := make([]byte, maxDataLen)
				dataLen := maxDataLen
				var valueType uint32

				err := regEnumValue(
					hKey,
					i,
					&nameBuf[0],
					&nameLen,
					nil,
					&valueType,
					&dataBuf[0],
					&dataLen,
				)
				if err != nil {
					continue
				}

				name := windows.UTF16ToString(nameBuf[:nameLen])
				var fullData string
				if valueType == windows.REG_SZ && dataLen >= 2 {
					dataUint16 := unsafe.Slice((*uint16)(unsafe.Pointer(&dataBuf[0])), dataLen/2)
					fullData = windows.UTF16ToString(dataUint16)
				} else {
					fullData = windows.BytePtrToString(&dataBuf[0])
				}

				sign, hit := CheckFileSignAndYara(ctx, fullData, scanner)
				item := StartupItem{
					ItemName: name,
					ExePath:  fullData,
					SignInfo: sign,
				}
				if hit {
					item.YaraRes = "命中"
				} else {
					item.YaraRes = "正常"
				}
				outChan <- item
			}
			windows.RegCloseKey(hKey)
		}
	}()
	return outChan
}
