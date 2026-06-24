//go:build windows

package eventlog

import (
	"context"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ===================== 调试日志模块 =====================
var (
	debugFile *os.File
	debugMu   sync.Mutex
)

func init() {
	logPath := filepath.Join(os.TempDir(), "eventlog_debug.txt")
	var err error
	debugFile, err = os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return
	}
	_, _ = debugFile.Write([]byte{0xEF, 0xBB, 0xBF})
	writeDebug("===== 事件日志调试模块初始化完成 =====")
	writeDebug("日志文件路径: %s", logPath)
}

// writeDebug 写入调试日志
func writeDebug(format string, args ...interface{}) {
	debugMu.Lock()
	defer debugMu.Unlock()
	if debugFile == nil {
		return
	}
	now := time.Now().Format("2006-01-02 15:04:05")
	line := fmt.Sprintf("[%s] %s\r\n", now, fmt.Sprintf(format, args...))
	_, _ = debugFile.WriteString(line)
	_ = debugFile.Sync()
}

// ===================== Win32 事件日志 API 声明 =====================
var (
	wevtapi = windows.NewLazySystemDLL("wevtapi.dll")

	procEvtQuery  = wevtapi.NewProc("EvtQuery")
	procEvtNext   = wevtapi.NewProc("EvtNext")
	procEvtRender = wevtapi.NewProc("EvtRender")
	procEvtClose  = wevtapi.NewProc("EvtClose")
)

const (
	evtQueryChannelPath      = 0x1
	evtQueryReverseDirection = 0x200
	evtRenderEventXml        = 0x1
)

// ===================== XML 事件解析结构体 =====================
type rawEvent struct {
	XMLName xml.Name `xml:"Event"`
	System  struct {
		EventID     int `xml:"EventID"`
		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
		Provider struct {
			Name string `xml:"Name,attr"`
		} `xml:"Provider"`
		Computer string `xml:"Computer"`
	} `xml:"System"`
	EventData struct {
		Data []dataField `xml:"Data"`
	} `xml:"EventData"`
	UserData struct {
		XMLInner string `xml:",innerxml"`
	} `xml:"UserData"`
}

type dataField struct {
	Name  string `xml:"Name,attr"`
	Value string `xml:",chardata"`
}

// ===================== 通用日志条目结构体 =====================
type LogEntry struct {
	Time        string
	EventID     string
	Command     string
	Host        string
	Description string
	ThreatDesc  string
	IsSuspect   bool

	// 登录类字段
	UserName string
	SrcIP    string

	// 服务创建类字段
	SvcName      string
	SvcPath      string
	SvcType      string
	SvcStartType string
	SvcAccount   string

	// 用户创建类字段
	OperatorUser   string
	OperatorDomain string
	NewUser        string
	NewUserDomain  string
	Privilege      string

	// SQL Server类字段
	SqlLoginUser string
	SqlClientIP  string
	SqlFunction  string
	SqlOldValue  string
	SqlNewValue  string

	// 网络连接类字段
	SrcAddr string
	DstAddr string
	Proto   string

	// 计划任务类字段
	TaskAction  string
	TaskName    string
	TaskUser    string
	TaskContent string
}

// ===================== 核心采集封装函数 =====================

// evtQueryEvents 查询指定通道的事件日志，返回原始XML字符串数组
func evtQueryEvents(channel string, maxCount int) ([]string, error) {
	writeDebug("【采集入口】开始查询通道: %s，最大读取条数: %d", channel, maxCount)

	channelPtr, err := windows.UTF16PtrFromString(channel)
	if err != nil {
		writeDebug("【采集入口】通道名转UTF16失败: %s，错误: %v", channel, err)
		return nil, err
	}

	queryHandle, _, err := procEvtQuery.Call(
		0,
		uintptr(unsafe.Pointer(channelPtr)),
		0,
		uintptr(evtQueryChannelPath|evtQueryReverseDirection),
	)
	if queryHandle == 0 {
		winErr := getLastErrorCode()
		writeDebug("【采集入口】EvtQuery打开通道失败: %s，系统错误码: %d", channel, winErr)
		return nil, err
	}
	writeDebug("【采集入口】通道打开成功: %s，句柄值: %d", channel, queryHandle)

	defer func() {
		_, _, _ = procEvtClose.Call(queryHandle)
		writeDebug("【采集入口】通道句柄已关闭: %s", channel)
	}()

	var events []string
	batchSize := 10
	handles := make([]uintptr, batchSize)

	for len(events) < maxCount {
		var returned uint32
		ret, _, _ := procEvtNext.Call(
			queryHandle,
			uintptr(batchSize),
			uintptr(unsafe.Pointer(&handles[0])),
			0xFFFFFFFF,
			0,
			uintptr(unsafe.Pointer(&returned)),
		)
		if ret == 0 {
			winErr := getLastErrorCode()
			if winErr == uint32(windows.ERROR_NO_MORE_ITEMS) {
				writeDebug("【采集入口】通道 %s 读取完毕，共获取 %d 条原始事件", channel, len(events))
			} else {
				writeDebug("【采集入口】EvtNext读取失败，通道: %s，系统错误码: %d", channel, winErr)
			}
			break
		}

		for i := uint32(0); i < returned; i++ {
			handle := handles[i]
			xmlStr, renderErr := renderEventToXML(handle)
			_, _, _ = procEvtClose.Call(handle)
			if renderErr != nil {
				continue
			}
			events = append(events, xmlStr)
			if len(events) >= maxCount {
				break
			}
		}
	}

	writeDebug("【采集入口】通道 %s 查询完成，最终有效事件数: %d", channel, len(events))
	return events, nil
}

// getLastErrorCode 获取系统最后错误码，统一转换为uint32
func getLastErrorCode() uint32 {
	lastErr := windows.GetLastError()
	if errno, ok := lastErr.(syscall.Errno); ok {
		return uint32(errno)
	}
	return 0
}

// renderEventToXML 将事件句柄渲染为XML格式字符串
func renderEventToXML(eventHandle uintptr) (string, error) {
	var bufSize uint32
	procEvtRender.Call(0, eventHandle, uintptr(evtRenderEventXml), 0, 0, uintptr(unsafe.Pointer(&bufSize)), 0)
	if bufSize == 0 {
		return "", windows.ERROR_INSUFFICIENT_BUFFER
	}

	buf := make([]uint16, bufSize/2+1)
	var used uint32
	ret, _, err := procEvtRender.Call(
		0, eventHandle, uintptr(evtRenderEventXml),
		uintptr(bufSize), uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&used)), 0,
	)
	if ret == 0 {
		return "", err
	}
	return windows.UTF16ToString(buf), nil
}

// getEventDataValue 从事件数据中按名称提取字段值
func getEventDataValue(event *rawEvent, name string) string {
	for _, d := range event.EventData.Data {
		if strings.EqualFold(d.Name, name) {
			return d.Value
		}
	}
	return ""
}

// formatEventTime 将UTC时间字符串转换为本地时间格式
func formatEventTime(systemTime string) string {
	t, err := time.Parse(time.RFC3339Nano, systemTime)
	if err != nil {
		return systemTime
	}
	return t.Local().Format("2006-01-02 15:04:05")
}

// ===================== 威胁检测规则函数 =====================

// checkServiceThreat 检测服务路径是否包含可疑特征
func checkServiceThreat(path string) (string, bool) {
	pathLower := strings.ToLower(path)
	dangerKeys := []string{
		"powershell", "cmd.exe", "cmd /c", ".bat", ".ps1",
		"-encoded", "-nop", "-hidden", "base64",
		"\\temp\\", "\\tmp\\", "appdata\\roaming",
	}
	for _, k := range dangerKeys {
		if strings.Contains(pathLower, k) {
			return "检测到可疑服务创建，疑似横向攻击渗透", true
		}
	}
	return "", false
}

// checkPowershellThreat 检测PowerShell命令是否包含可疑特征
func checkPowershellThreat(cmd string) (string, bool) {
	cmdLower := strings.ToLower(cmd)
	if strings.Contains(cmdLower, "appdomain::currentdomain") ||
		strings.Contains(cmdLower, "assembly.load") ||
		strings.Contains(cmdLower, "-nop -w hidden -encodedcommand") {
		return "检测到CobaltStrike powershell上线痕迹!!!", true
	}

	dangerCount := 0
	dangerKeys := []string{
		"-encodedcommand", "-enc ", "-nop", "-noprofile",
		"invoke-expression", "iex ", "downloadstring", "downloadfile",
		"frombase64string", "memorystream", "reflection.assembly",
	}
	for _, k := range dangerKeys {
		if strings.Contains(cmdLower, k) {
			dangerCount++
		}
	}
	if dangerCount >= 2 {
		return "检测到可疑PowerShell编码执行，存在安全风险", true
	}
	return "", false
}

// ===================== 1. 登录成功日志（事件ID 4624） =====================

// GetLoginSuccessStream 获取登录成功事件流
func GetLoginSuccessStream(ctx context.Context) <-chan LogEntry {
	writeDebug("【函数调用】GetLoginSuccessStream 被执行")
	outCh := make(chan LogEntry, 10)
	go func() {
		defer close(outCh)
		events, err := evtQueryEvents("Security", 300)
		if err != nil {
			return
		}

		matchCount := 0
		for _, rawXML := range events {
			select {
			case <-ctx.Done():
				return
			default:
			}

			var evt rawEvent
			if xml.Unmarshal([]byte(rawXML), &evt) != nil {
				continue
			}
			if evt.System.EventID != 4624 {
				continue
			}
			matchCount++

			userName := getEventDataValue(&evt, "TargetUserName")
			srcIP := getEventDataValue(&evt, "IpAddress")
			loginType := getEventDataValue(&evt, "LogonType")

			desc := "登录成功"
			if loginType == "10" {
				desc = "RDP远程桌面登录成功"
			}
			if srcIP != "" && srcIP != "-" {
				desc += "，来源IP：" + srcIP
			}

			outCh <- LogEntry{
				Time:        formatEventTime(evt.System.TimeCreated.SystemTime),
				EventID:     "4624",
				UserName:    userName,
				Host:        evt.System.Computer,
				Description: desc,
			}
			time.Sleep(2 * time.Millisecond)
		}
		writeDebug("【登录成功】过滤完成，匹配到4624事件共 %d 条", matchCount)
	}()
	return outCh
}

// ===================== 2. 登录失败日志（事件ID 4625） =====================

// GetLoginFailStream 获取登录失败事件流
func GetLoginFailStream(ctx context.Context) <-chan LogEntry {
	writeDebug("【函数调用】GetLoginFailStream 被执行")
	outCh := make(chan LogEntry, 10)
	go func() {
		defer close(outCh)
		events, err := evtQueryEvents("Security", 300)
		if err != nil {
			return
		}

		matchCount := 0
		for _, rawXML := range events {
			select {
			case <-ctx.Done():
				return
			default:
			}

			var evt rawEvent
			if xml.Unmarshal([]byte(rawXML), &evt) != nil {
				continue
			}
			if evt.System.EventID != 4625 {
				continue
			}
			matchCount++

			userName := getEventDataValue(&evt, "TargetUserName")
			srcIP := getEventDataValue(&evt, "IpAddress")

			desc := "登录失败"
			if srcIP != "" && srcIP != "-" {
				desc += "，来源IP：" + srcIP
			}

			outCh <- LogEntry{
				Time:        formatEventTime(evt.System.TimeCreated.SystemTime),
				EventID:     "4625",
				UserName:    userName,
				Host:        evt.System.Computer,
				Description: desc,
			}
			time.Sleep(2 * time.Millisecond)
		}
		writeDebug("【登录失败】过滤完成，匹配到4625事件共 %d 条", matchCount)
	}()
	return outCh
}

// ===================== 3. RDP登录日志（登录类型10） =====================

// GetRDPLoginStream 获取RDP远程桌面登录事件流
func GetRDPLoginStream(ctx context.Context) <-chan LogEntry {
	writeDebug("【函数调用】GetRDPLoginStream 被执行")
	outCh := make(chan LogEntry, 10)
	go func() {
		defer close(outCh)
		events, err := evtQueryEvents("Security", 300)
		if err != nil {
			return
		}

		matchCount := 0
		for _, rawXML := range events {
			select {
			case <-ctx.Done():
				return
			default:
			}

			var evt rawEvent
			if xml.Unmarshal([]byte(rawXML), &evt) != nil {
				continue
			}
			if evt.System.EventID != 4624 {
				continue
			}
			if getEventDataValue(&evt, "LogonType") != "10" {
				continue
			}
			matchCount++

			userName := getEventDataValue(&evt, "TargetUserName")
			srcIP := getEventDataValue(&evt, "IpAddress")

			outCh <- LogEntry{
				Time:        formatEventTime(evt.System.TimeCreated.SystemTime),
				EventID:     "4624",
				UserName:    userName,
				Host:        evt.System.Computer,
				Description: "RDP远程登录成功，来源IP：" + srcIP,
			}
			time.Sleep(2 * time.Millisecond)
		}
		writeDebug("【RDP登录】过滤完成，匹配到RDP登录事件共 %d 条", matchCount)
	}()
	return outCh
}

// ===================== 4. RDP连接日志（事件ID 1149） =====================

// GetRDPConnectStream 获取RDP远程连接建立事件流
func GetRDPConnectStream(ctx context.Context) <-chan LogEntry {
	writeDebug("【函数调用】GetRDPConnectStream 被执行")
	outCh := make(chan LogEntry, 10)
	go func() {
		defer close(outCh)
		channel := "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"
		events, err := evtQueryEvents(channel, 200)
		if err != nil {
			return
		}

		matchCount := 0
		for _, rawXML := range events {
			select {
			case <-ctx.Done():
				return
			default:
			}

			var evt rawEvent
			if xml.Unmarshal([]byte(rawXML), &evt) != nil {
				continue
			}
			if evt.System.EventID != 1149 {
				continue
			}
			matchCount++

			user := getEventDataValue(&evt, "UserName")
			srcIP := getEventDataValue(&evt, "ClientIP")

			outCh <- LogEntry{
				Time:        formatEventTime(evt.System.TimeCreated.SystemTime),
				EventID:     "1149",
				UserName:    user,
				Host:        evt.System.Computer,
				Description: "RDP远程连接建立，来源IP：" + srcIP,
			}
			time.Sleep(2 * time.Millisecond)
		}
		writeDebug("【RDP连接】过滤完成，匹配到1149事件共 %d 条", matchCount)
	}()
	return outCh
}

// ===================== 5. 服务创建日志（事件ID 7045）【修复版：全量读取+字段兼容】 =====================

// GetServiceCreateStream 获取服务创建事件流
func GetServiceCreateStream(ctx context.Context) <-chan LogEntry {
	writeDebug("【函数调用】GetServiceCreateStream 被执行")
	outCh := make(chan LogEntry, 10)
	go func() {
		defer close(outCh)
		// 提升读取量至10000条，覆盖更长时间范围的服务安装记录
		events, err := evtQueryEvents("System", 100000)
		if err != nil {
			writeDebug("【服务创建】System通道查询失败: %v", err)
			return
		}

		writeDebug("【服务创建】原始System事件总数: %d，开始过滤7045事件", len(events))

		var (
			matchCount    int
			parseFailCnt  int
			emptyFieldCnt int
		)

		for _, rawXML := range events {
			select {
			case <-ctx.Done():
				return
			default:
			}

			var evt rawEvent
			if xml.Unmarshal([]byte(rawXML), &evt) != nil {
				parseFailCnt++
				continue
			}
			if evt.System.EventID != 7045 {
				continue
			}
			matchCount++

			// 兼容字段名：不同系统版本字段名大小写/命名有差异
			svcName := getEventDataValue(&evt, "ServiceName")
			if svcName == "" {
				svcName = getEventDataValue(&evt, "serviceName")
			}

			svcPath := getEventDataValue(&evt, "ImagePath")
			if svcPath == "" {
				svcPath = getEventDataValue(&evt, "imagePath")
			}

			svcType := getEventDataValue(&evt, "ServiceType")
			if svcType == "" {
				svcType = getEventDataValue(&evt, "serviceType")
			}

			startType := getEventDataValue(&evt, "StartType")
			if startType == "" {
				startType = getEventDataValue(&evt, "startType")
			}

			account := getEventDataValue(&evt, "AccountName")
			if account == "" {
				account = getEventDataValue(&evt, "accountName")
			}

			// 服务名称为空则标记为异常数据
			if svcName == "" {
				emptyFieldCnt++
				svcName = "未识别服务"
			}

			// 服务类型转换
			svcTypeDesc := svcType
			switch svcType {
			case "1":
				svcTypeDesc = "内核模式驱动"
			case "16":
				svcTypeDesc = "用户模式服务"
			case "32":
				svcTypeDesc = "共享进程服务"
			}

			// 启动类型转换
			startTypeDesc := startType
			switch startType {
			case "0":
				startTypeDesc = "系统启动"
			case "1":
				startTypeDesc = "自动启动"
			case "2":
				startTypeDesc = "自动启动"
			case "3":
				startTypeDesc = "按需启动"
			case "4":
				startTypeDesc = "禁用"
			}

			threatDesc, isSuspect := checkServiceThreat(svcPath)

			outCh <- LogEntry{
				Time:         formatEventTime(evt.System.TimeCreated.SystemTime),
				EventID:      "7045",
				Host:         evt.System.Computer,
				SvcName:      svcName,
				SvcPath:      svcPath,
				SvcType:      svcTypeDesc,
				SvcStartType: startTypeDesc,
				SvcAccount:   account,
				Description:  "服务创建事件",
				ThreatDesc:   threatDesc,
				IsSuspect:    isSuspect,
			}
			time.Sleep(2 * time.Millisecond)
		}

		writeDebug("【服务创建】过滤完成，匹配7045事件: %d 条，XML解析失败: %d 条，字段异常: %d 条",
			matchCount, parseFailCnt, emptyFieldCnt)
	}()
	return outCh
}

// ===================== 6. 用户创建日志（事件ID 4720） =====================

// GetUserCreateStream 获取用户账户创建事件流
func GetUserCreateStream(ctx context.Context) <-chan LogEntry {
	writeDebug("【函数调用】GetUserCreateStream 被执行")
	outCh := make(chan LogEntry, 10)
	go func() {
		defer close(outCh)
		events, err := evtQueryEvents("Security", 500)
		if err != nil {
			return
		}

		matchCount := 0
		for _, rawXML := range events {
			select {
			case <-ctx.Done():
				return
			default:
			}

			var evt rawEvent
			if xml.Unmarshal([]byte(rawXML), &evt) != nil {
				continue
			}
			if evt.System.EventID != 4720 {
				continue
			}
			matchCount++

			operator := getEventDataValue(&evt, "SubjectUserName")
			opDomain := getEventDataValue(&evt, "SubjectDomainName")
			newUser := getEventDataValue(&evt, "TargetUserName")
			newDomain := getEventDataValue(&evt, "TargetDomainName")
			priv := getEventDataValue(&evt, "PrivilegeList")

			outCh <- LogEntry{
				Time:           formatEventTime(evt.System.TimeCreated.SystemTime),
				EventID:        "4720",
				Host:           evt.System.Computer,
				OperatorUser:   operator,
				OperatorDomain: opDomain,
				NewUser:        newUser,
				NewUserDomain:  newDomain,
				Privilege:      priv,
				Description:    "用户账户创建",
			}
			time.Sleep(2 * time.Millisecond)
		}
		writeDebug("【用户创建】过滤完成，匹配到4720事件共 %d 条", matchCount)
	}()
	return outCh
}

// ===================== 7. SQL Server日志 =====================

// GetSqlServerStream 获取SQL Server相关事件流
func GetSqlServerStream(ctx context.Context) <-chan LogEntry {
	writeDebug("【函数调用】GetSqlServerStream 被执行")
	outCh := make(chan LogEntry, 10)
	go func() {
		defer close(outCh)
		events, err := evtQueryEvents("Application", 500)
		if err != nil {
			return
		}

		matchCount := 0
		for _, rawXML := range events {
			select {
			case <-ctx.Done():
				return
			default:
			}

			var evt rawEvent
			if xml.Unmarshal([]byte(rawXML), &evt) != nil {
				continue
			}
			if !strings.Contains(strings.ToLower(evt.System.Provider.Name), "mssql") {
				continue
			}
			matchCount++

			loginUser := getEventDataValue(&evt, "LoginName")
			clientIP := getEventDataValue(&evt, "ClientIP")
			msg := getEventDataValue(&evt, "Message")

			outCh <- LogEntry{
				Time:         formatEventTime(evt.System.TimeCreated.SystemTime),
				EventID:      strconv.Itoa(evt.System.EventID),
				Host:         evt.System.Computer,
				SqlLoginUser: loginUser,
				SqlClientIP:  clientIP,
				SqlFunction:  evt.System.Provider.Name,
				Description:  msg,
			}
			time.Sleep(2 * time.Millisecond)
		}
		writeDebug("【SQL Server】过滤完成，匹配到MSSQL事件共 %d 条", matchCount)
	}()
	return outCh
}

// ===================== 8. PowerShell日志（事件日志+PSReadLine历史 双源合并） =====================

// getPSReadLineHistory 读取本地PSReadLine控制台历史命令文件
func getPSReadLineHistory() ([]string, time.Time, error) {
	// PSReadLine 默认历史文件路径，覆盖 PowerShell 5.1 / 7.x 控制台终端
	historyPath := filepath.Join(os.Getenv("APPDATA"), "Microsoft", "Windows", "PowerShell", "PSReadLine", "ConsoleHost_history.txt")

	fileInfo, err := os.Stat(historyPath)
	if err != nil {
		return nil, time.Time{}, err
	}

	content, err := os.ReadFile(historyPath)
	if err != nil {
		return nil, time.Time{}, err
	}

	// 跳过UTF-8 BOM头，兼容不同编码版本的历史文件
	if len(content) >= 3 && content[0] == 0xEF && content[1] == 0xBB && content[2] == 0xBF {
		content = content[3:]
	}

	// 按行拆分，兼容 Windows / Unix 换行符
	rawLines := strings.Split(string(content), "\r\n")
	if len(rawLines) == 1 {
		rawLines = strings.Split(string(content), "\n")
	}

	var cmdList []string
	for _, line := range rawLines {
		line = strings.TrimSpace(line)
		if line != "" {
			cmdList = append(cmdList, line)
		}
	}

	// 倒序排列：最新执行的命令排在最前面
	for i, j := 0, len(cmdList)-1; i < j; i, j = i+1, j-1 {
		cmdList[i], cmdList[j] = cmdList[j], cmdList[i]
	}

	return cmdList, fileInfo.ModTime(), nil
}

// GetPowerShellStream 获取PowerShell脚本执行事件流（系统事件+本地历史 合并输出）
func GetPowerShellStream(ctx context.Context) <-chan LogEntry {
	writeDebug("【函数调用】GetPowerShellStream 被执行")
	outCh := make(chan LogEntry, 10)
	go func() {
		defer close(outCh)

		var allEvents []string

		// 1. 查询新版Operational通道（4104脚本块审计事件）
		events1, err1 := evtQueryEvents("Microsoft-Windows-PowerShell/Operational", 500)
		if err1 == nil {
			allEvents = append(allEvents, events1...)
			writeDebug("【PowerShell】新版通道获取 %d 条事件", len(events1))
		} else {
			writeDebug("【PowerShell】新版通道查询失败: %v", err1)
		}

		// 2. 查询经典Windows PowerShell通道（400引擎启动事件）
		events2, err2 := evtQueryEvents("Windows PowerShell", 500)
		if err2 == nil {
			allEvents = append(allEvents, events2...)
			writeDebug("【PowerShell】经典通道获取 %d 条事件", len(events2))
		} else {
			writeDebug("【PowerShell】经典通道查询失败: %v", err2)
		}

		writeDebug("【PowerShell】双通道事件合并后共 %d 条，开始过滤", len(allEvents))

		// ========== PSReadLine本地历史命令（补充数据量） ==========
		historyCmds, modTime, histErr := getPSReadLineHistory()
		if histErr == nil {
			writeDebug("【PowerShell】PSReadLine历史获取 %d 条命令", len(historyCmds))
			hostName, _ := os.Hostname()
			timeStr := modTime.Local().Format("2006-01-02 15:04:05")

			for _, cmd := range historyCmds {
				select {
				case <-ctx.Done():
					return
				default:
				}

				threatDesc, isSuspect := checkPowershellThreat(cmd)
				outCh <- LogEntry{
					Time:        timeStr,
					EventID:     "PSReadLine",
					Command:     cmd,
					Host:        hostName,
					Description: "PowerShell历史命令",
					ThreatDesc:  threatDesc,
					IsSuspect:   isSuspect,
				}
				time.Sleep(2 * time.Millisecond)
			}
		} else {
			writeDebug("【PowerShell】PSReadLine历史读取失败: %v", histErr)
		}
	}()
	return outCh
}

// ===================== 9. 网络连接日志（事件ID 5156） =====================

// GetNetConnectStream 获取防火墙网络连接允许事件流
func GetNetConnectStream(ctx context.Context) <-chan LogEntry {
	writeDebug("【函数调用】GetNetConnectStream 被执行")
	outCh := make(chan LogEntry, 10)
	go func() {
		defer close(outCh)
		events, err := evtQueryEvents("Security", 500)
		if err != nil {
			return
		}

		matchCount := 0
		for _, rawXML := range events {
			select {
			case <-ctx.Done():
				return
			default:
			}

			var evt rawEvent
			if xml.Unmarshal([]byte(rawXML), &evt) != nil {
				continue
			}
			if evt.System.EventID != 5156 {
				continue
			}
			matchCount++

			srcAddr := getEventDataValue(&evt, "SourceAddress")
			srcPort := getEventDataValue(&evt, "SourcePort")
			dstAddr := getEventDataValue(&evt, "DestAddress")
			dstPort := getEventDataValue(&evt, "DestPort")
			proto := getEventDataValue(&evt, "Protocol")
			if proto == "6" {
				proto = "TCP"
			}
			if proto == "17" {
				proto = "UDP"
			}

			outCh <- LogEntry{
				Time:        formatEventTime(evt.System.TimeCreated.SystemTime),
				EventID:     "5156",
				Host:        evt.System.Computer,
				SrcAddr:     srcAddr + ":" + srcPort,
				DstAddr:     dstAddr + ":" + dstPort,
				Proto:       proto,
				Description: "网络连接允许",
			}
			time.Sleep(2 * time.Millisecond)
		}
		writeDebug("【网络连接】过滤完成，匹配到5156事件共 %d 条", matchCount)
	}()
	return outCh
}

// ===================== 10. 计划任务日志 =====================

// GetTaskScheduleStream 获取计划任务操作事件流
func GetTaskScheduleStream(ctx context.Context) <-chan LogEntry {
	writeDebug("【函数调用】GetTaskScheduleStream 被执行")
	outCh := make(chan LogEntry, 10)
	go func() {
		defer close(outCh)
		channel := "Microsoft-Windows-TaskScheduler/Operational"
		events, err := evtQueryEvents(channel, 500)
		if err != nil {
			return
		}

		matchCount := 0
		for _, rawXML := range events {
			select {
			case <-ctx.Done():
				return
			default:
			}

			var evt rawEvent
			if xml.Unmarshal([]byte(rawXML), &evt) != nil {
				continue
			}
			matchCount++

			taskName := getEventDataValue(&evt, "TaskName")
			userName := getEventDataValue(&evt, "UserContext")
			action := "任务操作"
			switch evt.System.EventID {
			case 106:
				action = "任务注册创建"
			case 100:
				action = "任务启动"
			case 102:
				action = "任务完成"
			case 140:
				action = "任务更新"
			case 141:
				action = "任务删除"
			}

			outCh <- LogEntry{
				Time:        formatEventTime(evt.System.TimeCreated.SystemTime),
				EventID:     strconv.Itoa(evt.System.EventID),
				Host:        evt.System.Computer,
				TaskAction:  action,
				TaskName:    taskName,
				TaskUser:    userName,
				TaskContent: taskName,
				Description: "计划任务事件",
			}
			time.Sleep(2 * time.Millisecond)
		}
		writeDebug("【计划任务】处理完成，共匹配到 %d 条计划任务事件", matchCount)
	}()
	return outCh
}
