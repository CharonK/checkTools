package ui

import (
	"os"
	"runtime"
	"strconv"
	"time"

	"github.com/shirou/gopsutil/v3/mem"
	gopsProcess "github.com/shirou/gopsutil/v3/process"
	"github.com/ying32/govcl/vcl"
	"github.com/ying32/govcl/vcl/types"
)

// MainForm 全局主窗口实例
var MainForm *TMainForm

// TMainForm 主窗口结构体
type TMainForm struct {
	*vcl.TForm
	PageControl *vcl.TPageControl
	StatusBar   *vcl.TStatusBar
	ProgressBar *vcl.TProgressBar
	selfProc    *gopsProcess.Process

	// 8个功能标签页
	TabProcess   *vcl.TTabSheet
	TabNetwork   *vcl.TTabSheet
	TabBeacon    *vcl.TTabSheet
	TabHost      *vcl.TTabSheet
	TabLog       *vcl.TTabSheet
	TabYaraScan  *vcl.TTabSheet
	TabTrace     *vcl.TTabSheet
	TabMemSearch *vcl.TTabSheet

	// 已实现功能页实例
	ProcessPage *TProcessPage
	isFirstShow bool
}

// OnFormCreate 窗口创建事件
func (f *TMainForm) OnFormCreate(sender vcl.IObject) {
	f.SetCaption("排查工具")
	f.SetWidth(1000)
	f.SetHeight(650)
	f.SetPosition(types.PoScreenCenter)
	f.isFirstShow = true
	f.SetOnShow(f.OnFormShow)

	// 初始化标签页控件
	f.PageControl = vcl.NewPageControl(f)
	f.PageControl.SetParent(f)
	f.PageControl.SetAlign(types.AlClient)

	// 初始化自身进程句柄（用于获取PID和进程CPU）
	selfPID := int32(os.Getpid())
	f.selfProc, _ = gopsProcess.NewProcess(selfPID)

	// 底部状态栏
	f.StatusBar = vcl.NewStatusBar(f)
	f.StatusBar.SetParent(f)
	f.StatusBar.SetAlign(types.AlBottom)
	f.StatusBar.SetSimplePanel(true)

	// 进度条（嵌入状态栏）
	f.ProgressBar = vcl.NewProgressBar(f)
	f.ProgressBar.SetParent(f.StatusBar)
	f.ProgressBar.SetBounds(10, 2, 200, 18)
	f.ProgressBar.SetMin(0)
	f.ProgressBar.SetMax(100)
	f.ProgressBar.SetVisible(false)

	// 1秒定时器，实时刷新状态栏
	statusTimer := vcl.NewTimer(f)
	statusTimer.SetInterval(1000)
	statusTimer.SetOnTimer(func(sender vcl.IObject) {
		f.updateStatusBar()
	})
	statusTimer.SetEnabled(true)

	// 启动时先刷新一次
	f.updateStatusBar()

	// 1. 进程信息页
	f.TabProcess = vcl.NewTabSheet(f)
	f.TabProcess.SetParent(f.PageControl)
	f.TabProcess.SetCaption("进程信息")
	f.ProcessPage = NewProcessPage(f.TabProcess)

	// 2. Yara进程扫描页
	f.TabYaraScan = vcl.NewTabSheet(f)
	f.TabYaraScan.SetParent(f.PageControl)
	f.TabYaraScan.SetCaption("进程扫描")
	NewYaraScanPage(f.TabYaraScan)

	// 3. 外连分析页
	f.TabNetwork = vcl.NewTabSheet(f)
	f.TabNetwork.SetParent(f.PageControl)
	f.TabNetwork.SetCaption("外连分析")
	NewNetworkPage(f.TabNetwork)

	// 4. 主机信息页
	f.TabHost = vcl.NewTabSheet(f)
	f.TabHost.SetParent(f.PageControl)
	f.TabHost.SetCaption("主机信息")
	NewHostPage(f.TabHost)

	// 5. 日志分析页
	f.TabLog = vcl.NewTabSheet(f)
	f.TabLog.SetParent(f.PageControl)
	f.TabLog.SetCaption("日志分析")
	NewLogPage(f.TabLog)

	// 6. Beacon扫描页
	f.TabBeacon = vcl.NewTabSheet(f)
	f.TabBeacon.SetParent(f.PageControl)
	f.TabBeacon.SetCaption("Beacon扫描")
	NewBeaconPage(f.TabBeacon)

	// 7. 活动痕迹页
	f.TabTrace = vcl.NewTabSheet(f)
	f.TabTrace.SetParent(f.PageControl)
	f.TabTrace.SetCaption("活动痕迹")
	NewTracePage(f.TabTrace)

	// 8. 内存检索页
	f.TabMemSearch = vcl.NewTabSheet(f)
	f.TabMemSearch.SetParent(f.PageControl)
	f.TabMemSearch.SetCaption("内存检索")
	NewMemSearchPage(f.TabMemSearch)
}

// updateStatusBar 刷新底部常驻状态栏
// updateStatusBar 刷新底部常驻状态栏，CPU口径与任务管理器对齐
func (f *TMainForm) updateStatusBar() {
	timeStr := time.Now().Format("2006-01-02 15:04:05")
	pidStr := strconv.Itoa(int(f.selfProc.Pid))

	// 当前进程CPU使用率：单核心结果 / 逻辑核心数 = 多核平均使用率，与任务管理器口径一致
	cpuStr := "-"
	cpuPct, err := f.selfProc.CPUPercent()
	if err == nil {
		multiCorePct := cpuPct / float64(runtime.NumCPU())
		cpuStr = strconv.FormatFloat(multiCorePct, 'f', 1, 64) + "%"
	}

	// 系统整体内存使用率
	memStr := "-"
	memStat, err := mem.VirtualMemory()
	if err == nil && memStat.Total > 0 {
		usedPercent := float64(memStat.Total-memStat.Available) / float64(memStat.Total) * 100
		memStr = strconv.FormatFloat(usedPercent, 'f', 1, 64) + "%"
	}

	statusText := "PID: " + pidStr + "  |  CPU: " + cpuStr + "  |  系统内存: " + memStr + "  |  " + timeStr
	f.StatusBar.SetSimpleText(statusText)
}

// OnFormShow 窗口首次完全显示后触发
func (f *TMainForm) OnFormShow(sender vcl.IObject) {
	if f.isFirstShow {
		f.isFirstShow = false
		f.ProcessPage.Refresh()
	}
}

// ShowLoading 显示加载状态（全局通用）
func (f *TMainForm) ShowLoading(text string) {
	f.StatusBar.SetSimpleText(text)
	f.ProgressBar.SetVisible(true)
	f.ProgressBar.SetStyle(types.PbstMarquee)
}

// HideLoading 隐藏加载状态，自动恢复常驻状态栏
func (f *TMainForm) HideLoading(_ string) {
	f.ProgressBar.SetVisible(false)
	f.updateStatusBar()
}
