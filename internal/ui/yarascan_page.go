package ui

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ying32/govcl/vcl"
	"github.com/ying32/govcl/vcl/types"

	"Scan/internal/process"
	"Scan/pkg/yara"
)

// TYaraScanPage 进程Yara扫描页
type TYaraScanPage struct {
	Parent      *vcl.TTabSheet
	TopPanel    *vcl.TPanel
	EdtRulePath *vcl.TEdit
	EdtSkipSize *vcl.TEdit
	BtnStart    *vcl.TButton

	ScanLogMemo  *vcl.TMemo
	AlertLogMemo *vcl.TMemo
	Splitter     *vcl.TSplitter

	isScanning bool
}

// NewYaraScanPage 初始化扫描页
func NewYaraScanPage(parent *vcl.TTabSheet) *TYaraScanPage {
	p := &TYaraScanPage{Parent: parent}
	p.buildUI()
	return p
}

// buildUI 构建界面
func (p *TYaraScanPage) buildUI() {
	// 顶部操作栏
	p.TopPanel = vcl.NewPanel(p.Parent)
	p.TopPanel.SetParent(p.Parent)
	p.TopPanel.SetAlign(types.AlTop)
	p.TopPanel.SetHeight(45)
	p.TopPanel.SetBevelOuter(types.BvNone)

	// 规则路径输入
	lblRule := vcl.NewLabel(p.TopPanel)
	lblRule.SetParent(p.TopPanel)
	lblRule.SetLeft(10)
	lblRule.SetTop(12)
	lblRule.SetCaption("请输入自定义规则路径:")

	p.EdtRulePath = vcl.NewEdit(p.TopPanel)
	p.EdtRulePath.SetParent(p.TopPanel)
	p.EdtRulePath.SetLeft(135)
	p.EdtRulePath.SetTop(10)
	p.EdtRulePath.SetWidth(210)
	// 默认填充exe同目录下的rules文件夹
	exePath, _ := os.Executable()
	defaultRuleDir := filepath.Join(filepath.Dir(exePath), "rules")
	p.EdtRulePath.SetText(defaultRuleDir)

	// 跳过进程大小
	lblSkip := vcl.NewLabel(p.TopPanel)
	lblSkip.SetParent(p.TopPanel)
	lblSkip.SetLeft(365)
	lblSkip.SetTop(12)
	lblSkip.SetCaption("跳过进程大小(MB):")

	p.EdtSkipSize = vcl.NewEdit(p.TopPanel)
	p.EdtSkipSize.SetParent(p.TopPanel)
	p.EdtSkipSize.SetLeft(485)
	p.EdtSkipSize.SetTop(10)
	p.EdtSkipSize.SetWidth(90)
	p.EdtSkipSize.SetText("1") // 默认跳过小于1MB的进程，提升速度

	// 开始扫描按钮
	p.BtnStart = vcl.NewButton(p.TopPanel)
	p.BtnStart.SetParent(p.TopPanel)
	p.BtnStart.SetLeft(600)
	p.BtnStart.SetTop(8)
	p.BtnStart.SetWidth(100)
	p.BtnStart.SetCaption("开始扫描")
	p.BtnStart.SetOnClick(p.onStartScan)

	// 底部告警日志区
	p.AlertLogMemo = vcl.NewMemo(p.Parent)
	p.AlertLogMemo.SetParent(p.Parent)
	p.AlertLogMemo.SetAlign(types.AlBottom)
	p.AlertLogMemo.SetHeight(230)
	p.AlertLogMemo.SetReadOnly(true)
	p.AlertLogMemo.SetScrollBars(types.SsVertical)
	p.AlertLogMemo.Lines().Add("告警日志")
	p.AlertLogMemo.Lines().Add("================================")

	// 可拖动分割条
	p.Splitter = vcl.NewSplitter(p.Parent)
	p.Splitter.SetParent(p.Parent)
	p.Splitter.SetAlign(types.AlBottom)
	p.Splitter.SetHeight(3)

	// 上方扫描日志区
	p.ScanLogMemo = vcl.NewMemo(p.Parent)
	p.ScanLogMemo.SetParent(p.Parent)
	p.ScanLogMemo.SetAlign(types.AlClient)
	p.ScanLogMemo.SetReadOnly(true)
	p.ScanLogMemo.SetScrollBars(types.SsBoth)
}

// onStartScan 开始扫描按钮事件
func (p *TYaraScanPage) onStartScan(_ vcl.IObject) {
	if p.isScanning {
		return
	}

	ruleDir := strings.TrimSpace(p.EdtRulePath.Text())
	if ruleDir == "" {
		vcl.ShowMessage("请填写规则目录路径")
		return
	}

	// 解析跳过大小
	skipSizeMB, err := strconv.Atoi(strings.TrimSpace(p.EdtSkipSize.Text()))
	if err != nil || skipSizeMB < 0 {
		skipSizeMB = 1
	}
	skipSizeBytes := uint64(skipSizeMB) * 1024 * 1024

	// 清空日志
	p.ScanLogMemo.Clear()
	p.AlertLogMemo.Clear()
	p.AlertLogMemo.Lines().Add("告警日志")
	p.AlertLogMemo.Lines().Add("================================")

	// 锁定按钮状态
	p.isScanning = true
	p.BtnStart.SetEnabled(false)
	p.BtnStart.SetCaption("扫描中...")

	// 后台异步执行扫描
	go func() {
		defer vcl.ThreadSync(func() {
			p.isScanning = false
			p.BtnStart.SetEnabled(true)
			p.BtnStart.SetCaption("开始扫描")
		})

		// 1. 加载规则
		p.appendScanLog(">>> 正在加载Yara规则库...")
		scanner, err := yara.NewYaraScanner(ruleDir)
		if err != nil {
			p.appendScanLog("❌ 规则加载失败: " + err.Error())
			return
		}
		defer scanner.Destroy()
		p.appendScanLog(fmt.Sprintf("✅ 规则加载完成，准备扫描进程..."))

		// 2. 获取全量进程
		procList, err := process.GetAllProcesses()
		if err != nil {
			p.appendScanLog("❌ 获取进程列表失败: " + err.Error())
			return
		}
		p.appendScanLog(fmt.Sprintf("共获取 %d 个进程，开始扫描...\n", len(procList)))

		// 3. 逐进程扫描
		hitCount := 0
		scanCount := 0
		for _, proc := range procList {
			// 跳过小内存进程
			if proc.Memory < skipSizeBytes {
				continue
			}
			scanCount++

			p.appendScanLog(fmt.Sprintf("正在扫描进程 %d (%s)", proc.PID, proc.Name))

			// 执行内存扫描
			matches, err := scanner.ScanProcess(proc.PID)
			if err != nil {
				p.appendScanLog(fmt.Sprintf("[跳过] PID: %d 进程名: %s 原因: %v", proc.PID, proc.Name, err))
				continue
			}

			if len(matches) == 0 {
				p.appendScanLog(fmt.Sprintf("[未发现] PID: %d 进程名: %s", proc.PID, proc.Name))
			} else {
				hitCount++
				p.appendScanLog(fmt.Sprintf("⚠️ [发现威胁] PID: %d 进程名: %s", proc.PID, proc.Name))

				// 追加到告警日志
				startTime := "-"
				if proc.CreateTime > 0 {
					startTime = time.UnixMilli(proc.CreateTime).Format("2006-01-02 15:04:05")
				}
				p.appendAlertLog(fmt.Sprintf("[发现] PID: %d  进程名: %s  进程启动时间: %s", proc.PID, proc.Name, startTime))
				for _, ruleName := range matches {
					p.appendAlertLog("    匹配规则: " + ruleName)
				}
				p.appendAlertLog("")
			}
		}

		// 扫描结束
		p.appendScanLog(fmt.Sprintf("\n✅ 扫描完成！实际扫描 %d 个进程，共发现 %d 个威胁进程", scanCount, hitCount))
	}()
}

// appendScanLog 追加扫描日志，自动滚动到底部
func (p *TYaraScanPage) appendScanLog(text string) {
	vcl.ThreadSync(func() {
		p.ScanLogMemo.Lines().Add(text)
		// 光标移到文本末尾，实现自动滚动
		textLen := p.ScanLogMemo.GetTextLen()
		p.ScanLogMemo.SetSelStart(textLen)
		p.ScanLogMemo.SetSelLength(0)
	})
}

// appendAlertLog 追加告警日志，自动滚动到底部
func (p *TYaraScanPage) appendAlertLog(text string) {
	vcl.ThreadSync(func() {
		p.AlertLogMemo.Lines().Add(text)
		// 光标移到文本末尾，实现自动滚动
		textLen := p.AlertLogMemo.GetTextLen()
		p.AlertLogMemo.SetSelStart(textLen)
		p.AlertLogMemo.SetSelLength(0)
	})
}
