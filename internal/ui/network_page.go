package ui

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ying32/govcl/vcl"
	"github.com/ying32/govcl/vcl/types"

	"Scan/internal/network"
)

// TNetworkPage 外连分析页面
type TNetworkPage struct {
	Parent      *vcl.TTabSheet
	TopPanel    *vcl.TPanel
	EdtTargetIP *vcl.TEdit
	BtnStart    *vcl.TButton
	BtnStop     *vcl.TButton
	MemoLog     *vcl.TMemo

	scanCtx    context.Context
	scanCancel context.CancelFunc
	isRunning  int32 // 原子标记扫描是否运行，防止重复启动
}

func NewNetworkPage(parent *vcl.TTabSheet) *TNetworkPage {
	p := &TNetworkPage{
		Parent:     parent,
		isRunning:  0,
		scanCancel: func() {},
	}
	p.buildUI()
	p.bindEvent()
	return p
}

func (p *TNetworkPage) buildUI() {
	p.TopPanel = vcl.NewPanel(p.Parent)
	p.TopPanel.SetParent(p.Parent)
	p.TopPanel.SetAlign(types.AlTop)
	p.TopPanel.SetHeight(42)
	p.TopPanel.SetBevelOuter(types.BvNone)

	p.EdtTargetIP = vcl.NewEdit(p.TopPanel)
	p.EdtTargetIP.SetParent(p.TopPanel)
	p.EdtTargetIP.SetLeft(10)
	p.EdtTargetIP.SetTop(8)
	p.EdtTargetIP.SetWidth(400)
	p.EdtTargetIP.SetText("")
	p.EdtTargetIP.SetHint("输入需要检索的IP地址")

	p.BtnStart = vcl.NewButton(p.TopPanel)
	p.BtnStart.SetParent(p.TopPanel)
	p.BtnStart.SetLeft(420)
	p.BtnStart.SetTop(6)
	p.BtnStart.SetWidth(90)
	p.BtnStart.SetCaption("启动")

	p.BtnStop = vcl.NewButton(p.TopPanel)
	p.BtnStop.SetParent(p.TopPanel)
	p.BtnStop.SetLeft(520)
	p.BtnStop.SetTop(6)
	p.BtnStop.SetWidth(90)
	p.BtnStop.SetCaption("停止")
	p.BtnStop.SetEnabled(false)

	p.MemoLog = vcl.NewMemo(p.Parent)
	p.MemoLog.SetParent(p.Parent)
	p.MemoLog.SetAlign(types.AlClient)
	p.MemoLog.SetReadOnly(true)
	p.MemoLog.SetScrollBars(types.SsVertical)
	p.MemoLog.SetFont(vcl.NewFont())
	p.MemoLog.Font().SetName("Consolas")
}

func (p *TNetworkPage) bindEvent() {
	p.BtnStart.SetOnClick(p.onStartSearch)
	p.BtnStop.SetOnClick(p.onStopScan)
}

// onStopScan 停止扫描
func (p *TNetworkPage) onStopScan(_ vcl.IObject) {
	if atomic.LoadInt32(&p.isRunning) == 0 {
		return
	}
	p.scanCancel()
	p.appendLog("【手动终止】已停止当前扫描任务")
}

// restoreUI 统一恢复按钮状态，单独抽离
func (p *TNetworkPage) restoreUI() {
	vcl.ThreadSync(func() {
		p.BtnStart.SetEnabled(true)
		p.BtnStop.SetEnabled(false)
		// 仅结束时滚动到底，减少频繁刷新
		lenText := p.MemoLog.GetTextLen()
		p.MemoLog.SetSelStart(lenText)
		p.MemoLog.SetSelLength(0)
	})
	atomic.StoreInt32(&p.isRunning, 0)
}

// onStartSearch 启动扫描
func (p *TNetworkPage) onStartSearch(_ vcl.IObject) {
	// 正在运行直接返回，防止重复开协程卡死
	if atomic.LoadInt32(&p.isRunning) == 1 {
		vcl.ShowMessage("当前扫描任务正在执行，请等待完成或点击停止")
		return
	}

	targetIP := strings.TrimSpace(p.EdtTargetIP.Text())
	if targetIP == "" {
		vcl.ShowMessage("请输入目标IP地址")
		return
	}

	atomic.StoreInt32(&p.isRunning, 1)
	p.scanCtx, p.scanCancel = context.WithCancel(context.Background())

	// 主线程同步切换按钮
	vcl.ThreadSync(func() {
		p.BtnStart.SetEnabled(false)
		p.BtnStop.SetEnabled(true)
		p.MemoLog.Clear()
	})
	p.appendLog(fmt.Sprintf("===== 开始检索IP: %s =====", targetIP))

	// 后台扫描协程
	go func(ctx context.Context) {
		// 任务结束强制恢复UI，defer只做标记，不操作UI
		defer func() {
			atomic.StoreInt32(&p.isRunning, 0)
		}()

		// 提前退出判断
		select {
		case <-ctx.Done():
			p.appendLog("扫描已被终止，退出检索")
			p.restoreUI()
			return
		default:
		}

		matchProcs, err := network.SearchIPByAddr(ctx, targetIP)
		if err != nil {
			select {
			case <-ctx.Done():
				p.restoreUI()
				return
			default:
			}
			p.appendLog(fmt.Sprintf("检索网络连接失败: %v", err))
			p.restoreUI()
			return
		}

		if len(matchProcs) == 0 {
			p.appendLog("未找到与该IP关联的任何进程")
			p.appendLog("===== 检索任务完成 =====")
			p.restoreUI()
			return
		}

		p.appendLog(fmt.Sprintf("共匹配到 %d 个关联进程：", len(matchProcs)))
		p.appendLog("----------------------------------------")

		// 遍历进程
		for _, proc := range matchProcs {
			// 每次循环检测停止信号
			select {
			case <-ctx.Done():
				p.appendLog("扫描终止，不再继续遍历进程")
				p.appendLog("===== 检索任务完成 =====")
				p.restoreUI()
				return
			default:
			}

			p.appendLog(fmt.Sprintf("【进程信息】PID: %d | 进程名: %s | 路径: %s", proc.PID, proc.Name, proc.ExePath))

			persistList, err := network.CheckPersistByExePath(proc.ExePath)
			if err != nil {
				p.appendLog(fmt.Sprintf("  自启动检测失败: %v", err))
				p.appendLog("")
				continue
			}
			if len(persistList) == 0 {
				p.appendLog("  未检测到相关自启动/权限维持项")
			} else {
				p.appendLog("  ⚠️ 检测到可疑持久化项：")
				for _, item := range persistList {
					p.appendLog(fmt.Sprintf("    类型: %s | 路径: %s", item.Type, item.Path))
					p.appendLog(fmt.Sprintf("    详情: %s", item.Detail))
				}
			}
			p.appendLog("----------------------------------------")
		}

		// 全部遍历完成
		p.appendLog("===== 检索任务完成 =====")
		p.restoreUI()
	}(p.scanCtx)
}

// appendLog 线程安全写入日志，移除每次自动滚动
func (p *TNetworkPage) appendLog(text string) {
	vcl.ThreadSync(func() {
		now := time.Now().Format("15:04:05")
		line := fmt.Sprintf("[%s] %s", now, text)
		p.MemoLog.Lines().Add(line)
	})
}
