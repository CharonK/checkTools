package ui

import (
	"Scan/internal/host"
	"Scan/pkg/yara"
	"context"
	"os/exec"
	"sync/atomic"

	"github.com/ying32/govcl/vcl"
	"github.com/ying32/govcl/vcl/types"
)

// THostPage 主机信息页面
type THostPage struct {
	Parent     *vcl.TTabSheet
	PageCtrl   *vcl.TPageControl
	TabUser    *vcl.TTabSheet
	TabTask    *vcl.TTabSheet
	TabService *vcl.TTabSheet
	TabStartup *vcl.TTabSheet
	LvUser     *vcl.TListView
	LvTask     *vcl.TListView
	LvService  *vcl.TListView
	LvStartup  *vcl.TListView

	// 计划任务右键菜单
	TaskPopupMenu *vcl.TPopupMenu
	MiOpenTaskDir *vcl.TMenuItem

	scanCtx       context.Context
	scanCancel    context.CancelFunc
	isScanRunning int32
}

// GlobalYaraScanner 全局YARA扫描器实例
var GlobalYaraScanner *yara.Scanner

// NewHostPage 初始化主机页面
func NewHostPage(parent *vcl.TTabSheet) *THostPage {
	p := &THostPage{
		Parent:        parent,
		isScanRunning: 0,
		scanCancel:    func() {},
	}
	p.buildUI()
	p.bindEvent()
	p.PageCtrl.SetTabIndex(0)
	p.scanUserList()

	return p
}

func (p *THostPage) buildUI() {
	p.PageCtrl = vcl.NewPageControl(p.Parent)
	p.PageCtrl.SetParent(p.Parent)
	p.PageCtrl.SetAlign(types.AlClient)

	// 用户信息页
	p.TabUser = vcl.NewTabSheet(p.PageCtrl)
	p.TabUser.SetParent(p.PageCtrl)
	p.TabUser.SetCaption("用户信息")
	p.LvUser = p.createUserListView(p.TabUser)

	// 计划任务页
	p.TabTask = vcl.NewTabSheet(p.PageCtrl)
	p.TabTask.SetParent(p.PageCtrl)
	p.TabTask.SetCaption("计划任务")
	p.LvTask = p.createTaskListView(p.TabTask)
	// 初始化右键菜单
	p.initTaskPopupMenu()

	// 服务信息页
	p.TabService = vcl.NewTabSheet(p.PageCtrl)
	p.TabService.SetParent(p.PageCtrl)
	p.TabService.SetCaption("服务信息")
	p.LvService = p.createServiceListView(p.TabService)

	// 启动项信息页
	p.TabStartup = vcl.NewTabSheet(p.PageCtrl)
	p.TabStartup.SetParent(p.PageCtrl)
	p.TabStartup.SetCaption("启动项信息")
	p.LvStartup = p.createStartupListView(p.TabStartup)
}

// 初始化计划任务右键菜单
func (p *THostPage) initTaskPopupMenu() {
	p.TaskPopupMenu = vcl.NewPopupMenu(p.Parent)
	p.MiOpenTaskDir = vcl.NewMenuItem(p.TaskPopupMenu)
	p.MiOpenTaskDir.SetCaption("打开文件所在位置")
	p.TaskPopupMenu.Items().Add(p.MiOpenTaskDir)
	p.LvTask.SetPopupMenu(p.TaskPopupMenu)
	p.MiOpenTaskDir.SetOnClick(p.onOpenTaskDir)
}

// 右键打开任务文件所在目录
func (p *THostPage) onOpenTaskDir(sender vcl.IObject) {
	_ = sender
	selected := p.LvTask.Selected()
	if selected == nil {
		return
	}
	// 第1列（Caption）是任务名称，第2列（SubItems[0]）是任务文件路径
	filePath := selected.SubItems().Strings(0)
	if filePath == "" {
		return
	}
	// 调用资源管理器并选中文件
	cmd := exec.Command("explorer", "/select,", filePath)
	_ = cmd.Start()
}

func (p *THostPage) createUserListView(parent *vcl.TTabSheet) *vcl.TListView {
	lv := vcl.NewListView(parent)
	lv.SetParent(parent)
	lv.SetAlign(types.AlClient)
	lv.SetViewStyle(types.VsReport)
	lv.SetGridLines(true)
	lv.SetRowSelect(true)
	lv.SetReadOnly(true)

	col1 := lv.Columns().Add()
	col1.SetCaption("用户名")
	col1.SetWidth(220)
	col2 := lv.Columns().Add()
	col2.SetCaption("状态")
	col2.SetWidth(120)
	col3 := lv.Columns().Add()
	col3.SetCaption("备注")
	col3.SetWidth(300)
	return lv
}

func (p *THostPage) createTaskListView(parent *vcl.TTabSheet) *vcl.TListView {
	lv := vcl.NewListView(parent)
	lv.SetParent(parent)
	lv.SetAlign(types.AlClient)
	lv.SetViewStyle(types.VsReport)
	lv.SetGridLines(true)
	lv.SetRowSelect(true)
	lv.SetReadOnly(true)

	cols := []struct {
		title string
		width int32
	}{
		{"任务名称", 220},
		{"任务文件路径", 300}, // 新增列
		{"任务命令", 260},
		{"任务参数", 160},
		{"任务用户", 140},
		{"触发器", 140},
		{"任务描述", 240},
		{"签名信息", 100},
		{"YARA扫描结果", 100},
		{"状态", 80},
	}
	for _, col := range cols {
		c := lv.Columns().Add()
		c.SetCaption(col.title)
		c.SetWidth(col.width)
	}
	return lv
}

func (p *THostPage) createServiceListView(parent *vcl.TTabSheet) *vcl.TListView {
	lv := vcl.NewListView(parent)
	lv.SetParent(parent)
	lv.SetAlign(types.AlClient)
	lv.SetViewStyle(types.VsReport)
	lv.SetGridLines(true)
	lv.SetRowSelect(true)
	lv.SetReadOnly(true)

	cols := []struct {
		title string
		width int32
	}{
		{"服务名", 220},
		{"服务状态", 140},
		{"服务描述", 260},
		{"可执行文件路径", 380},
		{"签名信息", 120},
		{"YARA扫描结果", 120},
	}
	for _, col := range cols {
		c := lv.Columns().Add()
		c.SetCaption(col.title)
		c.SetWidth(col.width)
	}
	return lv
}

func (p *THostPage) createStartupListView(parent *vcl.TTabSheet) *vcl.TListView {
	lv := vcl.NewListView(parent)
	lv.SetParent(parent)
	lv.SetAlign(types.AlClient)
	lv.SetViewStyle(types.VsReport)
	lv.SetGridLines(true)
	lv.SetRowSelect(true)
	lv.SetReadOnly(true)

	cols := []struct {
		title string
		width int32
	}{
		{"启动项名称", 220},
		{"可执行文件路径", 420},
		{"签名信息", 120},
		{"YARA扫描结果", 120},
	}
	for _, col := range cols {
		c := lv.Columns().Add()
		c.SetCaption(col.title)
		c.SetWidth(col.width)
	}
	return lv
}

func (p *THostPage) bindEvent() {
	p.PageCtrl.SetOnChange(func(sender vcl.IObject) {
		p.onTabChange(sender)
	})
}

func (p *THostPage) onTabChange(sender vcl.IObject) {
	_ = sender
	if atomic.LoadInt32(&p.isScanRunning) == 1 {
		p.scanCancel()
	}
	atomic.StoreInt32(&p.isScanRunning, 0)

	idx := p.PageCtrl.TabIndex()
	switch idx {
	case 0:
		p.scanUserList()
	case 1:
		p.scanTaskList()
	case 2:
		p.scanServiceList()
	case 3:
		p.scanStartupList()
	}
}

func (p *THostPage) resetScanState() {
	atomic.StoreInt32(&p.isScanRunning, 0)
}

// 逐条渲染用户列表
func (p *THostPage) scanUserList() {
	if atomic.LoadInt32(&p.isScanRunning) == 1 {
		return
	}
	atomic.StoreInt32(&p.isScanRunning, 1)
	p.scanCtx, p.scanCancel = context.WithCancel(context.Background())
	p.LvUser.Items().Clear()

	go func(ctx context.Context) {
		defer p.resetScanState()
		userChan := host.GetAllUserListStream(ctx)
		for user := range userChan {
			select {
			case <-ctx.Done():
				return
			default:
			}
			row := user
			vcl.ThreadSync(func() {
				item := p.LvUser.Items().Add()
				item.SetCaption(row.UserName)
				item.SubItems().Add(row.Status)
				item.SubItems().Add(row.Remark)
			})
		}
	}(p.scanCtx)
}

// 逐条渲染计划任务
func (p *THostPage) scanTaskList() {
	if atomic.LoadInt32(&p.isScanRunning) == 1 {
		return
	}
	atomic.StoreInt32(&p.isScanRunning, 1)
	p.scanCtx, p.scanCancel = context.WithCancel(context.Background())
	p.LvTask.Items().Clear()

	go func(ctx context.Context) {
		defer p.resetScanState()
		if GlobalYaraScanner == nil {
			return
		}
		taskChan := host.GetAllTaskListStream(ctx, GlobalYaraScanner)
		for task := range taskChan {
			select {
			case <-ctx.Done():
				return
			default:
			}
			row := task
			vcl.ThreadSync(func() {
				item := p.LvTask.Items().Add()
				item.SetCaption(row.TaskName)
				item.SubItems().Add(row.FilePath) // 新增文件路径列
				item.SubItems().Add(row.CmdPath)
				item.SubItems().Add(row.Arguments)
				item.SubItems().Add(row.RunUser)
				item.SubItems().Add(row.TriggerTime)
				item.SubItems().Add(row.Description)
				item.SubItems().Add(row.SignInfo)
				item.SubItems().Add(row.YaraResult)
				item.SubItems().Add(row.Remark)
			})
		}
	}(p.scanCtx)
}

// 逐条渲染服务列表
func (p *THostPage) scanServiceList() {
	if atomic.LoadInt32(&p.isScanRunning) == 1 {
		return
	}
	atomic.StoreInt32(&p.isScanRunning, 1)
	p.scanCtx, p.scanCancel = context.WithCancel(context.Background())
	p.LvService.Items().Clear()

	go func(ctx context.Context) {
		defer p.resetScanState()
		if GlobalYaraScanner == nil {
			return
		}
		svcChan := host.GetAllServiceListStream(ctx, GlobalYaraScanner)
		for svc := range svcChan {
			select {
			case <-ctx.Done():
				return
			default:
			}
			row := svc
			vcl.ThreadSync(func() {
				item := p.LvService.Items().Add()
				item.SetCaption(row.SvcName)
				item.SubItems().Add(row.Status)
				item.SubItems().Add(row.Description)
				item.SubItems().Add(row.BinPath)
				item.SubItems().Add(row.SignInfo)
				item.SubItems().Add(row.YaraResult)
			})
		}
	}(p.scanCtx)
}

// 逐条渲染启动项
func (p *THostPage) scanStartupList() {
	if atomic.LoadInt32(&p.isScanRunning) == 1 {
		return
	}
	atomic.StoreInt32(&p.isScanRunning, 1)
	p.scanCtx, p.scanCancel = context.WithCancel(context.Background())
	p.LvStartup.Items().Clear()

	go func(ctx context.Context) {
		defer p.resetScanState()
		if GlobalYaraScanner == nil {
			return
		}
		startChan := host.GetAllStartupListStream(ctx, GlobalYaraScanner)
		for item := range startChan {
			select {
			case <-ctx.Done():
				return
			default:
			}
			row := item
			vcl.ThreadSync(func() {
				listItem := p.LvStartup.Items().Add()
				listItem.SetCaption(row.ItemName)
				listItem.SubItems().Add(row.ExePath)
				listItem.SubItems().Add(row.SignInfo)
				listItem.SubItems().Add(row.YaraRes)
			})
		}
	}(p.scanCtx)
}

func (p *THostPage) StopScan() {
	p.scanCancel()
}
