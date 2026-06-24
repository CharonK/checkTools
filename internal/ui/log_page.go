package ui

import (
	"context"
	"sync/atomic"

	"Scan/pkg/eventlog"

	"github.com/ying32/govcl/vcl"
	"github.com/ying32/govcl/vcl/types"
)

// TLogPage 日志分析页结构体
type TLogPage struct {
	Parent   *vcl.TTabSheet
	PageCtrl *vcl.TPageControl

	// 子标签页
	TabLoginSuccess *vcl.TTabSheet
	TabLoginFail    *vcl.TTabSheet
	TabRDPLogin     *vcl.TTabSheet
	TabRDPConnect   *vcl.TTabSheet
	TabService      *vcl.TTabSheet
	TabUserCreate   *vcl.TTabSheet
	TabSqlServer    *vcl.TTabSheet
	TabPowerShell   *vcl.TTabSheet
	TabNetConn      *vcl.TTabSheet
	TabTaskSched    *vcl.TTabSheet

	// 列表控件
	LvLoginSuccess *vcl.TListView
	LvLoginFail    *vcl.TListView
	LvRDPLogin     *vcl.TListView
	LvRDPConnect   *vcl.TListView
	LvService      *vcl.TListView
	LvUserCreate   *vcl.TListView
	LvSqlServer    *vcl.TListView
	LvPowerShell   *vcl.TListView
	LvNetConn      *vcl.TListView
	LvTaskSched    *vcl.TListView

	scanCtx    context.Context
	scanCancel context.CancelFunc
	isRunning  int32
}

// NewLogPage 初始化日志分析页
func NewLogPage(parent *vcl.TTabSheet) *TLogPage {
	p := &TLogPage{
		Parent: parent,
	}
	p.buildUI()
	p.bindEvents()
	return p
}

func (p *TLogPage) buildUI() {
	// 二级标签页容器，铺满整个父标签页
	p.PageCtrl = vcl.NewPageControl(p.Parent)
	p.PageCtrl.SetParent(p.Parent)
	p.PageCtrl.SetAlign(types.AlClient)

	// 1. 登录成功
	p.TabLoginSuccess = vcl.NewTabSheet(p.PageCtrl)
	p.TabLoginSuccess.SetParent(p.PageCtrl)
	p.TabLoginSuccess.SetCaption("登录成功")
	p.LvLoginSuccess = p.createLoginList(p.TabLoginSuccess)

	// 2. 登录失败
	p.TabLoginFail = vcl.NewTabSheet(p.PageCtrl)
	p.TabLoginFail.SetParent(p.PageCtrl)
	p.TabLoginFail.SetCaption("登录失败")
	p.LvLoginFail = p.createLoginList(p.TabLoginFail)

	// 3. RDP登录
	p.TabRDPLogin = vcl.NewTabSheet(p.PageCtrl)
	p.TabRDPLogin.SetParent(p.PageCtrl)
	p.TabRDPLogin.SetCaption("RDP登录")
	p.LvRDPLogin = p.createLoginList(p.TabRDPLogin)

	// 4. RDP连接
	p.TabRDPConnect = vcl.NewTabSheet(p.PageCtrl)
	p.TabRDPConnect.SetParent(p.PageCtrl)
	p.TabRDPConnect.SetCaption("RDP连接")
	p.LvRDPConnect = p.createLoginList(p.TabRDPConnect)

	// 5. 服务创建
	p.TabService = vcl.NewTabSheet(p.PageCtrl)
	p.TabService.SetParent(p.PageCtrl)
	p.TabService.SetCaption("服务创建")
	p.LvService = p.createServiceList(p.TabService)

	// 6. 用户创建日志
	p.TabUserCreate = vcl.NewTabSheet(p.PageCtrl)
	p.TabUserCreate.SetParent(p.PageCtrl)
	p.TabUserCreate.SetCaption("用户创建日志")
	p.LvUserCreate = p.createUserCreateList(p.TabUserCreate)

	// 7. SQL Server日志
	p.TabSqlServer = vcl.NewTabSheet(p.PageCtrl)
	p.TabSqlServer.SetParent(p.PageCtrl)
	p.TabSqlServer.SetCaption("SQL Server日志")
	p.LvSqlServer = p.createSqlServerList(p.TabSqlServer)

	// 8. PowerShell日志
	p.TabPowerShell = vcl.NewTabSheet(p.PageCtrl)
	p.TabPowerShell.SetParent(p.PageCtrl)
	p.TabPowerShell.SetCaption("PowerShell日志")
	p.LvPowerShell = p.createPowerShellList(p.TabPowerShell)

	// 9. 出站入站连接记录
	p.TabNetConn = vcl.NewTabSheet(p.PageCtrl)
	p.TabNetConn.SetParent(p.PageCtrl)
	p.TabNetConn.SetCaption("出站入站连接记录")
	p.LvNetConn = p.createNetConnList(p.TabNetConn)

	// 10. 计划任务日志
	p.TabTaskSched = vcl.NewTabSheet(p.PageCtrl)
	p.TabTaskSched.SetParent(p.PageCtrl)
	p.TabTaskSched.SetCaption("计划任务日志")
	p.LvTaskSched = p.createTaskSchedList(p.TabTaskSched)
}

func (p *TLogPage) bindEvents() {
	p.PageCtrl.SetOnChange(func(sender vcl.IObject) {
		p.stopCurrentScan()
		switch p.PageCtrl.ActivePageIndex() {
		case 0:
			p.loadLoginSuccess()
		case 1:
			p.loadLoginFail()
		case 2:
			p.loadRDPLogin()
		case 3:
			p.loadRDPConnect()
		case 4:
			p.loadServiceCreate()
		case 5:
			p.loadUserCreate()
		case 6:
			p.loadSqlServer()
		case 7:
			p.loadPowerShell()
		case 8:
			p.loadNetConn()
		case 9:
			p.loadTaskSched()
		}
	})

	// 默认加载第一个标签页
	p.PageCtrl.SetActivePageIndex(0)
	p.loadLoginSuccess()
}

// ===================== 列表创建函数 =====================

func (p *TLogPage) createLoginList(parent *vcl.TTabSheet) *vcl.TListView {
	lv := vcl.NewListView(parent)
	lv.SetParent(parent)
	lv.SetAlign(types.AlClient)
	lv.SetViewStyle(types.VsReport)
	lv.SetGridLines(true)
	lv.SetReadOnly(true)

	cols := []struct {
		title string
		width int32
	}{
		{"时间", 160}, {"事件ID", 80},
		{"命令", 500}, {"主机", 150}, {"描述", 200},
	}
	for _, c := range cols {
		col := lv.Columns().Add()
		col.SetCaption(c.title)
		col.SetWidth(c.width)
	}
	return lv
}

func (p *TLogPage) createServiceList(parent *vcl.TTabSheet) *vcl.TListView {
	lv := vcl.NewListView(parent)
	lv.SetParent(parent)
	lv.SetAlign(types.AlClient)
	lv.SetViewStyle(types.VsReport)
	lv.SetGridLines(true)
	lv.SetReadOnly(true)

	cols := []struct {
		title string
		width int32
	}{
		{"时间", 160}, {"事件ID", 80},
		{"服务名称", 260}, {"服务路径", 260},
		{"服务类型", 140}, {"启动类型", 120},
		{"登录账号", 160}, {"日志描述", 200},
	}
	for _, c := range cols {
		col := lv.Columns().Add()
		col.SetCaption(c.title)
		col.SetWidth(c.width)
	}
	return lv
}

func (p *TLogPage) createUserCreateList(parent *vcl.TTabSheet) *vcl.TListView {
	lv := vcl.NewListView(parent)
	lv.SetParent(parent)
	lv.SetAlign(types.AlClient)
	lv.SetViewStyle(types.VsReport)
	lv.SetGridLines(true)
	lv.SetReadOnly(true)

	cols := []struct {
		title string
		width int32
	}{
		{"时间", 160}, {"事件ID", 80},
		{"操作用户", 160}, {"操作用户所在域", 180},
		{"新用户", 160}, {"新用户所在域", 180},
		{"权限", 200}, {"描述", 200},
	}
	for _, c := range cols {
		col := lv.Columns().Add()
		col.SetCaption(c.title)
		col.SetWidth(c.width)
	}
	return lv
}

func (p *TLogPage) createSqlServerList(parent *vcl.TTabSheet) *vcl.TListView {
	lv := vcl.NewListView(parent)
	lv.SetParent(parent)
	lv.SetAlign(types.AlClient)
	lv.SetViewStyle(types.VsReport)
	lv.SetGridLines(true)
	lv.SetReadOnly(true)

	cols := []struct {
		title string
		width int32
	}{
		{"时间", 160}, {"事件ID", 80},
		{"登录用户", 160}, {"登录地址", 160},
		{"sqlserver函数", 200}, {"旧值", 120},
		{"新值", 120}, {"日志描述", 300},
	}
	for _, c := range cols {
		col := lv.Columns().Add()
		col.SetCaption(c.title)
		col.SetWidth(c.width)
	}
	return lv
}

func (p *TLogPage) createPowerShellList(parent *vcl.TTabSheet) *vcl.TListView {
	lv := vcl.NewListView(parent)
	lv.SetParent(parent)
	lv.SetAlign(types.AlClient)
	lv.SetViewStyle(types.VsReport)
	lv.SetGridLines(true)
	lv.SetReadOnly(true)

	cols := []struct {
		title string
		width int32
	}{
		{"时间", 160}, {"事件ID", 80},
		{"命令", 520}, {"主机", 120},
		{"描述", 140}, {"威胁描述", 300},
	}
	for _, c := range cols {
		col := lv.Columns().Add()
		col.SetCaption(c.title)
		col.SetWidth(c.width)
	}
	return lv
}

func (p *TLogPage) createNetConnList(parent *vcl.TTabSheet) *vcl.TListView {
	lv := vcl.NewListView(parent)
	lv.SetParent(parent)
	lv.SetAlign(types.AlClient)
	lv.SetViewStyle(types.VsReport)
	lv.SetGridLines(true)
	lv.SetReadOnly(true)

	cols := []struct {
		title string
		width int32
	}{
		{"时间", 160}, {"事件ID", 80},
		{"源地址", 220}, {"目的地址", 220},
		{"协议", 100}, {"描述", 200},
	}
	for _, c := range cols {
		col := lv.Columns().Add()
		col.SetCaption(c.title)
		col.SetWidth(c.width)
	}
	return lv
}

func (p *TLogPage) createTaskSchedList(parent *vcl.TTabSheet) *vcl.TListView {
	lv := vcl.NewListView(parent)
	lv.SetParent(parent)
	lv.SetAlign(types.AlClient)
	lv.SetViewStyle(types.VsReport)
	lv.SetGridLines(true)
	lv.SetReadOnly(true)

	cols := []struct {
		title string
		width int32
	}{
		{"时间", 160}, {"主机", 150}, {"事件ID", 80},
		{"动作", 140}, {"任务", 260},
		{"用户", 160}, {"计划任务内容", 300},
	}
	for _, c := range cols {
		col := lv.Columns().Add()
		col.SetCaption(c.title)
		col.SetWidth(c.width)
	}
	return lv
}

// ===================== 数据加载控制 =====================

func (p *TLogPage) stopCurrentScan() {
	if atomic.LoadInt32(&p.isRunning) == 1 && p.scanCancel != nil {
		p.scanCancel()
	}
}

// ===================== 各标签页数据加载 =====================

func (p *TLogPage) loadLoginSuccess() {
	p.scanCtx, p.scanCancel = context.WithCancel(context.Background())
	atomic.StoreInt32(&p.isRunning, 1)
	p.LvLoginSuccess.Items().Clear()

	go func() {
		defer atomic.StoreInt32(&p.isRunning, 0)
		ch := eventlog.GetLoginSuccessStream(p.scanCtx)
		for item := range ch {
			select {
			case <-p.scanCtx.Done():
				return
			default:
			}
			row := item
			vcl.ThreadSync(func() {
				li := p.LvLoginSuccess.Items().Add()
				li.SetCaption(row.Time)
				li.SubItems().Add(row.EventID)
				li.SubItems().Add(row.UserName)
				li.SubItems().Add(row.Host)
				li.SubItems().Add(row.Description)
			})
		}
	}()
}

func (p *TLogPage) loadLoginFail() {
	p.scanCtx, p.scanCancel = context.WithCancel(context.Background())
	atomic.StoreInt32(&p.isRunning, 1)
	p.LvLoginFail.Items().Clear()

	go func() {
		defer atomic.StoreInt32(&p.isRunning, 0)
		ch := eventlog.GetLoginFailStream(p.scanCtx)
		for item := range ch {
			select {
			case <-p.scanCtx.Done():
				return
			default:
			}
			row := item
			vcl.ThreadSync(func() {
				li := p.LvLoginFail.Items().Add()
				li.SetCaption(row.Time)
				li.SubItems().Add(row.EventID)
				li.SubItems().Add(row.UserName)
				li.SubItems().Add(row.Host)
				li.SubItems().Add(row.Description)
			})
		}
	}()
}

func (p *TLogPage) loadRDPLogin() {
	p.scanCtx, p.scanCancel = context.WithCancel(context.Background())
	atomic.StoreInt32(&p.isRunning, 1)
	p.LvRDPLogin.Items().Clear()

	go func() {
		defer atomic.StoreInt32(&p.isRunning, 0)
		ch := eventlog.GetRDPLoginStream(p.scanCtx)
		for item := range ch {
			select {
			case <-p.scanCtx.Done():
				return
			default:
			}
			row := item
			vcl.ThreadSync(func() {
				li := p.LvRDPLogin.Items().Add()
				li.SetCaption(row.Time)
				li.SubItems().Add(row.EventID)
				li.SubItems().Add(row.UserName)
				li.SubItems().Add(row.Host)
				li.SubItems().Add(row.Description)
			})
		}
	}()
}

func (p *TLogPage) loadRDPConnect() {
	p.scanCtx, p.scanCancel = context.WithCancel(context.Background())
	atomic.StoreInt32(&p.isRunning, 1)
	p.LvRDPConnect.Items().Clear()

	go func() {
		defer atomic.StoreInt32(&p.isRunning, 0)
		ch := eventlog.GetRDPConnectStream(p.scanCtx)
		for item := range ch {
			select {
			case <-p.scanCtx.Done():
				return
			default:
			}
			row := item
			vcl.ThreadSync(func() {
				li := p.LvRDPConnect.Items().Add()
				li.SetCaption(row.Time)
				li.SubItems().Add(row.EventID)
				li.SubItems().Add(row.UserName)
				li.SubItems().Add(row.Host)
				li.SubItems().Add(row.Description)
			})
		}
	}()
}

func (p *TLogPage) loadServiceCreate() {
	p.scanCtx, p.scanCancel = context.WithCancel(context.Background())
	atomic.StoreInt32(&p.isRunning, 1)
	p.LvService.Items().Clear()

	go func() {
		defer atomic.StoreInt32(&p.isRunning, 0)
		ch := eventlog.GetServiceCreateStream(p.scanCtx)
		for item := range ch {
			select {
			case <-p.scanCtx.Done():
				return
			default:
			}
			row := item
			vcl.ThreadSync(func() {
				li := p.LvService.Items().Add()
				li.SetCaption(row.Time)
				li.SubItems().Add(row.EventID)
				li.SubItems().Add(row.SvcName)
				li.SubItems().Add(row.SvcPath)
				li.SubItems().Add(row.SvcType)
				li.SubItems().Add(row.SvcStartType)
				li.SubItems().Add(row.SvcAccount)
				li.SubItems().Add(row.Description)
			})
		}
	}()
}

func (p *TLogPage) loadUserCreate() {
	p.scanCtx, p.scanCancel = context.WithCancel(context.Background())
	atomic.StoreInt32(&p.isRunning, 1)
	p.LvUserCreate.Items().Clear()

	go func() {
		defer atomic.StoreInt32(&p.isRunning, 0)
		ch := eventlog.GetUserCreateStream(p.scanCtx)
		for item := range ch {
			select {
			case <-p.scanCtx.Done():
				return
			default:
			}
			row := item
			vcl.ThreadSync(func() {
				li := p.LvUserCreate.Items().Add()
				li.SetCaption(row.Time)
				li.SubItems().Add(row.EventID)
				li.SubItems().Add(row.OperatorUser)
				li.SubItems().Add(row.OperatorDomain)
				li.SubItems().Add(row.NewUser)
				li.SubItems().Add(row.NewUserDomain)
				li.SubItems().Add(row.Privilege)
				li.SubItems().Add(row.Description)
			})
		}
	}()
}

func (p *TLogPage) loadSqlServer() {
	p.scanCtx, p.scanCancel = context.WithCancel(context.Background())
	atomic.StoreInt32(&p.isRunning, 1)
	p.LvSqlServer.Items().Clear()

	go func() {
		defer atomic.StoreInt32(&p.isRunning, 0)
		ch := eventlog.GetSqlServerStream(p.scanCtx)
		for item := range ch {
			select {
			case <-p.scanCtx.Done():
				return
			default:
			}
			row := item
			vcl.ThreadSync(func() {
				li := p.LvSqlServer.Items().Add()
				li.SetCaption(row.Time)
				li.SubItems().Add(row.EventID)
				li.SubItems().Add(row.SqlLoginUser)
				li.SubItems().Add(row.SqlClientIP)
				li.SubItems().Add(row.SqlFunction)
				li.SubItems().Add(row.SqlOldValue)
				li.SubItems().Add(row.SqlNewValue)
				li.SubItems().Add(row.Description)
			})
		}
	}()
}

func (p *TLogPage) loadPowerShell() {
	p.scanCtx, p.scanCancel = context.WithCancel(context.Background())
	atomic.StoreInt32(&p.isRunning, 1)
	p.LvPowerShell.Items().Clear()

	go func() {
		defer atomic.StoreInt32(&p.isRunning, 0)
		ch := eventlog.GetPowerShellStream(p.scanCtx)
		for item := range ch {
			select {
			case <-p.scanCtx.Done():
				return
			default:
			}
			row := item
			vcl.ThreadSync(func() {
				li := p.LvPowerShell.Items().Add()
				li.SetCaption(row.Time)
				li.SubItems().Add(row.EventID)
				li.SubItems().Add(row.Command)
				li.SubItems().Add(row.Host)
				li.SubItems().Add(row.Description)
				li.SubItems().Add(row.ThreatDesc)
			})
		}
	}()
}

func (p *TLogPage) loadNetConn() {
	p.scanCtx, p.scanCancel = context.WithCancel(context.Background())
	atomic.StoreInt32(&p.isRunning, 1)
	p.LvNetConn.Items().Clear()

	go func() {
		defer atomic.StoreInt32(&p.isRunning, 0)
		ch := eventlog.GetNetConnectStream(p.scanCtx)
		for item := range ch {
			select {
			case <-p.scanCtx.Done():
				return
			default:
			}
			row := item
			vcl.ThreadSync(func() {
				li := p.LvNetConn.Items().Add()
				li.SetCaption(row.Time)
				li.SubItems().Add(row.EventID)
				li.SubItems().Add(row.SrcAddr)
				li.SubItems().Add(row.DstAddr)
				li.SubItems().Add(row.Proto)
				li.SubItems().Add(row.Description)
			})
		}
	}()
}

func (p *TLogPage) loadTaskSched() {
	p.scanCtx, p.scanCancel = context.WithCancel(context.Background())
	atomic.StoreInt32(&p.isRunning, 1)
	p.LvTaskSched.Items().Clear()

	go func() {
		defer atomic.StoreInt32(&p.isRunning, 0)
		ch := eventlog.GetTaskScheduleStream(p.scanCtx)
		for item := range ch {
			select {
			case <-p.scanCtx.Done():
				return
			default:
			}
			row := item
			vcl.ThreadSync(func() {
				li := p.LvTaskSched.Items().Add()
				li.SetCaption(row.Time)
				li.SubItems().Add(row.Host)
				li.SubItems().Add(row.EventID)
				li.SubItems().Add(row.TaskAction)
				li.SubItems().Add(row.TaskName)
				li.SubItems().Add(row.TaskUser)
				li.SubItems().Add(row.TaskContent)
			})
		}
	}()
}
