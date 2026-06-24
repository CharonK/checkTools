package ui

import (
	"context"
	"strconv"
	"sync/atomic"

	"Scan/pkg/memscan"

	"github.com/ying32/govcl/vcl"
	"github.com/ying32/govcl/vcl/types"
)

// TMemScanPage 内存检索页面
type TMemScanPage struct {
	Parent *vcl.TTabSheet

	PanelTop   *vcl.TPanel
	EdtKeyword *vcl.TEdit
	BtnSearch  *vcl.TButton
	LvResult   *vcl.TListView

	scanCtx       context.Context
	scanCancel    context.CancelFunc
	isScanRunning int32
}

// NewMemScanPage 初始化内存检索页面
func NewMemScanPage(parent *vcl.TTabSheet) *TMemScanPage {
	p := &TMemScanPage{
		Parent:        parent,
		isScanRunning: 0,
		scanCancel:    func() {},
	}
	p.buildUI()
	p.bindEvent()
	return p
}

func (p *TMemScanPage) buildUI() {
	// 顶部搜索栏面板，固定在顶部
	p.PanelTop = vcl.NewPanel(p.Parent)
	p.PanelTop.SetParent(p.Parent)
	p.PanelTop.SetAlign(types.AlTop)
	p.PanelTop.SetHeight(40)
	p.PanelTop.SetBevelOuter(types.BvNone)

	// 输入框
	p.EdtKeyword = vcl.NewEdit(p.PanelTop)
	p.EdtKeyword.SetParent(p.PanelTop)
	p.EdtKeyword.SetBounds(10, 8, 320, 24)
	p.EdtKeyword.SetTextHint("输入要检索的字符串，支持中文、域名")

	// 右侧检索按钮
	p.BtnSearch = vcl.NewButton(p.PanelTop)
	p.BtnSearch.SetParent(p.PanelTop)
	p.BtnSearch.SetBounds(340, 6, 100, 28)
	p.BtnSearch.SetCaption("开始检索")

	// 结果列表，占满剩余空间
	p.LvResult = vcl.NewListView(p.Parent)
	p.LvResult.SetParent(p.Parent)
	p.LvResult.SetAlign(types.AlClient)
	p.LvResult.SetViewStyle(types.VsReport)
	p.LvResult.SetGridLines(true)
	p.LvResult.SetRowSelect(true)
	p.LvResult.SetReadOnly(true)

	// 列配置
	cols := []struct {
		title string
		width int32
	}{
		{"进程ID", 100},
		{"进程名", 220},
		{"匹配内容", 320},
		{"匹配地址", 160},
		{"匹配类型", 100},
	}
	for _, col := range cols {
		c := p.LvResult.Columns().Add()
		c.SetCaption(col.title)
		c.SetWidth(col.width)
	}
}

func (p *TMemScanPage) bindEvent() {
	// 点击按钮触发检索
	p.BtnSearch.SetOnClick(func(sender vcl.IObject) {
		p.startScan()
	})
}

// startScan 启动内存检索
func (p *TMemScanPage) startScan() {
	keyword := p.EdtKeyword.Text()
	if keyword == "" {
		vcl.ShowMessage("请输入检索关键词")
		return
	}

	// 终止上一轮扫描
	if atomic.LoadInt32(&p.isScanRunning) == 1 {
		p.scanCancel()
		atomic.StoreInt32(&p.isScanRunning, 0)
	}

	atomic.StoreInt32(&p.isScanRunning, 1)
	p.scanCtx, p.scanCancel = context.WithCancel(context.Background())
	p.LvResult.Items().Clear()
	p.BtnSearch.SetCaption("检索中...")
	p.BtnSearch.SetEnabled(false)

	go func(ctx context.Context, kw string) {
		defer func() {
			atomic.StoreInt32(&p.isScanRunning, 0)
			vcl.ThreadSync(func() {
				p.BtnSearch.SetCaption("开始检索")
				p.BtnSearch.SetEnabled(true)
			})
		}()

		ch := memscan.GetMemMatchStream(ctx, kw)
		for item := range ch {
			select {
			case <-ctx.Done():
				return
			default:
			}
			row := item
			vcl.ThreadSync(func() {
				li := p.LvResult.Items().Add()
				li.SetCaption(strconv.Itoa(int(row.Pid)))
				li.SubItems().Add(row.ProcessName)
				li.SubItems().Add(row.MatchString)
				li.SubItems().Add("0x" + strconv.FormatUint(uint64(row.Address), 16))
				li.SubItems().Add(row.MatchType)
			})
		}
	}(p.scanCtx, keyword)
}

// StopScan 停止扫描，页面关闭时调用
func (p *TMemScanPage) StopScan() {
	p.scanCancel()
}
