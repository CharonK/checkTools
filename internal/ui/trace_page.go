package ui

import (
	"context"
	"strconv"
	"sync/atomic"

	"Scan/pkg/trace"

	"github.com/ying32/govcl/vcl"
	"github.com/ying32/govcl/vcl/types"
)

// TTracePage 活动痕迹页面
type TTracePage struct {
	Parent        *vcl.TTabSheet
	PageCtrl      *vcl.TPageControl
	TabPrefetch   *vcl.TTabSheet
	TabUserAssist *vcl.TTabSheet
	TabRecent     *vcl.TTabSheet

	LvPrefetch   *vcl.TListView
	LvUserAssist *vcl.TListView
	LvRecent     *vcl.TListView

	scanCtx       context.Context
	scanCancel    context.CancelFunc
	isScanRunning int32
}

// NewTracePage 初始化活动痕迹页面
func NewTracePage(parent *vcl.TTabSheet) *TTracePage {
	p := &TTracePage{
		Parent:        parent,
		isScanRunning: 0,
		scanCancel:    func() {},
	}
	p.buildUI()
	p.bindEvent()
	// 首次进入默认加载第一个标签
	p.PageCtrl.SetTabIndex(0)
	p.scanPrefetch()

	return p
}

func (p *TTracePage) buildUI() {
	p.PageCtrl = vcl.NewPageControl(p.Parent)
	p.PageCtrl.SetParent(p.Parent)
	p.PageCtrl.SetAlign(types.AlClient)

	// Prefetch记录页
	p.TabPrefetch = vcl.NewTabSheet(p.PageCtrl)
	p.TabPrefetch.SetParent(p.PageCtrl)
	p.TabPrefetch.SetCaption("Prefetch记录")
	p.LvPrefetch = p.createPrefetchListView(p.TabPrefetch)

	// UserAssist活动记录页
	p.TabUserAssist = vcl.NewTabSheet(p.PageCtrl)
	p.TabUserAssist.SetParent(p.PageCtrl)
	p.TabUserAssist.SetCaption("UserAssit活动记录")
	p.LvUserAssist = p.createUserAssistListView(p.TabUserAssist)

	// Recent File记录页
	p.TabRecent = vcl.NewTabSheet(p.PageCtrl)
	p.TabRecent.SetParent(p.PageCtrl)
	p.TabRecent.SetCaption("Recent File记录")
	p.LvRecent = p.createRecentListView(p.TabRecent)
}

func (p *TTracePage) createPrefetchListView(parent *vcl.TTabSheet) *vcl.TListView {
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
		{"时间", 150},
		{"可执行文件", 200},
		{"可执行文件路径", 500},
	}
	for _, col := range cols {
		c := lv.Columns().Add()
		c.SetCaption(col.title)
		c.SetWidth(col.width)
	}
	return lv
}

func (p *TTracePage) createUserAssistListView(parent *vcl.TTabSheet) *vcl.TListView {
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
		{"时间", 150},
		{"可执行文件", 200},
		{"可执行文件路径", 400},
		{"运行次数", 80},
		{"聚焦次数", 80},
	}
	for _, col := range cols {
		c := lv.Columns().Add()
		c.SetCaption(col.title)
		c.SetWidth(col.width)
	}
	return lv
}

func (p *TTracePage) createRecentListView(parent *vcl.TTabSheet) *vcl.TListView {
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
		{"文件名", 200},
		{"文件路径", 350},
		{"创建时间", 150},
		{"修改时间", 150},
		{"目标文件路径", 400},
	}
	for _, col := range cols {
		c := lv.Columns().Add()
		c.SetCaption(col.title)
		c.SetWidth(col.width)
	}
	return lv
}

func (p *TTracePage) bindEvent() {
	p.PageCtrl.SetOnChange(func(sender vcl.IObject) {
		p.onTabChange(sender)
	})
}

func (p *TTracePage) onTabChange(sender vcl.IObject) {
	_ = sender
	// 切换标签终止上一轮扫描，防窜页
	if atomic.LoadInt32(&p.isScanRunning) == 1 {
		p.scanCancel()
	}
	atomic.StoreInt32(&p.isScanRunning, 0)

	idx := p.PageCtrl.TabIndex()
	switch idx {
	case 0:
		p.scanPrefetch()
	case 1:
		p.scanUserAssist()
	case 2:
		p.scanRecent()
	}
}

func (p *TTracePage) resetScanState() {
	atomic.StoreInt32(&p.isScanRunning, 0)
}

// 逐条渲染Prefetch记录
func (p *TTracePage) scanPrefetch() {
	if atomic.LoadInt32(&p.isScanRunning) == 1 {
		return
	}
	atomic.StoreInt32(&p.isScanRunning, 1)
	p.scanCtx, p.scanCancel = context.WithCancel(context.Background())
	p.LvPrefetch.Items().Clear()

	go func(ctx context.Context) {
		defer p.resetScanState()
		ch := trace.GetPrefetchListStream(ctx)
		for item := range ch {
			select {
			case <-ctx.Done():
				return
			default:
			}
			row := item
			vcl.ThreadSync(func() {
				li := p.LvPrefetch.Items().Add()
				li.SetCaption(row.RunTime.Format("2006-01-02 15:04:05"))
				li.SubItems().Add(row.ExeName)
				li.SubItems().Add(row.ExePath)
			})
		}
	}(p.scanCtx)
}

// 逐条渲染UserAssist活动记录
func (p *TTracePage) scanUserAssist() {
	if atomic.LoadInt32(&p.isScanRunning) == 1 {
		return
	}
	atomic.StoreInt32(&p.isScanRunning, 1)
	p.scanCtx, p.scanCancel = context.WithCancel(context.Background())
	p.LvUserAssist.Items().Clear()

	go func(ctx context.Context) {
		defer p.resetScanState()
		ch := trace.GetUserAssistListStream(ctx)
		for item := range ch {
			select {
			case <-ctx.Done():
				return
			default:
			}
			row := item
			vcl.ThreadSync(func() {
				li := p.LvUserAssist.Items().Add()
				if row.LastRunTime.IsZero() {
					li.SetCaption("未记录")
				} else {
					li.SetCaption(row.LastRunTime.Format("2006-01-02 15:04:05"))
				}
				li.SubItems().Add(row.ExeName)
				li.SubItems().Add(row.ExePath)
				li.SubItems().Add(strconv.Itoa(row.RunCount))
				li.SubItems().Add(strconv.Itoa(row.FocusCount))
			})
		}
	}(p.scanCtx)
}

// 逐条渲染Recent File记录
func (p *TTracePage) scanRecent() {
	if atomic.LoadInt32(&p.isScanRunning) == 1 {
		return
	}
	atomic.StoreInt32(&p.isScanRunning, 1)
	p.scanCtx, p.scanCancel = context.WithCancel(context.Background())
	p.LvRecent.Items().Clear()

	go func(ctx context.Context) {
		defer p.resetScanState()
		ch := trace.GetRecentFilesStream(ctx)
		for item := range ch {
			select {
			case <-ctx.Done():
				return
			default:
			}
			row := item
			vcl.ThreadSync(func() {
				li := p.LvRecent.Items().Add()
				li.SetCaption(row.FileName)
				li.SubItems().Add(row.FilePath)
				if row.CreateTime.IsZero() {
					li.SubItems().Add("未记录")
				} else {
					li.SubItems().Add(row.CreateTime.Format("2006-01-02 15:04:05"))
				}
				li.SubItems().Add(row.ModifyTime.Format("2006-01-02 15:04:05"))
				li.SubItems().Add(row.TargetPath)
			})
		}
	}(p.scanCtx)
}

func (p *TTracePage) StopScan() {
	p.scanCancel()
}
