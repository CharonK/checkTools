package ui

import "github.com/ying32/govcl/vcl"

type TTracePage struct {
	Parent *vcl.TTabSheet
}

func NewTracePage(parent *vcl.TTabSheet) *TTracePage {
	p := &TTracePage{Parent: parent}
	p.buildUI()
	return p
}

func (p *TTracePage) buildUI() {
	tip := vcl.NewLabel(p.Parent)
	tip.SetParent(p.Parent)
	tip.SetLeft(20)
	tip.SetTop(20)
	tip.SetCaption("活动痕迹：Prefetch/UserAssist/Recent 历史操作记录采集")
}
