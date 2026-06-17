package ui

import "github.com/ying32/govcl/vcl"

type TNetworkPage struct {
	Parent *vcl.TTabSheet
}

func NewNetworkPage(parent *vcl.TTabSheet) *TNetworkPage {
	p := &TNetworkPage{Parent: parent}
	p.buildUI()
	return p
}

func (p *TNetworkPage) buildUI() {
	tip := vcl.NewLabel(p.Parent)
	tip.SetParent(p.Parent)
	tip.SetLeft(20)
	tip.SetTop(20)
	tip.SetCaption("外连分析模块：IP定位异常进程 + 权限维持项溯源")
}
