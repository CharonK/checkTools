package ui

import "github.com/ying32/govcl/vcl"

type TBeaconPage struct {
	Parent *vcl.TTabSheet
}

func NewBeaconPage(parent *vcl.TTabSheet) *TBeaconPage {
	p := &TBeaconPage{Parent: parent}
	p.buildUI()
	return p
}

func (p *TBeaconPage) buildUI() {
	tip := vcl.NewLabel(p.Parent)
	tip.SetParent(p.Parent)
	tip.SetLeft(20)
	tip.SetTop(20)
	tip.SetCaption("Beacon扫描模块：CobaltStrike Beacon 内存特征检索")
}
