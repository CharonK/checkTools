package ui

import "github.com/ying32/govcl/vcl"

type TLogPage struct {
	Parent *vcl.TTabSheet
}

func NewLogPage(parent *vcl.TTabSheet) *TLogPage {
	p := &TLogPage{Parent: parent}
	p.buildUI()
	return p
}

func (p *TLogPage) buildUI() {
	tip := vcl.NewLabel(p.Parent)
	tip.SetParent(p.Parent)
	tip.SetLeft(20)
	tip.SetTop(20)
	tip.SetCaption("日志分析模块：Windows事件ID一键筛选（登录/RDP/SQL/PowerShell等）")
}
