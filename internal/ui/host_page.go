package ui

import "github.com/ying32/govcl/vcl"

type THostPage struct {
	Parent *vcl.TTabSheet
}

func NewHostPage(parent *vcl.TTabSheet) *THostPage {
	p := &THostPage{Parent: parent}
	p.buildUI()
	return p
}

func (p *THostPage) buildUI() {
	tip := vcl.NewLabel(p.Parent)
	tip.SetParent(p.Parent)
	tip.SetLeft(20)
	tip.SetTop(20)
	tip.SetCaption("主机信息模块：用户/服务/计划任务/自启动 + Yara文件扫描")
}
