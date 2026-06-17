package ui

import "github.com/ying32/govcl/vcl"

type TMemSearchPage struct {
	Parent *vcl.TTabSheet
}

func NewMemSearchPage(parent *vcl.TTabSheet) *TMemSearchPage {
	p := &TMemSearchPage{Parent: parent}
	p.buildUI()
	return p
}

func (p *TMemSearchPage) buildUI() {
	tip := vcl.NewLabel(p.Parent)
	tip.SetParent(p.Parent)
	tip.SetLeft(20)
	tip.SetTop(20)
	tip.SetCaption("内存检索：按字符串批量检索进程内存，适配挖矿/恶意外连场景")
}
