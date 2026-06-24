package ui

import (
	"github.com/ying32/govcl/vcl"
	"github.com/ying32/govcl/vcl/types"
)

// BeautifyListView 统一美化列表控件，所有属性均为govcl原生支持
func BeautifyListView(lv *vcl.TListView) {
	// 开启双缓冲，彻底解决滚动、逐条刷新时的闪烁问题
	lv.SetDoubleBuffered(true)
	// 去掉老式3D凹陷边框，改为扁平风格
	lv.SetBorderStyle(types.BsNone)
	// 整行选中高亮
	lv.SetRowSelect(true)
	// 显示网格线
	lv.SetGridLines(true)
	// 统一全局字体，更符合现代Windows观感
	lv.Font().SetName("微软雅黑")
	lv.Font().SetSize(9)
}

// CreateContentPanel 创建带内边距的内容容器，避免控件贴死窗口边缘
func CreateContentPanel(parent vcl.IWinControl) *vcl.TPanel {
	panel := vcl.NewPanel(parent)
	panel.SetParent(parent)
	panel.SetAlign(types.AlClient)
	// 去除所有斜面凸起边框
	panel.SetBevelOuter(types.BvNone)
	panel.SetBevelInner(types.BvNone)
	// 5像素内边距，视觉更透气不拥挤
	panel.SetBorderWidth(5)
	// 继承父容器背景色，无违和感
	panel.SetColor(parent.Color())
	return panel
}
