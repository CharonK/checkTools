package ui

import (
	"github.com/ying32/govcl/vcl"
	"github.com/ying32/govcl/vcl/types"
)

// 全局空图片列表：用于统一撑高 ListView 行高，无需自绘
var listRowHeightImgList *vcl.TImageList

func init() {
	listRowHeightImgList = vcl.NewImageList(nil)
	listRowHeightImgList.SetHeight(22) // 列表行高22像素，舒适不拥挤
	listRowHeightImgList.SetWidth(1)
}

// BeautifyMainPageControl 美化窗口顶层主标签栏
func BeautifyMainPageControl(pc *vcl.TPageControl) {
	pc.SetDoubleBuffered(true)
	pc.Font().SetName("微软雅黑")
	pc.Font().SetSize(10) // 主标签字号稍大，层级分明
	pc.SetTabHeight(26)   // 标签高度舒展不拥挤
}

// BeautifySubPageControl 美化页面内的二级标签栏
func BeautifySubPageControl(pc *vcl.TPageControl) {
	pc.SetDoubleBuffered(true)
	pc.Font().SetName("微软雅黑")
	pc.Font().SetSize(9)
	pc.SetTabHeight(24)
}

// BeautifyListView 统一美化所有列表控件
func BeautifyListView(lv *vcl.TListView) {
	// 双缓冲：彻底解决逐条刷新、滚动时的闪烁问题
	lv.SetDoubleBuffered(true)
	// 去3D边框，扁平风格
	lv.SetBorderStyle(types.BsNone)
	// 整行选中高亮
	lv.SetRowSelect(true)
	// 显示网格线
	lv.SetGridLines(true)
	// 统一字体
	lv.Font().SetName("微软雅黑")
	lv.Font().SetSize(9)
	// 优化行高，通过空图片列表实现
	lv.SetSmallImages(listRowHeightImgList)
	// 禁止点击表头排序，避免误操作打乱顺序
	lv.SetColumnClick(false)
}

// CreateContentPanel 创建带内边距的内容容器，避免控件贴死窗口边缘
func CreateContentPanel(parent vcl.IWinControl) *vcl.TPanel {
	panel := vcl.NewPanel(parent)
	panel.SetParent(parent)
	panel.SetAlign(types.AlClient)
	// 去除所有斜面凸起边框
	panel.SetBevelOuter(types.BvNone)
	panel.SetBevelInner(types.BvNone)
	// 8px 内边距，视觉更透气
	panel.SetBorderWidth(8)
	// 继承父容器背景色，无违和感
	panel.SetColor(parent.Color())
	return panel
}

// BeautifyStatusBar 美化底部状态栏
func BeautifyStatusBar(sb *vcl.TStatusBar) {
	sb.SetHeight(28) // 适中高度，不挤也不浪费空间
	sb.Font().SetName("微软雅黑")
	sb.Font().SetSize(9)
}
