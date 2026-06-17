package ui

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ying32/govcl/vcl"
	"github.com/ying32/govcl/vcl/types"

	"Scan/internal/process"
	"Scan/pkg/winapi"
)

// 进程列表列索引
const (
	colPID = iota
	colName
	colPPID
	colParentName
	colUser
	colMemory
	colStartTime
	colPath
	colFileCreate
	colFileModify
	colMD5
	colSignature
)

// DLL列表列索引
const (
	colDllPath = iota
	colDllMD5
	colDllSize
	colDllSign
)

// 消除未使用常量警告
var _ = colFileCreate
var _ = colFileModify
var _ = colMD5
var _ = colSignature
var _ = colDllPath
var _ = colDllMD5
var _ = colDllSize
var _ = colDllSign

// TProcessPage 进程信息页
type TProcessPage struct {
	Parent     *vcl.TTabSheet
	TopPanel   *vcl.TPanel
	BtnRefresh *vcl.TButton
	EditSearch *vcl.TEdit

	ProcessListView *vcl.TListView
	Splitter        *vcl.TSplitter
	DllListView     *vcl.TListView

	PopupMenu *vcl.TPopupMenu

	SelectedPID  int32
	procList     []process.ProcessInfo
	filteredList []process.ProcessInfo

	sortCol      int32
	sortAsc      bool
	lastClickCol int32
	colWidths    []int32
}

// NewProcessPage 初始化进程页
func NewProcessPage(parent *vcl.TTabSheet) *TProcessPage {
	p := &TProcessPage{
		Parent:  parent,
		sortCol: colPID,
		sortAsc: true,
	}
	p.buildUI()
	p.bindEvents()
	return p
}

// buildUI 构建界面布局
func (p *TProcessPage) buildUI() {
	// 1. 顶部操作栏：刷新按钮 + 搜索框
	p.TopPanel = vcl.NewPanel(p.Parent)
	p.TopPanel.SetParent(p.Parent)
	p.TopPanel.SetAlign(types.AlTop)
	p.TopPanel.SetHeight(38)
	p.TopPanel.SetBevelOuter(types.BvNone)

	p.BtnRefresh = vcl.NewButton(p.TopPanel)
	p.BtnRefresh.SetParent(p.TopPanel)
	p.BtnRefresh.SetLeft(10)
	p.BtnRefresh.SetTop(6)
	p.BtnRefresh.SetWidth(80)
	p.BtnRefresh.SetCaption("刷新")

	p.EditSearch = vcl.NewEdit(p.TopPanel)
	p.EditSearch.SetParent(p.TopPanel)
	p.EditSearch.SetLeft(100)
	p.EditSearch.SetTop(7)
	p.EditSearch.SetWidth(260)
	p.EditSearch.SetHint("输入关键词回车搜索，支持PID/进程名/路径等")
	p.EditSearch.SetText("")

	// 2. 底部DLL模块列表
	p.DllListView = vcl.NewListView(p.Parent)
	p.DllListView.SetParent(p.Parent)
	p.DllListView.SetAlign(types.AlBottom)
	p.DllListView.SetHeight(220)
	p.DllListView.SetViewStyle(types.VsReport)
	p.DllListView.SetGridLines(true)
	p.DllListView.SetRowSelect(true)
	p.DllListView.SetFullDrag(true)
	p.DllListView.SetReadOnly(true)

	// DLL列表列定义
	dllColumns := []struct {
		title string
		width int32
	}{
		{"模块路径", 500},
		{"MD5", 220},
		{"大小", 80},
		{"数字签名", 120},
	}
	for _, col := range dllColumns {
		c := p.DllListView.Columns().Add()
		c.SetCaption(col.title)
		c.SetWidth(col.width)
	}

	// 3. 可拖动分割条
	p.Splitter = vcl.NewSplitter(p.Parent)
	p.Splitter.SetParent(p.Parent)
	p.Splitter.SetAlign(types.AlBottom)
	p.Splitter.SetHeight(3)

	// 4. 主进程列表（占剩余空间）
	p.ProcessListView = vcl.NewListView(p.Parent)
	p.ProcessListView.SetParent(p.Parent)
	p.ProcessListView.SetAlign(types.AlClient)
	p.ProcessListView.SetViewStyle(types.VsReport)
	p.ProcessListView.SetGridLines(true)
	p.ProcessListView.SetRowSelect(true)
	p.ProcessListView.SetFullDrag(true)
	p.ProcessListView.SetReadOnly(true)
	p.ProcessListView.SetOnSelectItem(p.onSelectItem)

	// 进程列表列定义
	procColumns := []struct {
		title string
		width int32
	}{
		{"PID", 80},
		{"进程名", 200},
		{"父PID", 80},
		{"父进程名", 150},
		{"用户名", 180},
		{"内存占用", 120},
		{"进程启动时间", 150},
		{"可执行文件路径", 300},
		{"文件创建时间", 150},
		{"文件修改时间", 150},
		{"MD5", 220},
		{"签名信息", 120},
	}
	for _, col := range procColumns {
		c := p.ProcessListView.Columns().Add()
		c.SetCaption(col.title)
		c.SetWidth(col.width)
		p.colWidths = append(p.colWidths, col.width)
	}

	// 右键菜单
	p.PopupMenu = vcl.NewPopupMenu(p.Parent)
	p.buildPopupMenu()
	p.ProcessListView.SetPopupMenu(p.PopupMenu)
}

// bindEvents 绑定所有交互事件
func (p *TProcessPage) bindEvents() {
	// 刷新按钮
	p.BtnRefresh.SetOnClick(func(_ vcl.IObject) {
		p.Refresh()
	})

	// 表头点击排序
	p.ProcessListView.SetOnColumnClick(func(sender vcl.IObject, column *vcl.TListColumn) {
		colIdx := column.Index()
		if colIdx == p.sortCol {
			p.sortAsc = !p.sortAsc
		} else {
			p.sortCol = colIdx
			p.sortAsc = true
		}
		p.displayProcessList()
	})

	// 记录点击列索引，用于双击复制
	p.ProcessListView.SetOnMouseDown(func(sender vcl.IObject, button types.TMouseButton, shift types.TShiftState, x, y int32) {
		if button != types.MbLeft {
			return
		}
		var colIdx int32 = -1
		var totalWidth int32 = 0
		for i, w := range p.colWidths {
			totalWidth += w
			if x < totalWidth {
				colIdx = int32(i)
				break
			}
		}
		p.lastClickCol = colIdx
	})

	// 双击单元格复制内容
	p.ProcessListView.SetOnDblClick(func(sender vcl.IObject) {
		item := p.ProcessListView.Selected()
		if item == nil || p.lastClickCol < 0 {
			return
		}
		var text string
		if p.lastClickCol == 0 {
			text = item.Caption()
		} else {
			subIdx := p.lastClickCol - 1
			if subIdx < item.SubItems().Count() {
				text = item.SubItems().Strings(subIdx)
			}
		}
		if text != "" {
			vcl.Clipboard.SetAsText(text)
		}
	})

	// 搜索框回车过滤
	p.EditSearch.SetOnKeyPress(func(sender vcl.IObject, key *types.Char) {
		if *key == 13 {
			p.filterProcessList()
		}
	})

	// 全局Ctrl+F聚焦搜索框
	MainForm.SetKeyPreview(true)
	MainForm.SetOnKeyDown(func(sender vcl.IObject, key *types.Word, shift types.TShiftState) {
		if *key == 70 && (shift&types.SsCtrl) != 0 {
			p.EditSearch.SetFocus()
			p.EditSearch.SelectAll()
		}
	})
}

// buildPopupMenu 右键菜单（修复：绑定正确的终止进程方法 onKillProcessClick）
func (p *TProcessPage) buildPopupMenu() {
	miCopyAll := vcl.NewMenuItem(p.PopupMenu)
	miCopyAll.SetCaption("复制进程全部信息")
	miCopyAll.SetOnClick(p.copyProcessInfo)
	p.PopupMenu.Items().Add(miCopyAll)

	miSep1 := vcl.NewMenuItem(p.PopupMenu)
	miSep1.SetCaption("-")
	p.PopupMenu.Items().Add(miSep1)

	miCopyPID := vcl.NewMenuItem(p.PopupMenu)
	miCopyPID.SetCaption("复制PID")
	miCopyPID.SetOnClick(func(_ vcl.IObject) {
		if p.SelectedPID != 0 {
			vcl.Clipboard.SetAsText(strconv.Itoa(int(p.SelectedPID)))
		}
	})
	p.PopupMenu.Items().Add(miCopyPID)

	miCopyName := vcl.NewMenuItem(p.PopupMenu)
	miCopyName.SetCaption("复制进程名")
	miCopyName.SetOnClick(func(_ vcl.IObject) {
		item := p.ProcessListView.Selected()
		if item != nil {
			vcl.Clipboard.SetAsText(item.SubItems().Strings(0))
		}
	})
	p.PopupMenu.Items().Add(miCopyName)

	miCopyPath := vcl.NewMenuItem(p.PopupMenu)
	miCopyPath.SetCaption("复制进程路径")
	miCopyPath.SetOnClick(func(_ vcl.IObject) {
		item := p.ProcessListView.Selected()
		if item != nil {
			vcl.Clipboard.SetAsText(item.SubItems().Strings(6))
		}
	})
	p.PopupMenu.Items().Add(miCopyPath)

	miSep2 := vcl.NewMenuItem(p.PopupMenu)
	miSep2.SetCaption("-")
	p.PopupMenu.Items().Add(miSep2)

	miOpenPath := vcl.NewMenuItem(p.PopupMenu)
	miOpenPath.SetCaption("在资源管理器中打开")
	miOpenPath.SetOnClick(p.openFileLocation)
	p.PopupMenu.Items().Add(miOpenPath)

	miSep3 := vcl.NewMenuItem(p.PopupMenu)
	miSep3.SetCaption("-")
	p.PopupMenu.Items().Add(miSep3)

	miKill := vcl.NewMenuItem(p.PopupMenu)
	miKill.SetCaption("终止进程")
	// 修复：绑定已存在的 onKillProcessClick，不再使用不存在的 killProcess
	miKill.SetOnClick(p.onKillProcessClick)
	p.PopupMenu.Items().Add(miKill)
}

// getSelectedPID 获取当前选中进程PID（修复：之前缺失该方法定义）
func (p *TProcessPage) getSelectedPID() int32 {
	return p.SelectedPID
}

// Refresh 重新加载全部进程
func (p *TProcessPage) Refresh() {
	MainForm.ShowLoading("正在加载进程列表...")
	p.DllListView.Items().Clear()

	go func() {
		procList, err := process.GetAllProcesses()
		vcl.ThreadSync(func() {
			defer MainForm.HideLoading("就绪")
			if err != nil {
				vcl.ShowMessage("获取进程列表失败: " + err.Error())
				return
			}
			p.procList = procList
			p.filterProcessList()
		})
	}()
}

// filterProcessList 全局搜索过滤
func (p *TProcessPage) filterProcessList() {
	keyword := strings.ToLower(p.EditSearch.Text())
	if keyword == "" {
		p.filteredList = p.procList
	} else {
		p.filteredList = nil
		for _, proc := range p.procList {
			pidStr := strconv.Itoa(int(proc.PID))
			ppidStr := strconv.Itoa(int(proc.PPID))
			memStr := strconv.FormatFloat(float64(proc.Memory)/1024/1024, 'f', 2, 64) + " MB"
			startTimeStr := "-"
			if proc.CreateTime > 0 {
				startTimeStr = time.UnixMilli(proc.CreateTime).Format("2006-01-02 15:04:05")
			}

			if strings.Contains(strings.ToLower(pidStr), keyword) ||
				strings.Contains(strings.ToLower(proc.Name), keyword) ||
				strings.Contains(strings.ToLower(ppidStr), keyword) ||
				strings.Contains(strings.ToLower(proc.ParentName), keyword) ||
				strings.Contains(strings.ToLower(proc.User), keyword) ||
				strings.Contains(strings.ToLower(memStr), keyword) ||
				strings.Contains(strings.ToLower(startTimeStr), keyword) ||
				strings.Contains(strings.ToLower(proc.Path), keyword) {
				p.filteredList = append(p.filteredList, proc)
			}
		}
	}
	p.displayProcessList()
}

// displayProcessList 渲染进程列表
func (p *TProcessPage) displayProcessList() {
	p.sortProcessList()
	p.ProcessListView.Items().Clear()

	for _, proc := range p.filteredList {
		item := p.ProcessListView.Items().Add()
		item.SetCaption(strconv.Itoa(int(proc.PID)))
		item.SubItems().Add(proc.Name)
		item.SubItems().Add(strconv.Itoa(int(proc.PPID)))
		item.SubItems().Add(proc.ParentName)
		item.SubItems().Add(proc.User)
		item.SubItems().Add(strconv.FormatFloat(float64(proc.Memory)/1024/1024, 'f', 2, 64) + " MB")

		startTime := "-"
		if proc.CreateTime > 0 {
			startTime = time.UnixMilli(proc.CreateTime).Format("2006-01-02 15:04:05")
		}
		item.SubItems().Add(startTime)
		item.SubItems().Add(proc.Path)
		item.SubItems().Add("获取中...")
		item.SubItems().Add("获取中...")
		item.SubItems().Add("计算中...")
		item.SubItems().Add("验证中...")
	}

	go p.batchUpdateProcessDetails()
}

// sortProcessList 排序逻辑
func (p *TProcessPage) sortProcessList() {
	sort.Slice(p.filteredList, func(i, j int) bool {
		a, b := p.filteredList[i], p.filteredList[j]
		switch p.sortCol {
		case colPID:
			if p.sortAsc {
				return a.PID < b.PID
			}
			return a.PID > b.PID
		case colName:
			if p.sortAsc {
				return strings.ToLower(a.Name) < strings.ToLower(b.Name)
			}
			return strings.ToLower(a.Name) > strings.ToLower(b.Name)
		case colPPID:
			if p.sortAsc {
				return a.PPID < b.PPID
			}
			return a.PPID > b.PPID
		case colParentName:
			if p.sortAsc {
				return strings.ToLower(a.ParentName) < strings.ToLower(b.ParentName)
			}
			return strings.ToLower(a.ParentName) > strings.ToLower(b.ParentName)
		case colUser:
			if p.sortAsc {
				return strings.ToLower(a.User) < strings.ToLower(b.User)
			}
			return strings.ToLower(a.User) > strings.ToLower(b.User)
		case colMemory:
			if p.sortAsc {
				return a.Memory < b.Memory
			}
			return a.Memory > b.Memory
		case colStartTime:
			if p.sortAsc {
				return a.CreateTime < b.CreateTime
			}
			return a.CreateTime > b.CreateTime
		case colPath:
			if p.sortAsc {
				return strings.ToLower(a.Path) < strings.ToLower(b.Path)
			}
			return strings.ToLower(a.Path) > strings.ToLower(b.Path)
		default:
			return false
		}
	})
}

// batchUpdateProcessDetails 异步补全进程的文件时间、MD5、签名
func (p *TProcessPage) batchUpdateProcessDetails() {
	timeFormat := "2006-01-02 15:04:05"
	for i, proc := range p.filteredList {
		idx := int32(i)

		ct, mt, err := winapi.GetFileTimes(proc.Path)
		vcl.ThreadSync(func() {
			if idx < p.ProcessListView.Items().Count() {
				item := p.ProcessListView.Items().Item(idx)
				if err != nil || ct.IsZero() {
					item.SubItems().SetStrings(7, "-")
					item.SubItems().SetStrings(8, "-")
				} else {
					item.SubItems().SetStrings(7, ct.Format(timeFormat))
					item.SubItems().SetStrings(8, mt.Format(timeFormat))
				}
			}
		})

		md5Str, _ := process.GetFileMD5(proc.Path)
		vcl.ThreadSync(func() {
			if idx < p.ProcessListView.Items().Count() {
				item := p.ProcessListView.Items().Item(idx)
				item.SubItems().SetStrings(9, md5Str)
			}
		})

		sign := winapi.VerifyFileSignature(proc.Path)
		vcl.ThreadSync(func() {
			if idx < p.ProcessListView.Items().Count() {
				item := p.ProcessListView.Items().Item(idx)
				item.SubItems().SetStrings(10, sign)
			}
		})
	}
}

// onSelectItem 选中进程自动加载下方DLL列表
func (p *TProcessPage) onSelectItem(_ vcl.IObject, item *vcl.TListItem, selected bool) {
	if !selected || item == nil {
		return
	}
	pid, _ := strconv.Atoi(item.Caption())
	p.SelectedPID = int32(pid)
	go p.loadDllModules(int32(pid))
}

// loadDllModules 加载指定进程的DLL模块
func (p *TProcessPage) loadDllModules(pid int32) {
	modules, err := process.GetProcessModules(pid)
	vcl.ThreadSync(func() {
		p.DllListView.Items().Clear()
		if err != nil {
			return
		}

		for _, mod := range modules {
			item := p.DllListView.Items().Add()
			item.SetCaption(mod.Path)
			item.SubItems().Add("计算中...")
			item.SubItems().Add(strconv.Itoa(int(mod.Size/1024)) + " KB")
			item.SubItems().Add("验证中...")
		}

		go p.batchUpdateDllDetails(modules)
	})
}

// batchUpdateDllDetails 异步补全DLL的MD5和签名
func (p *TProcessPage) batchUpdateDllDetails(modules []process.ModuleInfo) {
	for i, mod := range modules {
		idx := int32(i)

		md5Str, _ := process.GetFileMD5(mod.Path)
		vcl.ThreadSync(func() {
			if idx < p.DllListView.Items().Count() {
				item := p.DllListView.Items().Item(idx)
				item.SubItems().SetStrings(0, md5Str)
			}
		})

		sign := winapi.VerifyFileSignature(mod.Path)
		vcl.ThreadSync(func() {
			if idx < p.DllListView.Items().Count() {
				item := p.DllListView.Items().Item(idx)
				item.SubItems().SetStrings(2, sign)
			}
		})
	}
}

// copyProcessInfo 复制全量进程信息
func (p *TProcessPage) copyProcessInfo(_ vcl.IObject) {
	if p.SelectedPID == 0 {
		vcl.ShowMessage("请先选中一个进程")
		return
	}
	item := p.ProcessListView.Selected()
	if item == nil {
		return
	}

	content := "PID: " + item.Caption() + "\r\n" +
		"进程名: " + item.SubItems().Strings(0) + "\r\n" +
		"父PID: " + item.SubItems().Strings(1) + "\r\n" +
		"父进程名: " + item.SubItems().Strings(2) + "\r\n" +
		"用户名: " + item.SubItems().Strings(3) + "\r\n" +
		"内存占用: " + item.SubItems().Strings(4) + "\r\n" +
		"进程启动时间: " + item.SubItems().Strings(5) + "\r\n" +
		"可执行文件路径: " + item.SubItems().Strings(6) + "\r\n" +
		"文件创建时间: " + item.SubItems().Strings(7) + "\r\n" +
		"文件修改时间: " + item.SubItems().Strings(8) + "\r\n" +
		"MD5: " + item.SubItems().Strings(9) + "\r\n" +
		"签名信息: " + item.SubItems().Strings(10)

	vcl.Clipboard.SetAsText(content)
	vcl.ShowMessage("进程信息已复制到剪贴板")
}

// openFileLocation 打开文件所在目录
func (p *TProcessPage) openFileLocation(_ vcl.IObject) {
	if p.SelectedPID == 0 {
		vcl.ShowMessage("请先选中一个进程")
		return
	}
	item := p.ProcessListView.Selected()
	if item == nil {
		return
	}
	filePath := item.SubItems().Strings(6)
	if filePath == "" || filePath == "-" {
		vcl.ShowMessage("无法获取进程文件路径")
		return
	}
	err := winapi.OpenFileLocation(filePath)
	if err != nil {
		vcl.ShowMessage("打开失败: " + err.Error())
	}
}

// onKillProcessClick 终止进程右键菜单点击事件
func (p *TProcessPage) onKillProcessClick(_ vcl.IObject) {
	selectedPid := p.getSelectedPID()
	if selectedPid == 0 {
		vcl.ShowMessage("请先选中一个进程")
		return
	}

	// 修复：用 MbYes + MbNo 组合代替不存在的 MbYesNo
	res := vcl.MessageDlg(
		fmt.Sprintf("确定要强制终止进程 PID:%d 吗？", selectedPid),
		types.MtConfirmation,
		types.MbYes|types.MbNo,
		0,
	)
	if res != types.MrYes {
		return
	}

	// 执行强制终止
	err := process.TerminateProcess(selectedPid)
	if err != nil {
		vcl.ShowMessage(fmt.Sprintf("终止失败：%v\n请尝试以管理员身份运行程序", err))
		return
	}

	// 终止成功，自动刷新列表
	p.Refresh()
}
