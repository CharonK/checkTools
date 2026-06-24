//go:build windows
// +build windows

package network

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
)

// NetMatchResult IP匹配进程结果
type NetMatchResult struct {
	PID     int32
	Name    string
	ExePath string
}

// PersistInfo 持久化/自启动项信息
type PersistInfo struct {
	Type    string
	Path    string
	Detail  string
	Suspect bool
}

// execHidden 封装：执行命令并隐藏控制台窗口，彻底解决闪黑框问题
func execHidden(name string, arg ...string) *exec.Cmd {
	cmd := exec.Command(name, arg...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow: true, // 核心：隐藏子进程控制台窗口
	}
	return cmd
}

func SearchIPByAddr(ctx context.Context, targetIP string) ([]NetMatchResult, error) {
	conns, err := net.ConnectionsWithContext(ctx, "all")
	if err != nil {
		return nil, fmt.Errorf("枚举网络连接失败: %w", err)
	}

	matchPIDMap := make(map[int32]struct{})
	for _, conn := range conns {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("scan canceled")
		default:
		}
		var checkIP string
		if strings.EqualFold(conn.Laddr.IP, targetIP) {
			checkIP = conn.Laddr.IP
		} else if strings.EqualFold(conn.Raddr.IP, targetIP) {
			checkIP = conn.Raddr.IP
		}
		if checkIP == "" {
			continue
		}
		if conn.Pid > 0 {
			matchPIDMap[int32(conn.Pid)] = struct{}{}
		}
	}

	var resList []NetMatchResult
	for pid := range matchPIDMap {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("scan canceled")
		default:
		}
		proc, err := process.NewProcess(pid)
		if err != nil {
			continue
		}
		name, _ := proc.Name()
		exePath, _ := proc.Exe()
		resList = append(resList, NetMatchResult{
			PID:     pid,
			Name:    name,
			ExePath: exePath,
		})
	}
	return resList, nil
}

// CheckPersistByExePath 检测自启动项，全程无控制台弹窗
func CheckPersistByExePath(exePath string) ([]PersistInfo, error) {
	var persistList []PersistInfo
	exeLower := strings.ToLower(exePath)

	// 1. 注册表Run/RunOnce自启动项
	regPaths := []string{
		`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`,
		`HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`,
		`HKLM\Software\Microsoft\Windows\CurrentVersion\Run`,
		`HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`,
	}
	for _, regPath := range regPaths {
		cmd := execHidden("reg", "query", regPath)
		out, err := cmd.CombinedOutput()
		if err != nil {
			continue
		}
		outStr := strings.ToLower(string(out))
		if strings.Contains(outStr, exeLower) {
			persistList = append(persistList, PersistInfo{
				Type:    "注册表启动项",
				Path:    regPath,
				Detail:  "程序路径写入注册表开机自启",
				Suspect: true,
			})
		}
	}

	// 2. Windows系统服务
	cmdSvc := execHidden("sc", "query", "state= all")
	svcOut, err := cmdSvc.CombinedOutput()
	if err == nil {
		svcStr := strings.ToLower(string(svcOut))
		if strings.Contains(svcStr, exeLower) {
			persistList = append(persistList, PersistInfo{
				Type:    "系统服务",
				Path:    "系统服务列表",
				Detail:  "程序注册为后台系统服务",
				Suspect: true,
			})
		}
	}

	// 3. 开机启动文件夹
	userStartup := filepath.Join(os.Getenv("APPDATA"), `Microsoft\Windows\Start Menu\Programs\Startup`)
	globalStartup := filepath.Join(os.Getenv("PROGRAMDATA"), `Microsoft\Windows\Start Menu\Programs\StartUp`)
	persistList = append(persistList, PersistInfo{
		Type:    "用户启动文件夹",
		Path:    userStartup,
		Detail:  "请手动查看目录内快捷方式",
		Suspect: false,
	})
	persistList = append(persistList, PersistInfo{
		Type:    "全局启动文件夹",
		Path:    globalStartup,
		Detail:  "请手动查看目录内快捷方式",
		Suspect: false,
	})

	// 4. 计划任务
	cmdTask := execHidden("schtasks", "/query", "/v", "/fo", "csv")
	taskOut, err := cmdTask.CombinedOutput()
	if err == nil {
		taskStr := strings.ToLower(string(taskOut))
		if strings.Contains(taskStr, exeLower) {
			persistList = append(persistList, PersistInfo{
				Type:    "计划任务",
				Path:    "系统任务计划程序",
				Detail:  "程序添加定时开机任务",
				Suspect: true,
			})
		}
	}

	return persistList, nil
}
