//go:build windows

package process

import (
	"crypto/md5"
	"encoding/hex"
	"io"
	"os"

	"github.com/shirou/gopsutil/v3/process"
	"golang.org/x/sys/windows"
)

// ProcessInfo 进程信息结构体
type ProcessInfo struct {
	PID        int32
	PPID       int32
	Name       string
	ParentName string
	Path       string
	User       string
	Memory     uint64
	CreateTime int64 // 毫秒级时间戳
}

// TerminateProcess 强制终止指定PID的进程
func TerminateProcess(pid int32) error {
	// 申请终止权限打开进程句柄
	handle, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)

	// 强制终止进程，退出码为0
	return windows.TerminateProcess(handle, 0)
}

// GetAllProcesses 获取全量有效进程列表（自动过滤无名称的无效进程）
func GetAllProcesses() ([]ProcessInfo, error) {
	procs, err := process.Processes()
	if err != nil {
		return nil, err
	}

	// 预构建PID→进程名映射，用于填充父进程名称
	pidNameMap := make(map[int32]string)
	for _, p := range procs {
		name, _ := p.Name()
		if name != "" {
			pidNameMap[p.Pid] = name
		}
	}

	var result []ProcessInfo
	for _, p := range procs {
		name, _ := p.Name()
		// 核心：过滤进程名为空的无效条目
		if name == "" {
			continue
		}

		ppid, _ := p.Ppid()
		path, _ := p.Exe()
		user, _ := p.Username()
		createTime, _ := p.CreateTime()

		var memUsage uint64
		if mem, memErr := p.MemoryInfo(); memErr == nil && mem != nil {
			memUsage = mem.RSS
		}

		// 填充父进程名，找不到则显示-
		parentName := pidNameMap[ppid]
		if parentName == "" {
			parentName = "-"
		}

		result = append(result, ProcessInfo{
			PID:        p.Pid,
			PPID:       ppid,
			Name:       name,
			ParentName: parentName,
			Path:       path,
			User:       user,
			Memory:     memUsage,
			CreateTime: createTime,
		})
	}
	return result, nil
}

// GetFileMD5 计算可执行文件的MD5哈希
func GetFileMD5(filePath string) (string, error) {
	if filePath == "" {
		return "-", nil
	}
	f, err := os.Open(filePath)
	if err != nil {
		return "-", err
	}
	defer f.Close()

	h := md5.New()
	if _, err := io.Copy(h, f); err != nil {
		return "-", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// KillProcess 终止指定进程
func KillProcess(pid int32) error {
	p, err := process.NewProcess(pid)
	if err != nil {
		return err
	}
	return p.Kill()
}
