package logutil

import (
	"fmt"
	"os"
	"sync"
	"time"
)

var (
	logFile *os.File
	mu      sync.Mutex
)

// Init 初始化调试日志文件，程序启动调用一次
func Init(logPath string) error {
	mu.Lock()
	defer mu.Unlock()
	var err error
	logFile, err = os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	// 写入UTF-8 BOM，记事本打开中文不会乱码
	_, _ = logFile.Write([]byte{0xEF, 0xBB, 0xBF})
	return nil
}

// Debug 输出调试信息，自动加时间戳，线程安全
func Debug(format string, args ...interface{}) {
	mu.Lock()
	defer mu.Unlock()
	if logFile == nil {
		return
	}
	now := time.Now().Format("2006-01-02 15:04:05")

	// 合并参数，避免可变参数混合传参的编译问题
	fullFormat := fmt.Sprintf("[%s] %s\r\n", now, format)
	msg := fmt.Sprintf(fullFormat, args...)

	_, _ = logFile.WriteString(msg)
	// 同步输出到控制台
	fmt.Print(msg)
}

// Close 程序退出关闭日志句柄
func Close() {
	mu.Lock()
	defer mu.Unlock()
	if logFile != nil {
		_ = logFile.Sync()
		_ = logFile.Close()
		logFile = nil
	}
}
