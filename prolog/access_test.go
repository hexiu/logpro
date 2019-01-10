package prolog

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/hexiu/utils/timepro"
)

// Test_ReadFileFirstLine 读取日志第一行测试
func Test_ReadFileFirstLine(t *testing.T) {
	path, _ := filepath.Abs(".")
	root := filepath.Join(path, "..", "logs", "access-default.log")
	fmt.Println(root)
	alog := ReadFileFirstLine(root)
	fmt.Println(root, alog)
	t.Log(alog, root)
}

// Test_ReadFileLastLine 读取日志第一行测试
func Test_ReadFileLastLine(t *testing.T) {
	path, _ := filepath.Abs(".")
	root := filepath.Join(path, "..", "logs", "access-default.log")
	fmt.Println(root)
	alog := ReadFileLastLine(root)
	fmt.Println(root, alog)
	t.Log(alog, root)
}

// Test_AccessPro 测试accesspro
func Test_AccessPro(t *testing.T) {
	wtime := "2019-01-02 19:45:16"
	etime := timepro.StringToTime(wtime)
	stime := etime.Add(-20 * time.Second)
	apro := NewAccessPro(stime, etime,1000)
	path, _ := filepath.Abs(".")
	root := filepath.Join(path, "..", "logs", "access-default.log")
	files := []string{root}
	apro.ProLogFile(files, "")
	t.Log(files, len(apro.LogInfo))
}
