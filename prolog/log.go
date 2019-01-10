package prolog

import "github.com/astaxie/beego/logs"

var loger *logs.BeeLogger

func initlog() {
	loger = logs.NewLogger(0)
	loger.SetLevel(logs.LevelInfo)
}

func init() {
	initlog()
}

// SetLevel 设置日志等级
func SetLevel(level int) {
	loger.SetLevel(level)
}

// DeBugPrintln DeBug 输出
func DeBugPrintln(info ...interface{}) {
	loger.Debug("[logpro]", info...)
}
