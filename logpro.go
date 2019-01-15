package main

import (
	"fmt"
	"log"
	"logpro/prolog"
	"os"
	"path/filepath"
	"time"

	"github.com/hexiu/utils/timepro"

	"github.com/astaxie/beego/logs"
	cli "gopkg.in/urfave/cli.v2"
)

func initVersion(app *cli.App) {
	app.Version = "1.0.0"
}

func main() {
	fmt.Println("log pro! mail: jaxiuhe@tencent.com.")
	app := cli.NewApp()
	initVersion(app)
	app.Name = "logpro"

	app.Usage = "logpro --path /path/to/directory ."
	initCommand(app)
	app.Run(os.Args)
}

func initCommand(app *cli.App) {
	access := initAccess()
	app.Commands = append(app.Commands, access)
	ups := initUpstream()
	app.Commands = append(app.Commands, ups)
}

func initAccess() (access cli.Command) {
	access.Name = "access"
	access.Usage = "logpro access args. Get help : logpro access -h / --help or logpro help access."
	access.Action = commAction
	initAccessFlag(&access)
	return access
}

func initUpstream() (ups cli.Command) {
	ups.Name = "upstream"
	ups.Usage = "logpro upstream args. Get help : logpro upstream -h / --help or logpro help upstream."
	ups.Action = commUAction
	initUpstreamFlag(&ups)
	return ups
}

func initAccessFlag(app *cli.Command) {
	logpath := cli.StringFlag{
		Name:  "path,p",
		Usage: "/path/to/directory",
		Value: "/usr/local/nws/log",
	}
	logdomain := cli.StringFlag{
		Name:  "domain,d",
		Usage: "doamin , eg : www.qq.com.",
		Value: "",
	}
	logcode := cli.StringFlag{
		Name:  "retcode,r",
		Usage: "retcode, eg : 200,302,404.",
		Value: "404",
	}
	logdirt := cli.BoolFlag{
		Name:  "dirt,l",
		Usage: "dirt : true,false ,default is false.",
	}
	logstime := cli.StringFlag{
		Name:  "stime,s",
		Usage: "stime, eg : 2019-01-07 13:14:35",
	}
	logetime := cli.StringFlag{
		Name:  "etime,e",
		Usage: "etime, eg : 2019-01-07 13:14:35",
		Value: time.Now().String()[:16],
	}
	timegap := cli.Uint64Flag{
		Name:  "timegap,t",
		Usage: "timegap , eg: 10 , unit is second",
		Value: 900,
	}
	logsize := cli.Uint64Flag{
		Name:  "datasize,z",
		Usage: "datasize is get log size, eg: 1000. default is 1000.",
		Value: 1000,
	}
	logdebug := cli.BoolFlag{
		Name:  "debug",
		Usage: "debug code",
	}
	logformat := cli.BoolFlag{
		Name:  "format,f",
		Usage: "format is true/false, result is json or text.",
	}
	logout := cli.UintFlag{
		Name:  "outline,ol",
		Value: 10,
		Usage: "outline, out lines.",
	}
	app.Flags = append(app.Flags, logpath)
	app.Flags = append(app.Flags, logdomain)
	app.Flags = append(app.Flags, logcode)
	app.Flags = append(app.Flags, logdirt)
	app.Flags = append(app.Flags, logstime)
	app.Flags = append(app.Flags, logetime)
	app.Flags = append(app.Flags, timegap)
	app.Flags = append(app.Flags, logsize)
	app.Flags = append(app.Flags, logdebug)
	app.Flags = append(app.Flags, logformat)
	app.Flags = append(app.Flags, logout)
	return
}

func commAction(c *cli.Context) {
	if c.Bool("debug") {
		prolog.SetLevel(logs.LevelDebug)
	}
	path := c.String("path")
	if path[0] != '/' {
		basepath, err := filepath.Abs(".")
		if err != nil {
			panic(err)
		}
		path = filepath.Join(basepath, path)
	}
	files, err := prolog.ListDirFile(path, "access")
	if err != nil {
		log.Println(err)
	}
	var stime time.Time
	var etime time.Time
	var datasize int64 = 5
	size := c.Uint64("datasize")
	if size != 0 {
		datasize = int64(size)
	}
	if c.String("etime") == "" {
		etime = time.Now()
		timegap := 15 * 60
		stime = etime.Add(-time.Duration(timegap) * time.Second)
	} else {
		if c.String("stime") == "" {
			timegap := c.Uint64("timegap")
			if timegap < 0 && timegap >= 60*50 {
				log.Fatalln("not supported!, timegap should in 1 ~ 60*50!")
			}
			etime = timepro.StringToTime(c.String("etime"))
			stime = etime.Add(-time.Duration(timegap) * time.Second)
		} else {
			stime = timepro.StringToTime(c.String("stime"))
			etime = timepro.StringToTime(c.String("etime"))
		}
	}
	apro := prolog.NewAccessPro(stime, etime, datasize)
	apro.ProLogFile(files, c.String("domain"))
	apro.Filter(c.String("retcode"), c.String("domain"), c.Bool("dirt"), c.Bool("format"), int(c.Uint("outline")), c.String("sort"))
	fmt.Println("参数是: ")
	fmt.Println("处理时间区间: ", stime.String()[:16], "~", etime.String()[:16], "错误码: ", c.String("retcode"), c.String("domain"))
}

func initUpstreamFlag(app *cli.Command) {
	logpath := cli.StringFlag{
		Name:  "path,p",
		Usage: "/path/to/directory",
		Value: "/usr/local/nws/log",
	}
	logdomain := cli.StringFlag{
		Name:  "domain,d",
		Usage: "doamin , eg : www.qq.com.",
		Value: "",
	}
	logcode := cli.StringFlag{
		Name:  "retcode,r",
		Usage: "retcode, eg : 200,302,404.",
		Value: "0",
	}
	logdirt := cli.BoolFlag{
		Name:  "dirt,l",
		Usage: "dirt : true,false ,default is false.",
	}
	logstime := cli.StringFlag{
		Name:  "stime,s",
		Usage: "stime, eg : 2019-01-07 13:14:35",
	}
	logetime := cli.StringFlag{
		Name:  "etime,e",
		Usage: "etime, eg : 2019-01-07 13:14:35",
		Value: time.Now().String()[:16],
	}
	timegap := cli.Uint64Flag{
		Name:  "timegap,t",
		Usage: "timegap , eg: 10 , unit is second",
		Value: 900,
	}
	logsize := cli.Uint64Flag{
		Name:  "datasize,z",
		Usage: "datasize is get log size, eg: 1000. default is 1000.",
		Value: 1000,
	}
	logdebug := cli.BoolFlag{
		Name:  "debug",
		Usage: "debug code",
	}
	logformat := cli.BoolFlag{
		Name:  "format,f",
		Usage: "format is true/false, result is json or text.",
	}
	logout := cli.UintFlag{
		Name:  "outline,ol",
		Value: 10,
		Usage: "outline, out lines.",
	}
	logsort := cli.StringFlag{
		Name:  "sort",
		Value: "matchnum",
		Usage: "Enter Sort method : flux or matchnum.",
	}
	app.Flags = append(app.Flags, logpath)
	app.Flags = append(app.Flags, logdomain)
	app.Flags = append(app.Flags, logcode)
	app.Flags = append(app.Flags, logdirt)
	app.Flags = append(app.Flags, logstime)
	app.Flags = append(app.Flags, logetime)
	app.Flags = append(app.Flags, timegap)
	app.Flags = append(app.Flags, logsize)
	app.Flags = append(app.Flags, logdebug)
	app.Flags = append(app.Flags, logformat)
	app.Flags = append(app.Flags, logout)
	app.Flags = append(app.Flags, logsort)
	return
}

func commUAction(c *cli.Context) {
	if c.Bool("debug") {
		prolog.SetLevel(logs.LevelDebug)
	}
	path := c.String("path")
	if path[0] != '/' {
		basepath, err := filepath.Abs(".")
		if err != nil {
			panic(err)
		}
		path = filepath.Join(basepath, path)
	}
	files, err := prolog.ListDirFile(path, "[hy_access,upstream]")
	if err != nil {
		log.Println(err)
	}
	var stime time.Time
	var etime time.Time
	var datasize int64 = 5
	size := c.Uint64("datasize")
	if size != 0 {
		datasize = int64(size)
	}
	if c.String("etime") == "" {
		etime = time.Now()
		timegap := 15 * 60
		stime = etime.Add(-time.Duration(timegap) * time.Second)
	} else {
		if c.String("stime") == "" {
			timegap := c.Uint64("timegap")
			if timegap < 0 && timegap >= 60*50 {
				log.Fatalln("not supported!, timegap should in 1 ~ 60*50!")
			}
			etime = timepro.StringToTime(c.String("etime"))
			stime = etime.Add(-time.Duration(timegap) * time.Second)
		} else {
			stime = timepro.StringToTime(c.String("stime"))
			etime = timepro.StringToTime(c.String("etime"))
		}
	}
	apro := prolog.NewUpstreamPro(stime, etime, datasize)
	apro.ProLogFile(files, c.String("domain"))
	apro.Filter(c.String("retcode"), c.String("domain"), c.Bool("dirt"), c.Bool("format"), int(c.Uint("outline")), c.String("sort"))
	fmt.Println("参数是: ")
	fmt.Println("处理时间区间: ", stime.String()[:16], "~", etime.String()[:16], "错误码: ", c.String("retcode"), c.String("domain"))
}
