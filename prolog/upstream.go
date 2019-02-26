package prolog

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"standAlone/utils/logger"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hexiu/utils/timepro"
)

// UpstreamLog 访问日志处理结构
type UpstreamLog struct {
	UpstreamTimeThreadNum string
	ClientIP              string
	HTTPMethod            string
	URL                   string
	FwdOriginalDomain     string
	Range                 string
	XForwardedFor         string
	Location              string
	Mtime                 string
	BackCode              string
	HeadSize              string
	PostSize              string
	BackeHeaderSize       string
	BackContentSize       string // header + body
	UpstreamIP            string
	ConnectFlag           string
	LogRatio              string
	UpstreamTimer         string
	ErrCode               string
	OriginalDomain        string // 原来的域名
	UUID                  string
	LogMarkKey            string
	Line                  []byte
}

// NewUpstreamLog 创建一个新的访问日志结构
func NewUpstreamLog(line string) *UpstreamLog {
	linelist := strings.Split(line, "\001")
	if len(linelist) != 22 {
		DeBugPrintln(len(linelist), len(line), line, []byte(line))
		return nil
	}
	return &UpstreamLog{
		UpstreamTimeThreadNum: linelist[0],
		ClientIP:              linelist[1],
		HTTPMethod:            linelist[2],
		URL:                   linelist[3],
		FwdOriginalDomain:     linelist[4],
		Range:                 linelist[5],
		XForwardedFor:         linelist[6],
		Location:              linelist[7],
		Mtime:                 linelist[8],
		BackCode:              linelist[9],
		HeadSize:              linelist[10],
		PostSize:              linelist[11],
		BackeHeaderSize:       linelist[12],
		BackContentSize:       linelist[13],
		UpstreamIP:            linelist[14],
		ConnectFlag:           linelist[15],
		LogRatio:              linelist[16],
		UpstreamTimer:         linelist[17],
		ErrCode:               linelist[18],
		OriginalDomain:        linelist[19],
		UUID:                  linelist[20],
		LogMarkKey:            linelist[21],
		Line:                  []byte(line),
	}
}

// SubTime 判断当前是否会包含告警时段日志
func (ulog *UpstreamLog) SubTime(subtime string) time.Duration {
	Upstreamt := ulog.UpstreamTimeToTime()
	warnt := timepro.StringToTime(subtime)
	return Upstreamt.Sub(warnt)
}

// UpstreamTimeToTime 将时间格式化为时间类型
func (ulog *UpstreamLog) UpstreamTimeToTime() time.Time {
	return timepro.StringToTime(strings.Split(ulog.UpstreamTimeThreadNum, "]")[0][1:])
}

// String UpstreamLog的输出方式
func (ulog *UpstreamLog) String() string {
	return string(ulog.Line)
}

// SomeInfo 一部分信息
func (ulog *UpstreamLog) SomeInfo(someinfo []int) (info string) {
	line := string(ulog.Line)
	lineList := strings.Split(line, "\001")
	for _, v := range someinfo {
		if v > len(lineList) {
			continue
		}
		info += lineList[v] + "\001"
	}
	return
}

// Filter 过率信息
// content 过滤内容，支持正则，host 匹配的域名，dirt 是不是目录划分业务的标识符默认为false
func (ulog *UpstreamLog) Filter(content string) (match bool) {
	return true
}

// ToInt64 转换为int64
func (ulog *UpstreamLog) ToInt64(str string) int64 {
	str = strings.TrimSpace(str)
	n, err := strconv.ParseInt(str, 10, 64)
	if err != nil {
		return 0
	}
	return n
}

// UpstreamFile 访问日志对象
type UpstreamFile struct {
	FirstLine *UpstreamLog
	LastLine  *UpstreamLog
	Stat      os.FileInfo
	Filename  string
	File      *os.File
	StartFlag int64
	EndFlag   int64
	All       bool
	Some      bool
}

// NewUpstreamFile 创建一个日志处理对象
func NewUpstreamFile(filename string) *UpstreamFile {
	return &UpstreamFile{
		Filename: filename,
	}
}

// Init UpstreamFile 初始化
func (ufile *UpstreamFile) Init(stime, etime time.Time) (ok bool) {
	var err error
	ufile.Stat, err = os.Stat(ufile.Filename)
	if err != nil {
		panic(err)
	}
	modtime := ufile.Stat.ModTime()
	DeBugPrintln(stime.Sub(modtime), modtime, stime, ufile.Filename)
	DeBugPrintln("flag:", stime.Sub(modtime) > 0)
	if stime.Sub(modtime) > 0 {
		return false
	}
	ufile.File, err = os.Open(ufile.Filename)
	if err != nil {
		panic(err)
	}
	ufile.FirstLine = NewUpstreamLog(ReadFileFirstLine(ufile.Filename))
	ufile.LastLine = NewUpstreamLog(ReadFileLastLine(ufile.Filename))

	if ufile.FirstLine == nil || ufile.LastLine == nil {
		return false
	}
	return true
}

// JudgeContains 判断是否包含告警需要的信息
func (ufile *UpstreamFile) JudgeContains(starttime, warntime time.Time) {
	if warntime.Sub(ufile.FirstLine.UpstreamTimeToTime()) < 0 || ufile.LastLine.UpstreamTimeToTime().Sub(starttime) < 0 {
		ufile.All = false
		ufile.Some = false
		return
	}
	if starttime.Sub(ufile.FirstLine.UpstreamTimeToTime()) < 0 && ufile.LastLine.UpstreamTimeToTime().Sub(warntime) < 0 {
		ufile.All = true
		ufile.Some = false
		return
	}
	if starttime.Sub(ufile.FirstLine.UpstreamTimeToTime()) > 0 && ufile.LastLine.UpstreamTimeToTime().Sub(warntime) > 0 {
		ufile.All = false
		ufile.Some = true
		return
	}
	if ufile.FirstLine.UpstreamTimeToTime().Sub(starttime) > 0 && warntime.Sub(ufile.FirstLine.UpstreamTimeToTime()) > 0 {
		ufile.All = false
		ufile.Some = true
		return
	}
	if ufile.LastLine.UpstreamTimeToTime().Sub(starttime) > 0 && warntime.Sub(ufile.LastLine.UpstreamTimeToTime()) > 0 {
		ufile.All = false
		ufile.Some = true
		return
	}
	if ufile.FirstLine.UpstreamTimeToTime().Sub(starttime) > 0 && warntime.Sub(ufile.LastLine.UpstreamTimeToTime()) > 0 {
		ufile.All = false
		ufile.Some = true
		return
	}
	return
}

// UpstreamPro 日志处理
type UpstreamPro struct {
	LogInfo   []*UpstreamLog
	LogFile   []*UpstreamFile
	StartWarn time.Time
	EndWarn   time.Time
	SubTime   time.Duration
	Lock      *sync.Mutex
	MaxSize   int64
	AllNum    int64
}

// Close 关闭日志文件
func (ufile *UpstreamFile) Close() {
	ufile.File.Close()
	return
}

// AddLog 初始化日志处理模块
func (upro *UpstreamPro) AddLog(ulog *UpstreamLog, host, directory string) bool {
	defer func() {
		if _, ok := recover().(error); ok {
			return
		}
	}()
	upro.Lock.Lock()
	defer upro.Lock.Unlock()
	if upro.AllNum >= upro.MaxSize {
		return false
	}

	if host != "" {
		if strings.Contains(ulog.OriginalDomain, host) && strings.Contains(ulog.URL, directory) {
			if ulog.UpstreamTimeToTime().Sub(upro.StartWarn) >= 0 && ulog.UpstreamTimeToTime().Sub(upro.EndWarn) <= 0 {
				upro.LogInfo = append(upro.LogInfo, ulog)
				upro.AllNum++
				return true
			}
		}
	} else {
		if ulog.UpstreamTimeToTime().Sub(upro.StartWarn) >= 0 && ulog.UpstreamTimeToTime().Sub(upro.EndWarn) <= 0 {
			upro.LogInfo = append(upro.LogInfo, ulog)
			upro.AllNum++
			return true
		}
	}
	if upro.AllNum < 10 {
		return true
	}
	return false
}

// NewUpstreamPro 创建一个新的访问日志处理器
func NewUpstreamPro(stime, etime time.Time, datasize int64) *UpstreamPro {
	return &UpstreamPro{
		StartWarn: stime,
		EndWarn:   etime,
		SubTime:   etime.Sub(stime),
		Lock:      &sync.Mutex{},
		MaxSize:   datasize,
	}
}

// FilterUPro 日志处理器
type FilterUPro struct {
	LogInfo       []*UpstreamLog
	Host          *SomeInfo
	UpstreamIP    *SomeInfo
	URLErr        *SomeInfo
	ErrCode       *SomeInfo
	UpstreamTimer *SomeInfo
	UpFlux        *SomeInfo
	AllFlux       int64
	AllNum        int64
	ErrNum        int64
	MaxSize       int64
	Lock          *sync.Mutex
}

// NewFilterUPro 创建一个新的处理器
func NewFilterUPro() *FilterUPro {
	return &FilterUPro{
		Host:          NewSomeInfo(),
		UpstreamIP:    NewSomeInfo(),
		URLErr:        NewSomeInfo(),
		ErrCode:       NewSomeInfo(),
		UpstreamTimer: NewSomeInfo(),
		UpFlux:        NewSomeInfo(),
		AllNum:        0,
		MaxSize:       0,
		Lock:          &sync.Mutex{},
	}
}

// Add 添加数据
func (fp *FilterUPro) Add() {

	fp.AllNum++
}

// Count 返回日志数量
func (fp *FilterUPro) Count() int {
	return int(fp.ErrNum)
}

func (fp *FilterUPro) String(dirt bool, jsondata bool, outline int, sort string) (out string) {
	var jsonapi map[string][][]string
	jsonapi = make(map[string][][]string, 0)
	var outdata [][]string
	var list []string
	if dirt {
		fp.Host.Sort()
		list = fp.URLErr.CodeList
		length := len(fp.URLErr.CodeList)
		if length > outline {
			length = outline
		}
		for _, url := range list[:length] {
			if jsondata {
				outstr := fmt.Sprintln(url, "\t", fp.URLErr.CodeDict[url], "\t", strconv.Itoa(fp.Count()), "\t", fp.UpFlux.CodeDict[url], "\t", FloatToString(float64(fp.URLErr.CodeDict[url])/float64(fp.Count()), 2), "%")
				outlist := strings.Split(outstr[:len(outstr)-1], "\t")
				outdata = append(outdata, outlist)
			} else {
				out += fmt.Sprintln(url, "\t", fp.URLErr.CodeDict[url], "\t", strconv.Itoa(fp.Count()), "\t", fp.UpFlux.CodeDict[url], "\t", FloatToString(float64(fp.URLErr.CodeDict[url])/float64(fp.Count()), 2), "%")
			}
		}
		jsonapi["dir"] = outdata
	} else {
		fp.URLErr.Sort()
		list = fp.URLErr.CodeList
		length := len(fp.URLErr.CodeList)
		if length > outline {
			length = outline
		}
		for _, url := range list[:length] {
			DeBugPrintln(url)
			if jsondata {
				outstr := fmt.Sprintln(url, "\t", fp.URLErr.CodeDict[url], "\t", strconv.Itoa(fp.Count()), "\t", fp.UpFlux.CodeDict[url], "\t", FloatToString(float64(fp.URLErr.CodeDict[url])/float64(fp.Count()), 2), "%")
				outlist := strings.Split(outstr[:len(outstr)-1], "\t")
				outdata = append(outdata, outlist)
			} else {
				out += fmt.Sprintln(url, "\t", fp.URLErr.CodeDict[url], "\t", strconv.Itoa(fp.Count()), "\t", fp.UpFlux.CodeDict[url], "\t", FloatToString(float64(fp.URLErr.CodeDict[url])/float64(fp.Count()), 2), "%")
			}
		}
		jsonapi["uri"] = outdata
	}
	// 恢复outdata 为空
	outdata = [][]string{}

	out += "\n"

	list = fp.UpstreamIP.CodeList
	length := len(fp.UpstreamIP.CodeList)
	if length > outline {
		length = outline
	}
	for _, url := range list[:length] {
		DeBugPrintln(url)
		if jsondata {
			outstr := fmt.Sprintln(url, "\t", fp.UpstreamIP.CodeDict[url], "\t", strconv.Itoa(fp.Count()), "\t", FloatToString(float64(fp.UpstreamIP.CodeDict[url])/float64(fp.Count()), 2), "%")
			outlist := strings.Split(outstr[:len(outstr)-1], "\t")
			outdata = append(outdata, outlist)
		} else {
			out += fmt.Sprintln(url, "\t", fp.UpstreamIP.CodeDict[url], "\t", strconv.Itoa(fp.Count()), "\t", FloatToString(float64(fp.UpstreamIP.CodeDict[url])/float64(fp.Count()), 2), "%")
		}
	}
	jsonapi["uip"] = outdata
	out += "\n"
	outdata = [][]string{}

	list = fp.ErrCode.CodeList
	length = len(fp.ErrCode.CodeList)
	if length > outline {
		length = outline
	}
	for _, url := range list[:length] {
		DeBugPrintln(url)
		if jsondata {
			outstr := fmt.Sprintln(url, "\t", fp.ErrCode.CodeDict[url], "\t", strconv.Itoa(fp.Count()), "\t", FloatToString(float64(fp.ErrCode.CodeDict[url])/float64(fp.Count()), 2), "%")
			outlist := strings.Split(outstr[:len(outstr)-1], "\t")
			outdata = append(outdata, outlist)
		} else {
			out += fmt.Sprintln(url, "\t", fp.ErrCode.CodeDict[url], "\t", strconv.Itoa(fp.Count()), "\t", FloatToString(float64(fp.ErrCode.CodeDict[url])/float64(fp.Count()), 2), "%")
		}
	}
	jsonapi["errcode"] = outdata
	out += "\n"
	outdata = [][]string{}
	list = fp.UpFlux.CodeList
	length = len(fp.UpFlux.CodeList)
	if length > outline {
		length = outline
	}
	for _, url := range list[:length] {
		DeBugPrintln(url)
		if jsondata {
			outstr := fmt.Sprintln(url, "\t", fp.UpFlux.CodeDict[url], "M\t", fp.AllFlux, "M\t", FloatToString(float64(fp.UpFlux.CodeDict[url])/float64(fp.AllFlux), 2), "%")
			outlist := strings.Split(outstr[:len(outstr)-1], "\t")
			outdata = append(outdata, outlist)
		} else {
			out += fmt.Sprintln(url, "\t", fp.UpFlux.CodeDict[url], "M\t", fp.AllFlux, "M\t", FloatToString(float64(fp.UpFlux.CodeDict[url])/float64(fp.AllFlux), 2), "%")
		}
	}
	out += "\n"
	jsonapi["host"] = outdata

	if jsondata {
		jsonstr, _ := json.Marshal(jsonapi)
		return string(jsonstr)
	}
	return out

}

// FString ...
func (fp *FilterUPro) FString(dirt bool, ufi *FilterInfo) (out string) {
	var jsonapi map[string][][]string
	jsonapi = make(map[string][][]string, 0)
	var outdata [][]string
	var list []string
	if dirt {
		fp.Host.Sort()
		list = fp.URLErr.CodeList
		length := int64(len(fp.URLErr.CodeList))
		if length > ufi.OutLine {
			length = ufi.OutLine
		}
		for _, url := range list[:length] {
			if ufi.Format {
				outstr := fmt.Sprintln(url, "\t", fp.URLErr.CodeDict[url], "\t", strconv.Itoa(fp.Count()), "\t", FloatToString(float64(fp.URLErr.CodeDict[url])/float64(fp.Count()), 2), "%")
				outlist := strings.Split(outstr[:len(outstr)-1], "\t")
				outdata = append(outdata, outlist)
			} else {
				out += fmt.Sprintln(url, "\t", fp.URLErr.CodeDict[url], "\t", strconv.Itoa(fp.Count()), "\t", FloatToString(float64(fp.URLErr.CodeDict[url])/float64(fp.Count()), 2), "%")
			}
		}
		jsonapi["dir"] = outdata
	} else {
		fp.URLErr.Sort()
		list = fp.URLErr.CodeList
		length := len(fp.URLErr.CodeList)
		if length > int(ufi.OutLine) {
			length = int(ufi.OutLine)
		}
		for _, url := range list[:length] {
			DeBugPrintln(url)
			if ufi.Format {
				outstr := fmt.Sprintln(url, "\t", fp.URLErr.CodeDict[url], "\t", strconv.Itoa(fp.Count()), "\t", FloatToString(float64(fp.URLErr.CodeDict[url])/float64(fp.Count()), 2), "%")
				outlist := strings.Split(outstr[:len(outstr)-1], "\t")
				outdata = append(outdata, outlist)
			} else {
				out += fmt.Sprintln(url, "\t", fp.URLErr.CodeDict[url], "\t", strconv.Itoa(fp.Count()), "\t", FloatToString(float64(fp.URLErr.CodeDict[url])/float64(fp.Count()), 2), "%")
			}
		}
		jsonapi["uri"] = outdata
	}
	// 恢复outdata 为空
	outdata = [][]string{}

	out += "\n"

	list = fp.UpstreamIP.CodeList
	length := len(fp.UpstreamIP.CodeList)
	if length > int(ufi.OutLine) {
		length = int(ufi.OutLine)
	}
	for _, url := range list[:length] {
		DeBugPrintln(url)
		if ufi.Format {
			outstr := fmt.Sprintln(url, "\t", fp.UpstreamIP.CodeDict[url], "\t", strconv.Itoa(fp.Count()), "\t", FloatToString(float64(fp.UpstreamIP.CodeDict[url])/float64(fp.Count()), 2), "%")
			outlist := strings.Split(outstr[:len(outstr)-1], "\t")
			outdata = append(outdata, outlist)
		} else {
			out += fmt.Sprintln(url, "\t", fp.UpstreamIP.CodeDict[url], "\t", strconv.Itoa(fp.Count()), "\t", FloatToString(float64(fp.UpstreamIP.CodeDict[url])/float64(fp.Count()), 2), "%")
		}
	}
	jsonapi["uip"] = outdata
	out += "\n"
	outdata = [][]string{}

	list = fp.ErrCode.CodeList
	length = len(fp.ErrCode.CodeList)
	if length > int(ufi.OutLine) {
		length = int(ufi.OutLine)
	}
	for _, url := range list[:length] {
		DeBugPrintln(url)
		if ufi.Format {
			outstr := fmt.Sprintln(url, "\t", fp.ErrCode.CodeDict[url], "\t", strconv.Itoa(fp.Count()), "\t", FloatToString(float64(fp.ErrCode.CodeDict[url])/float64(fp.Count()), 2), "%")
			outlist := strings.Split(outstr[:len(outstr)-1], "\t")
			outdata = append(outdata, outlist)
		} else {
			out += fmt.Sprintln(url, "\t", fp.ErrCode.CodeDict[url], "\t", strconv.Itoa(fp.Count()), "\t", FloatToString(float64(fp.ErrCode.CodeDict[url])/float64(fp.Count()), 2), "%")
		}
	}
	jsonapi["errcode"] = outdata
	out += "\n"
	outdata = [][]string{}
	list = fp.UpFlux.CodeList
	length = len(fp.UpFlux.CodeList)
	if length > int(ufi.OutLine) {
		length = int(ufi.OutLine)
	}
	for _, url := range list[:length] {
		DeBugPrintln(url)
		if ufi.Format {
			outstr := fmt.Sprintln(url, "\t", FloatToString(float64(fp.UpFlux.CodeDict[url])/float64(logger.MB), 2), "M\t", FloatToString(float64(fp.AllFlux)/float64(logger.MB), 2), "M\t", FloatToString(float64(fp.UpFlux.CodeDict[url])/float64(fp.AllFlux), 2), "%")
			outlist := strings.Split(outstr[:len(outstr)-1], "\t")
			outdata = append(outdata, outlist)
		} else {
			out += fmt.Sprintln(url, "\t", FloatToString(float64(fp.UpFlux.CodeDict[url])/float64(logger.MB), 2), "M\t", FloatToString(float64(fp.AllFlux)/float64(logger.MB), 2), "M\t", FloatToString(float64(fp.UpFlux.CodeDict[url])/float64(fp.AllFlux), 2), "%")
		}
	}
	out += "\n"
	jsonapi["host"] = outdata

	if ufi.Format {
		jsonstr, _ := json.Marshal(jsonapi)
		return string(jsonstr)
	}
	return out
}

// FProLogFile F处理日志文件
func (upro *UpstreamPro) FProLogFile(files []string, ufi *FilterInfo, filterpro *FilterUPro) {
	var flag bool
	if ufi.Directory != "" {
		flag = true
	}
	DeBugPrintln("flag:", flag, ufi.Host, ufi.Directory)
	upro.LogInfo = make([]*UpstreamLog, 0)
	upro.LogFile = make([]*UpstreamFile, 0)

	for _, file := range files {
		ufile := NewUpstreamFile(file)
		ok := ufile.Init(upro.StartWarn, upro.EndWarn)
		if !ok {
			ufile.File.Close()
			continue
		}
		ufile.JudgeContains(upro.StartWarn, upro.EndWarn)
		DeBugPrintln("ufile:", ufile.All, ufile.Some)
		DeBugPrintln(ufile.FirstLine)
		DeBugPrintln(ufile.LastLine)
		DeBugPrintln(ufile.Filename, ufile.FirstLine.UpstreamTimeToTime(), ufile.LastLine.UpstreamTimeToTime())
		if ufile.All || ufile.Some {
			upro.LogFile = append(upro.LogFile, ufile)
			continue
		} else {
			ufile.Close()
		}
	}
	wg := sync.WaitGroup{}
	if ufi.LogQuit {
		fmt.Println("Contains Log's Files:")
		for _, uf := range upro.LogFile {
			fmt.Println(filepath.Join(ufi.LogPath, uf.Filename))
			uf.Close()
		}
		return
	}
	DeBugPrintln("filternum:", len(files), len(upro.LogFile))
	zonesize := ufi.ZoneSize
	for _, uf := range upro.LogFile {
		var n int64
		DeBugPrintln(uf.Filename)
		var lastdata = make([]byte, 2048)
		for n < uf.Stat.Size() {
			var linedata = make([]byte, zonesize)
			nu, err := uf.File.ReadAt(linedata, n)

			DeBugPrintln(nu, n, err)
			if err != nil && err != io.EOF {
				break
			}
			wg.Add(1)
			if lastdata[0] != 0 {
				linedata = append(lastdata, linedata...)
			}
			go fproUpstreamLogFile(uf.All, uf.Some, linedata, ufi, filterpro, &wg)
			lastdata = linedata[zonesize-2048 : zonesize]

			n += int64(nu)
		}
		wg.Wait()

		if filterpro.AllNum >= ufi.MaxLine {
			break
		}
	}
	out := filterpro.FString(flag, ufi)
	fmt.Println(out)
}

func fproUpstreamLogFile(all, some bool, linedata []byte, ufi *FilterInfo, fpro *FilterUPro, wg *sync.WaitGroup) {
	defer wg.Done()
	DeBugPrintln("prologfile:", all, some)
	if some {
		peach := ufi.StartWarn.String()[:16]
		DeBugPrintln(ufi.StartWarn, "\n\n\n,peach:", peach, "\n\n\n\n")
		// time.Sleep(100 * time.Second)
		match, _ := regexp.Compile(peach)
		index := match.FindAllIndex(linedata, 1)
		var indexlog int
		if len(index) == 0 {
			peach := ufi.EndWarn.String()[:16]
			DeBugPrintln(ufi.EndWarn, "\n\n\n", peach, "\n\n\n\n")
			// time.Sleep(100 * time.Second)
			match, _ := regexp.Compile(peach)
			index1 := match.FindAllIndex(linedata, 1)
			if len(index1) != 0 {
				indexlog = 0
			}
		} else {
			indexlog = index[0][0] - int(2*logger.KB)
			if indexlog < 0 {
				indexlog = 0
			}
			DeBugPrintln("findindex:", index[:1], len(linedata), indexlog)
		}
		DeBugPrintln(len(linedata), indexlog)
		linedata = (linedata)[indexlog:]
	}
	linebuf := bytes.NewBuffer(linedata)
	lineread := bufio.NewReader(linebuf)
	_, err := fReadULog(lineread, ufi, fpro)
	if err == OutTimeZone {
		return
	}
}

// fReadULog 加载log信息
func fReadULog(lineread *bufio.Reader, ufi *FilterInfo, filterpro *FilterUPro) (fp *FilterUPro, err error) {
	flag := false
	var i int
	for {
		i++
		line, _, err := lineread.ReadLine()
		if err == io.EOF {
			DeBugPrintln(err)
			break
		}
		if len(line) == 0 {
			continue
		}
		linestr := string(line)
		if ufi.FilterString != "" {
			match, _ := regexp.MatchString(ufi.FilterString, linestr)
			// DeBugPrintln(match, err)
			if match {
				ulog := NewUpstreamLog(linestr)
				if ulog == nil {
					continue
				}

				DeBugPrintln(i, "newulog")

				if !flag {
					if len(ulog.UpstreamTimeThreadNum) > 2048 {
						ulog.UpstreamTimeThreadNum = ulog.UpstreamTimeThreadNum[2048:]
					}
					flag = true
					DeBugPrintln(ulog)
					DeBugPrintln(ulog.String())
					DeBugPrintln("list:", strings.Split(ulog.String(), "\001"), len(strings.Split(ulog.String(), "\001")))
					DeBugPrintln(len(ulog.UpstreamTimeThreadNum), ulog.UpstreamTimeThreadNum, len(ulog.UpstreamTimeThreadNum))
					if ulog.UpstreamTimeToTime().Sub(ufi.EndWarn) > 0 {
						return filterpro, OutTimeZone
					}
				}
				var goon bool
				fp, goon, err = ulogFilter(ulog, ufi, filterpro, i)
				if goon {
					continue
				} else {
					break
				}
			} else {
				DeBugPrintln("no match!")
				continue
			}
		} else {
			ulog := NewUpstreamLog(linestr)
			if ulog == nil {
				continue
			}

			DeBugPrintln(i, "newulog")
			var goon bool
			fp, goon, err = ulogFilter(ulog, ufi, filterpro, i)
			if goon {
				continue
			} else {
				break
			}
		}

	}
	return filterpro, err
}

func ulogFilter(ulog *UpstreamLog, ufi *FilterInfo, filterpro *FilterUPro, i int) (fp *FilterUPro, goon bool, err error) {
	filterpro.Lock.Lock()
	defer filterpro.Lock.Unlock()
	defer func() {
		if _, ok := recover().(error); ok {
			return
		}
	}()
	if i%10 == 0 {
		if ulog.UpstreamTimeToTime().Sub(ufi.StartWarn) > -120*time.Second && ulog.UpstreamTimeToTime().Sub(ufi.EndWarn) < 60*time.Second {

		} else {
			DeBugPrintln("timeis:", ulog.UpstreamTimeToTime())
			return fp, false, err

		}
	}

	match, err := regexp.MatchString(ufi.Code, ulog.ErrCode)
	if !match {
		DeBugPrintln(match, err, ulog.ErrCode, ulog.BackContentSize)
	}
	if err != nil {
		return fp, true, err
	}

	if ufi.Host == "" {
		filterpro.AllNum++
		if !match {
			filterpro.ErrNum++
			filterpro.AllFlux += ulog.ToInt64(ulog.BackContentSize)
			filterpro.Host.Add(ulog.OriginalDomain)
			filterpro.UpstreamTimer.Add(ulog.UpstreamIP)

			DeBugPrintln("code:", ulog.ErrCode)
			filterpro.ErrCode.Add(ulog.ErrCode)
			filterpro.UpstreamIP.Add(ulog.UpstreamIP)
			filterpro.UpFlux.AddNum(ulog.OriginalDomain, ulog.ToInt64(ulog.BackContentSize))
		}

	} else {
		if !strings.Contains(ulog.OriginalDomain, ufi.Host) {
			return fp, true, err
		}

		filterpro.AllNum++
		// if strings.Contains(ulog.OriginalDomain, host) {
		if ulog.URL == "/" {
			return fp, true, err
		}
		direct := strings.Split(ulog.URL, "/")[1]

		if ufi.DirectoryFlag {
			if strings.Contains(ulog.URL, ufi.Directory) {
				if !match {
					filterpro.AllFlux += ulog.ToInt64(ulog.BackContentSize)

					filterpro.UpstreamTimer.Add(ulog.UpstreamIP)
					filterpro.Host.Add(ulog.OriginalDomain)
					filterpro.ErrNum++
					filterpro.URLErr.Add(ulog.URL)
					filterpro.ErrCode.Add(ulog.ErrCode)
					filterpro.UpstreamIP.Add(ulog.UpstreamIP)
					filterpro.UpFlux.AddNum(ulog.URL, ulog.ToInt64(ulog.BackContentSize))
				}
			}
		} else {
			if !match {
				filterpro.AllFlux += ulog.ToInt64(ulog.BackContentSize)

				filterpro.UpstreamTimer.Add(ulog.UpstreamIP)
				filterpro.Host.Add(ulog.OriginalDomain)
				filterpro.ErrNum++
				filterpro.URLErr.Add(ulog.URL)
				filterpro.ErrCode.Add(ulog.ErrCode)
				filterpro.UpstreamIP.Add(ulog.UpstreamIP)
				filterpro.UpFlux.AddNum(direct, ulog.ToInt64(ulog.BackContentSize))
			}
		}

	}
	return filterpro, true, err
}
