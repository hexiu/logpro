package prolog

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
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
	if len(linelist) < 22 {
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
	if starttime.Sub(ufile.FirstLine.UpstreamTimeToTime()) > 0 && ufile.LastLine.UpstreamTimeToTime().Sub(warntime) > 0 {
		ufile.All = true
		ufile.Some = false
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
			}
		}
	} else {
		if ulog.UpstreamTimeToTime().Sub(upro.StartWarn) >= 0 && ulog.UpstreamTimeToTime().Sub(upro.EndWarn) <= 0 {
			upro.LogInfo = append(upro.LogInfo, ulog)
			upro.AllNum++
		}
	}
	return true
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

// ProLogFile 处理日志文件
func (upro *UpstreamPro) ProLogFile(files []string, host string) {
	flag := strings.Contains(host, "/")
	var directory string
	if flag {
		peach := "/"
		if match, _ := regexp.Match(peach, []byte(host)); match {
			match, _ := regexp.Compile(peach)
			index := match.FindAllIndex([]byte(host), 1)
			DeBugPrintln("#####index:", index)
			directory = host[index[0][0]:]
		}
		host = strings.Split(host, "/")[0]
	}
	DeBugPrintln("flag:", flag, host, directory)
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
		DeBugPrintln(ufile.All, ufile.Some)
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
	DeBugPrintln("filternum:", len(files), len(upro.LogFile))
	zonesize := 50 * logger.MB
	for _, uf := range upro.LogFile {
		var n int64
		DeBugPrintln(uf.Filename)
		for n < uf.Stat.Size() {
			var linedata = make([]byte, zonesize)
			nu, err := uf.File.ReadAt(linedata, n)
			DeBugPrintln(nu, n, err)
			if err != nil && err != io.EOF {
				break
			}
			wg.Add(1)
			go proUpstreamLogFile(uf.All, uf.Some, linedata, upro, host, directory, &wg)
			n += int64(nu)
		}
		wg.Wait()

		if upro.AllNum >= upro.MaxSize {
			break
		}
	}
}

func proUpstreamLogFile(all, some bool, linedata []byte, upro *UpstreamPro, host, directory string, wg *sync.WaitGroup) {
	defer wg.Done()
	DeBugPrintln("prologfile:", all, some)
	if some {
		peach := host
		match, _ := regexp.Compile(peach)
		index := match.FindAllIndex(linedata, 1)
		var indexlog int
		if len(index) == 0 {
			indexlog = 0
		} else {
			indexlog = index[0][0] - int(10*logger.KB)
			if indexlog < 0 {
				indexlog = 0
			}
			DeBugPrintln(index[:1], len(linedata), indexlog)
		}
		DeBugPrintln(len(linedata), indexlog)
		linedata = (linedata)[indexlog:]
	}
	linebuf := bytes.NewBuffer(linedata)
	lineread := bufio.NewReader(linebuf)
	ReadULog(lineread, upro, host, directory)
}

// ReadULog 加载Upstreamlog信息
func ReadULog(lineread *bufio.Reader, upro *UpstreamPro, host, directory string) bool {

	for {
		line, _, err := lineread.ReadLine()
		linestr := string(line)
		if err == io.EOF {
			DeBugPrintln("AllNum:", upro.AllNum)
			DeBugPrintln(err)
			break
		}
		ulog := NewUpstreamLog(linestr)
		if ulog == nil {
			continue
		}
		if upro.AddLog(ulog, host, directory) {
			continue
		} else {
			DeBugPrintln(ulog, string(line), directory)
			return false
		}
	}
	return true
}

// FilterUPro 日志处理器
type FilterUPro struct {
	LogInfo       []*UpstreamLog
	Host          *SomeInfo
	UpstreamIP    *SomeInfo
	URLErr        *SomeInfo
	ErrCode       *SomeInfo
	UpstreamTimer *SomeInfo
	AllNum        int64
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
		AllNum:        0,
		MaxSize:       0,
		Lock:          &sync.Mutex{},
	}
}

// Add 添加数据
func (fp *FilterUPro) Add(ulog *UpstreamLog) {
	fp.Lock.Lock()
	defer fp.Lock.Unlock()
	fp.LogInfo = append(fp.LogInfo, ulog)
	fp.AllNum++
}

// Count 返回日志数量
func (fp *FilterUPro) Count() int {
	return int(fp.AllNum)
}

func (fp *FilterUPro) String(dirt bool, jsondata bool, outline int, sort string) (out string) {
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
				outstr := fmt.Sprintf("%s\t%s\t%s\t%s\n", url, strconv.Itoa(int(fp.URLErr.CodeDict[url])), strconv.Itoa(fp.Count()), FloatToString(float64(fp.URLErr.CodeDict[url])/float64(fp.Count()), 2))
				outlist := strings.Split(outstr[:len(outstr)-1], "\t")
				outdata = append(outdata, outlist)
			} else {
				out += fmt.Sprintln(url, "\t", fp.URLErr.CodeDict[url], "\t", strconv.Itoa(fp.Count()), "\t", FloatToString(float64(fp.URLErr.CodeDict[url])/float64(fp.Count()), 2), "%")
			}
		}
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
				outstr := fmt.Sprintf("%s\t%s\t%s\t%s\n", url, strconv.Itoa(int(fp.URLErr.CodeDict[url])), strconv.Itoa(fp.Count()), FloatToString(float64(fp.URLErr.CodeDict[url])/float64(fp.Count()), 2))
				outlist := strings.Split(outstr[:len(outstr)-1], "\t")
				outdata = append(outdata, outlist)
			} else {
				out += fmt.Sprintln(url, "\t", fp.URLErr.CodeDict[url], "\t", strconv.Itoa(fp.Count()), "\t", FloatToString(float64(fp.URLErr.CodeDict[url])/float64(fp.Count()), 2), "%")
			}
		}
	}

	out += "\n"

	list = fp.UpstreamIP.CodeList
	length := len(fp.UpstreamIP.CodeList)
	if length > outline {
		length = outline
	}
	for _, url := range list[:length] {
		DeBugPrintln(url)
		if jsondata {
			outstr := fmt.Sprintf("%s\t%s\t%s\t%s\n", url, strconv.Itoa(int(fp.URLErr.CodeDict[url])), strconv.Itoa(fp.Count()), FloatToString(float64(fp.URLErr.CodeDict[url])/float64(fp.Count()), 2))
			outlist := strings.Split(outstr[:len(outstr)-1], "\t")
			outdata = append(outdata, outlist)
		} else {
			out += fmt.Sprintln(url, "\t", fp.UpstreamIP.CodeDict[url], "\t", strconv.Itoa(fp.Count()), "\t", FloatToString(float64(fp.Host.CodeDict[url])/float64(fp.Count()), 2), "%")
		}
	}
	out += "\n"

	list = fp.ErrCode.CodeList
	length = len(fp.ErrCode.CodeList)
	if length > outline {
		length = outline
	}
	for _, url := range list[:length] {
		DeBugPrintln(url)
		if jsondata {
			outstr := fmt.Sprintf("%s\t%s\t%s\t%s\n", url, strconv.Itoa(int(fp.URLErr.CodeDict[url])), strconv.Itoa(fp.Count()), FloatToString(float64(fp.URLErr.CodeDict[url])/float64(fp.Count()), 2))
			outlist := strings.Split(outstr[:len(outstr)-1], "\t")
			outdata = append(outdata, outlist)
		} else {
			out += fmt.Sprintln(url, "\t", fp.ErrCode.CodeDict[url], "\t", strconv.Itoa(fp.Count()), "\t", FloatToString(float64(fp.Host.CodeDict[url])/float64(fp.Count()), 2), "%")
		}
	}
	if jsondata {
		jsonstr, _ := json.Marshal(outdata)
		return string(jsonstr)
	}
	return out

}

// Filter 过率信息
// content 过滤内容，支持正则，host 匹配的域名，dirt 是不是目录划分业务的标识符默认为false
func (upro *UpstreamPro) Filter(content, host string, dirt, format bool, outline int, sort string) (filterpro *FilterUPro, err error) {
	filterpro = NewFilterUPro()
	flag := strings.Contains(host, "/")
	var directory string
	if flag {
		peach := "/"
		if match, _ := regexp.Match(peach, []byte(host)); match {
			match, _ := regexp.Compile(peach)
			index := match.FindAllIndex([]byte(host), 1)
			directory = host[index[0][0]:]
			DeBugPrintln(directory)
		}
		host = strings.Split(host, "/")[0]
	}

	for _, ulog := range upro.LogInfo {
		filterpro.Add(ulog)
		if host == "" {
			filterpro.Host.Add(ulog.OriginalDomain)
			filterpro.UpstreamTimer.Add(ulog.UpstreamIP)

			DeBugPrintln("code:", ulog.ErrCode)
			filterpro.ErrCode.Add(ulog.ErrCode)
			filterpro.UpstreamIP.Add(ulog.UpstreamIP)
			filterpro.URLErr.Add(ulog.OriginalDomain)

		} else {
			if strings.Contains(ulog.OriginalDomain, host) {
				filterpro.UpstreamTimer.Add(ulog.UpstreamIP)
				filterpro.Host.Add(ulog.OriginalDomain)
				direct := strings.Split(ulog.URL, "/")[1]

				if dirt {
					// flag 标识 是否包含uri
					if flag {
						if strings.Contains(ulog.URL, directory) {
							filterpro.URLErr.Add(ulog.URL)
							filterpro.ErrCode.Add(ulog.ErrCode)
							filterpro.UpstreamIP.Add(ulog.UpstreamIP)

						}
					} else {
						if strings.Contains(ulog.URL, directory) {
							filterpro.URLErr.Add(direct)
							filterpro.ErrCode.Add(ulog.ErrCode)
							filterpro.UpstreamIP.Add(ulog.UpstreamIP)
						}
					}
				} else {
					if strings.Contains(ulog.BackCode, content) {
						filterpro.ErrCode.Add(ulog.ErrCode)
						filterpro.UpstreamIP.Add(ulog.UpstreamIP)
						filterpro.URLErr.Add(ulog.URL)
					}
				}

				// // match 说明返回码正常是0
				// if !match {
				// 	DeBugPrintln("code:", ulog.ErrCode)
				// 	filterpro.URLErr.Add(ulog.URL)
				// }
			}
		}

	}

	out := filterpro.String(dirt, format, outline, sort)
	fmt.Println(out)
	return
}
