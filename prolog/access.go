package prolog

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"standAlone/utils/logger"
	"strconv"
	"sync"

	"strings"
	"time"

	"github.com/hexiu/utils/timepro"
)

// AccessLog 访问日志处理结构
type AccessLog struct {
	AccessTimeThreadNum string
	ClientIP            string
	UnixTime            string
	GMTTime             string
	HTTPMethod          string
	URL                 string
	URLParam            string
	Range               string
	HeadSize            string
	PostSize            string
	FileSize            string
	Mtime               string
	BackCode            string
	BackeHeaderSize     string
	SendDataSize        string
	Referer             string
	Host                string
	UserAgent           string
	Cookie              string
	ClientFD            string
	XForwardIP          string
	Hit                 string
	Via                 string
	Server              string
	Location            string
	AcceptLanguage      string
	AcceptCharset       string
	ProTime             string
	LogRatio            string
	FileCrC             string
	UUID                string
	Line                []byte
}

// NewAccessLog 创建一个新的访问日志结构
func NewAccessLog(line string) *AccessLog {
	linelist := strings.Split(line, "\001")
	if len(linelist) != 31 && len(linelist) != 39 {
		return nil
	}
	return &AccessLog{
		AccessTimeThreadNum: linelist[0],
		ClientIP:            linelist[1],
		UnixTime:            linelist[2],
		GMTTime:             linelist[3],
		HTTPMethod:          linelist[4],
		URL:                 linelist[5],
		URLParam:            linelist[6],
		Range:               linelist[7],
		HeadSize:            linelist[8],
		PostSize:            linelist[9],
		FileSize:            linelist[10],
		Mtime:               linelist[11],
		BackCode:            linelist[12],
		BackeHeaderSize:     linelist[13],
		SendDataSize:        linelist[14],
		Referer:             linelist[15],
		Host:                linelist[16],
		UserAgent:           linelist[17],
		Cookie:              linelist[18],
		ClientFD:            linelist[19],
		XForwardIP:          linelist[20],
		Hit:                 linelist[21],
		Via:                 linelist[22],
		Server:              linelist[23],
		Location:            linelist[24],
		AcceptLanguage:      linelist[25],
		AcceptCharset:       linelist[26],
		ProTime:             linelist[27],
		LogRatio:            linelist[28],
		FileCrC:             linelist[29],
		UUID:                linelist[30],
		Line:                []byte(line),
	}
}

// SubTime 判断当前是否会包含告警时段日志
func (alog *AccessLog) SubTime(subtime string) time.Duration {
	accesst := alog.accessTimeToTime()
	warnt := timepro.StringToTime(subtime)
	return accesst.Sub(warnt)
}

func (alog *AccessLog) accessTimeToTime() time.Time {
	return timepro.StringToTime(strings.Split(alog.AccessTimeThreadNum, "]")[0][1:])
}

// String AccessLog的输出方式
func (alog *AccessLog) String() string {
	return string(alog.Line)
}

// SomeInfo 一部分信息
func (alog *AccessLog) SomeInfo(someinfo []int) (info string) {
	line := string(alog.Line)
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
func (alog *AccessLog) Filter(content string) (match bool, err error) {
	match, err = regexp.Match(content, []byte(alog.BackCode))
	return match, err
}

// ToInt64 转换为int64
func (alog *AccessLog) ToInt64(str string) int64 {
	str = strings.TrimSpace(str)
	n, err := strconv.ParseInt(str, 10, 64)
	if err != nil {
		return 0
	}
	return n
}

// ReadFileFirstLine 读取文件的第一行
func ReadFileFirstLine(filename string) (line string) {
	file, err := os.OpenFile(filename, os.O_RDONLY, os.ModePerm)
	defer file.Close()
	if err != nil {
		panic(err)
	}
	var linebyte = make([]byte, 5*logger.KB)
	length, err := file.Read(linebyte)
	if length < 0 {
		return ""
	}
	if err != nil && err != io.EOF {
		panic(err)
	}
	linebuf := bytes.NewReader(linebyte)
	linebufio := bufio.NewReader(linebuf)
	lineb, _, err := linebufio.ReadLine()
	if err != nil {
		panic(err)
	}
	if err == io.EOF {
		return
	}

	return string(lineb)
}

// ReadFileLastLine 读取文件的最后一行
func ReadFileLastLine(filename string) (line string) {
	stat, err := os.Stat(filename)
	if err != nil {
		panic(err)
	}
	file, err := os.OpenFile(filename, os.O_RDONLY, os.ModePerm)
	defer file.Close()
	if err != nil {
		panic(err)
	}
	var linebyte = make([]byte, 5*logger.KB)
	indexlog := stat.Size() - 5*logger.KB
	if indexlog < 0 {
		indexlog = 0
	}
	DeBugPrintln("file: ", filename, "filesize:", stat.Size())
	length, err := file.ReadAt(linebyte, indexlog)
	if length < 0 {
		return ""
	}
	if err != nil && err != io.EOF {
		panic(err)
	}
	linebuf := string(linebyte)
	linelist := strings.Split(linebuf, "\n")
	if len(linelist) < 2 {
		return ""
	}
	line = linelist[len(linelist)-2:][0]
	DeBugPrintln(string(line))
	return line
}

func readFirstLine(linedata *[]byte) (alog *AccessLog) {
	length := len(*linedata) - 1<<10
	if length < 0 {
		return nil
	}
	var linebyte = (*linedata)[:length]
	linebuf := bytes.NewReader(linebyte)
	linebufio := bufio.NewReader(linebuf)
	line, _, err := linebufio.ReadLine()
	if err != nil {
		panic(err)
	}
	return NewAccessLog(string(line))

}

func readLastLine(linedata *[]byte) (alog *AccessLog) {
	length := len(*linedata) - 1<<10
	if length < 0 {
		return nil
	}
	var linebyte = (*linedata)[length:]
	linebuf := bytes.NewReader(linebyte)
	linebufio := bufio.NewReader(linebuf)
	line, _, err := linebufio.ReadLine()
	if err != nil {
		panic(err)
	}
	return NewAccessLog(string(line))
}

// AccessFile 访问日志对象
type AccessFile struct {
	FirstLine *AccessLog
	LastLine  *AccessLog
	Stat      os.FileInfo
	Filename  string
	File      *os.File
	StartFlag int64
	EndFlag   int64
	All       bool
	Some      bool
}

// NewAccessFile 创建一个日志处理对象
func NewAccessFile(filename string) *AccessFile {
	return &AccessFile{
		Filename: filename,
	}
}

// Close 关闭日志文件
func (afile *AccessFile) Close() {
	afile.File.Close()
	return
}

// Init AccessFile 初始化
func (afile *AccessFile) Init(stime, etime time.Time) (ok bool) {
	var err error
	afile.Stat, err = os.Stat(afile.Filename)
	if err != nil {
		panic(err)
	}
	modtime := afile.Stat.ModTime()
	DeBugPrintln(stime.Sub(modtime), modtime, stime, afile.Filename)
	if stime.Sub(modtime) > 0 {
		return false
	}
	afile.File, err = os.Open(afile.Filename)
	if err != nil {
		panic(err)
	}
	afile.FirstLine = NewAccessLog(ReadFileFirstLine(afile.Filename))
	afile.LastLine = NewAccessLog(ReadFileLastLine(afile.Filename))
	DeBugPrintln(afile.FirstLine, afile.LastLine)
	if afile.FirstLine == nil || afile.LastLine == nil {
		return false
	}
	return true
}

// JudgeContains 判断是否包含告警需要的信息
func (afile *AccessFile) JudgeContains(starttime, warntime time.Time) {
	if warntime.Sub(afile.FirstLine.accessTimeToTime()) < 0 || afile.LastLine.accessTimeToTime().Sub(starttime) < 0 {
		afile.All = false
		afile.Some = false
		return
	}
	if starttime.Sub(afile.FirstLine.accessTimeToTime()) < 0 && afile.LastLine.accessTimeToTime().Sub(warntime) < 0 {
		afile.All = true
		afile.Some = false
		return
	}
	if starttime.Sub(afile.FirstLine.accessTimeToTime()) > 0 && afile.LastLine.accessTimeToTime().Sub(warntime) > 0 {
		afile.All = false
		afile.Some = true
		return
	}
	if afile.FirstLine.accessTimeToTime().Sub(starttime) > 0 && warntime.Sub(afile.FirstLine.accessTimeToTime()) > 0 {
		afile.All = false
		afile.Some = true
		return
	}
	if afile.LastLine.accessTimeToTime().Sub(starttime) > 0 && warntime.Sub(afile.LastLine.accessTimeToTime()) > 0 {
		afile.All = false
		afile.Some = true
		return
	}
	if afile.FirstLine.accessTimeToTime().Sub(starttime) > 0 && warntime.Sub(afile.LastLine.accessTimeToTime()) > 0 {
		afile.All = false
		afile.Some = true
		return
	}

	return
}

// AccessPro 日志处理
type AccessPro struct {
	LogInfo   []*AccessLog
	LogFile   []*AccessFile
	StartWarn time.Time
	EndWarn   time.Time
	SubTime   time.Duration
	Lock      *sync.Mutex
	MaxSize   int64
	AllNum    int64
}

// AddLog 初始化日志处理模块
func (apro *AccessPro) AddLog(alog *AccessLog, host, directory string) bool {
	defer func() {
		if _, ok := recover().(error); ok {
			return
		}
	}()
	apro.Lock.Lock()
	defer apro.Lock.Unlock()
	if apro.AllNum >= apro.MaxSize {
		return false
	}

	if host != "" {
		if strings.Contains(alog.Host, host) && strings.Contains(alog.URL, directory) {
			if alog.accessTimeToTime().Sub(apro.StartWarn) >= 0 && alog.accessTimeToTime().Sub(apro.EndWarn) <= 0 {
				apro.LogInfo = append(apro.LogInfo, alog)
				apro.AllNum++
			}
		}
	} else {
		if alog.accessTimeToTime().Sub(apro.StartWarn) >= 0 && alog.accessTimeToTime().Sub(apro.EndWarn) <= 0 {
			apro.LogInfo = append(apro.LogInfo, alog)
			apro.AllNum++
		}
	}
	return true
}

// NewAccessPro 创建一个新的访问日志处理器
func NewAccessPro(stime, etime time.Time, datasize int64) *AccessPro {
	return &AccessPro{
		StartWarn: stime,
		EndWarn:   etime,
		SubTime:   etime.Sub(stime),
		Lock:      &sync.Mutex{},
		MaxSize:   datasize,
	}
}

// FProLogFile F处理日志文件
func (apro *AccessPro) FProLogFile(files []string, afi *FilterInfo, filterpro *FilterPro) {
	var flag bool
	if afi.Directory != "" {
		flag = true
	}
	DeBugPrintln("flag:", flag, afi.Host, afi.Directory)
	apro.LogInfo = make([]*AccessLog, 0)
	apro.LogFile = make([]*AccessFile, 0)

	for _, file := range files {
		afile := NewAccessFile(file)
		ok := afile.Init(apro.StartWarn, apro.EndWarn)
		if !ok {
			afile.File.Close()
			continue
		}
		afile.JudgeContains(apro.StartWarn, apro.EndWarn)
		DeBugPrintln(afile.All, afile.Some)
		DeBugPrintln(afile.FirstLine)
		DeBugPrintln(afile.LastLine)
		DeBugPrintln(afile.Filename, afile.FirstLine.accessTimeToTime(), afile.LastLine.accessTimeToTime())
		if afile.All || afile.Some {
			apro.LogFile = append(apro.LogFile, afile)
			continue
		} else {
			afile.Close()
		}
	}
	wg := sync.WaitGroup{}
	DeBugPrintln("filternum:", len(files), len(apro.LogFile))
	if afi.LogQuit {
		fmt.Println("Contains Log's Files:")
		for _, af := range apro.LogFile {
			fmt.Println(filepath.Join(afi.LogPath, af.Filename))
			af.Close()
		}
		return
	}

	zonesize := afi.ZoneSize
	for _, af := range apro.LogFile {
		var n int64
		DeBugPrintln(af.Filename)
		var lastdata = make([]byte, 2048)
		for n < af.Stat.Size() {
			var linedata = make([]byte, zonesize)
			nu, err := af.File.ReadAt(linedata, n)

			DeBugPrintln(nu, n, err)
			if err != nil && err != io.EOF {
				break
			}
			wg.Add(1)
			linedata = append(lastdata, linedata...)
			go fproLogFile(af.All, af.Some, linedata, afi, filterpro, &wg)
			lastdata = linedata[zonesize-2048 : zonesize]

			n += int64(nu)
		}
		wg.Wait()

		if filterpro.AllNum >= afi.MaxLine {
			break
		}
	}
	out := filterpro.FString(flag, afi)
	fmt.Println(out)

}

// FilterInfo 访问日志过滤信息
type FilterInfo struct {
	Host          string
	Directory     string
	LogPath       string
	DirectoryFlag bool
	FluxSort      bool
	MatchNumSort  bool
	OutLine       int64
	URI           string
	Code          string
	FilterString  string
	Format        bool
	LogQuit       bool
	Sort          string
	MaxLine       int64
	StartWarn     time.Time
	EndWarn       time.Time
	ZoneSize      int64 // 读取信息的块大小
}

// NewFilterInfo 日志过滤信息
func NewFilterInfo() *FilterInfo {
	return &FilterInfo{
		ZoneSize: 100 * logger.MB,
		OutLine:  10,
		MaxLine:  100000,
	}
}

var OutTimeZone = errors.New("Out Time Zone")

// fReadLog 加载log信息
func fReadLog(lineread *bufio.Reader, afi *FilterInfo, filterpro *FilterPro) (fp *FilterPro, err error) {
	flag := false
	var i int
	for {
		i++
		line, _, err := lineread.ReadLine()
		linestr := string(line)
		if err == io.EOF {
			DeBugPrintln(err)
			break
		}
		if afi.FilterString != "" {
			match, _ := regexp.MatchString(afi.FilterString, linestr)
			// DeBugPrintln(match, err)
			if match {
				alog := NewAccessLog(linestr)
				if alog == nil {
					continue
				}

				if !flag {
					if len(alog.AccessTimeThreadNum) > 2048 {
						alog.AccessTimeThreadNum = alog.AccessTimeThreadNum[2048:]
					}
					flag = true
					DeBugPrintln(alog)
					DeBugPrintln(alog.String())
					DeBugPrintln("list:", strings.Split(alog.String(), "\001"), len(strings.Split(alog.String(), "\001")))
					DeBugPrintln(len(alog.AccessTimeThreadNum), alog.AccessTimeThreadNum, len(alog.AccessTimeThreadNum))
					if alog.accessTimeToTime().Sub(afi.EndWarn) > 0 {
						return filterpro, OutTimeZone
					}
				}
				var goon bool
				fp, goon, err = logFilter(alog, afi, filterpro, i)
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
			alog := NewAccessLog(linestr)
			if alog == nil {
				continue
			}

			var goon bool
			fp, goon, err = logFilter(alog, afi, filterpro, i)
			if goon {
				continue
			} else {
				break
			}
		}

	}
	return filterpro, err
}

func logFilter(alog *AccessLog, afi *FilterInfo, filterpro *FilterPro, i int) (fp *FilterPro, goon bool, err error) {
	defer func() {
		if _, ok := recover().(error); ok {
			return
		}
	}()
	if i%10 == 0 {
		if alog.accessTimeToTime().Sub(afi.StartWarn) > -120*time.Second && alog.accessTimeToTime().Sub(afi.EndWarn) < 60*time.Second {
		} else {
			DeBugPrintln("timeis:", alog.accessTimeToTime())
			return fp, false, err
		}
	}

	if afi.Host == "" {
		filterpro.Lock.Lock()
		defer filterpro.Lock.Unlock()
		filterpro.AllNum++
		filterpro.URL.Add(alog.Host)
		var match bool
		match, err = regexp.MatchString(afi.Code, alog.BackCode)
		if err != nil {
			return filterpro, false, err
		}
		if match {
			filterpro.ErrNum++
			filterpro.URLErr.Add(alog.Host)
			filterpro.Flux.AddNum(alog.Host, alog.ToInt64(alog.SendDataSize))
			filterpro.UA.Add(alog.UserAgent)
		}
	} else {
		if !strings.Contains(alog.Host, afi.Host) {
			return fp, true, err
		}
		filterpro.Lock.Lock()
		defer filterpro.Lock.Unlock()
		filterpro.AllNum++
		filterpro.URL.Add(alog.URL)
		if alog.URL == "/" {
			return filterpro, true, err
		}
		var match bool
		match, err = regexp.MatchString(afi.Code, alog.BackCode)
		if err != nil {
			return filterpro, false, err
		}
		if match {
			filterpro.ErrNum++
			if afi.DirectoryFlag {
				afi.Directory = strings.Split(alog.URL, "/")[1]
				filterpro.Dir.Add(afi.Directory)
				if afi.FluxSort {
					filterpro.Flux.AddNum(alog.URL, alog.ToInt64(alog.SendDataSize))
					filterpro.URLErr.Add(alog.URL)
					filterpro.UA.Add(alog.UserAgent)
				} else {
					filterpro.Flux.AddNum(afi.Directory, alog.ToInt64(alog.SendDataSize))
					filterpro.URLErr.Add(afi.Directory)
					filterpro.UA.Add(alog.UserAgent)
				}
			} else {
				filterpro.Flux.AddNum(alog.URL, alog.ToInt64(alog.SendDataSize))
				filterpro.URLErr.Add(alog.URL)
				filterpro.UA.Add(alog.UserAgent)
			}
		}
	}
	return filterpro, true, err
}

// SomeInfo 一些 信息
type SomeInfo struct {
	CodeDict map[string]int64
	CodeList []string
}

// NewSomeInfo 一些信息结构初始化
func NewSomeInfo() *SomeInfo {
	return &SomeInfo{
		CodeDict: make(map[string]int64, 0),
		CodeList: make([]string, 0),
	}
}

// AddNum 添加流量信息
func (si *SomeInfo) AddNum(key string, num int64) {
	if _, ok := si.CodeDict[key]; ok {
		si.CodeDict[key] += num
	} else {
		si.CodeDict[key] += num
		si.CodeList = append(si.CodeList, key)
	}
}

// Add 添加内容
func (si *SomeInfo) Add(key string) {
	if _, ok := si.CodeDict[key]; ok {
		si.CodeDict[key]++
	} else {
		si.CodeDict[key]++
		si.CodeList = append(si.CodeList, key)
	}
}

// Sort 信息排序
func (si *SomeInfo) Sort() {
	length := len(si.CodeList)
	for i := 0; i < length; i++ {
		for j := i; j < length; j++ {
			if si.CodeDict[si.CodeList[i]] < si.CodeDict[si.CodeList[j]] {
				si.CodeList[j], si.CodeList[i] = si.CodeList[i], si.CodeList[j]
			}
		}
	}
}

// FilterPro 日志处理器
type FilterPro struct {
	LogInfo []*AccessLog
	URL     *SomeInfo
	Dir     *SomeInfo
	URLErr  *SomeInfo
	Flux    *SomeInfo
	UA      *SomeInfo
	AllNum  int64
	ErrNum  int64
	MaxSize int64
	Lock    *sync.Mutex
}

// NewFilterPro 创建一个新的处理器
func NewFilterPro() *FilterPro {
	return &FilterPro{
		URL:    NewSomeInfo(),
		Dir:    NewSomeInfo(),
		URLErr: NewSomeInfo(),
		Flux:   NewSomeInfo(),
		UA:     NewSomeInfo(),
		AllNum: 0,
		Lock:   &sync.Mutex{},
	}
}

// Add 添加数据
func (fp *FilterPro) Add() {
	fp.AllNum++
}

// Count 返回日志数量
func (fp *FilterPro) Count() int {
	return int(fp.ErrNum)
}

func (fp *FilterPro) String(dirt bool, jsondata bool, outline int, sort string) (out string) {
	var jsonapi = make(map[string][][]string, 0)
	var outdata [][]string
	var list []string
	if dirt {
		if sort == "flux" {
			fp.Flux.Sort()
			list = fp.Flux.CodeList
		} else {
			fp.URLErr.Sort()
			list = fp.URLErr.CodeList
		}
		length := len(fp.URLErr.CodeList)
		if length > outline {
			length = outline
		}
		for _, url := range list[:length] {
			if jsondata {
				outstr := fmt.Sprintf("%s\t%s\t%s\t%s\t%s\n", url, strconv.Itoa(int(fp.URLErr.CodeDict[url])), strconv.Itoa(fp.Count()), FloatToString(float64(fp.Flux.CodeDict[url])/float64(logger.MB), 2), FloatToString(float64(fp.URLErr.CodeDict[url])/float64(fp.Count()), 2))
				outlist := strings.Split(outstr[:len(outstr)-1], "\t")
				outdata = append(outdata, outlist)
			} else {
				out += fmt.Sprintln(url, "\t", fp.URLErr.CodeDict[url], "\t", strconv.Itoa(fp.Count()), "\t", FloatToString(float64(fp.Flux.CodeDict[url])/float64(logger.MB), 2), "MB\t", FloatToString(float64(fp.URLErr.CodeDict[url])/float64(fp.Count()), 2), "%")
			}
		}
		jsonapi["uri"] = outdata

	} else {
		if sort == "flux" {
			fp.Flux.Sort()
			list = fp.Flux.CodeList
		} else {
			fp.URLErr.Sort()
			list = fp.URLErr.CodeList
		}
		length := len(fp.URLErr.CodeList)
		if length > outline {
			length = outline
		}
		for _, url := range list[:length] {
			if jsondata {
				outstr := fmt.Sprintf("%s\t%s\t%s\t%s\t%s\n", url, strconv.Itoa(int(fp.URLErr.CodeDict[url])), strconv.Itoa(fp.Count()), FloatToString(float64(fp.Flux.CodeDict[url])/float64(logger.MB), 2), FloatToString(float64(fp.URLErr.CodeDict[url])/float64(fp.Count()), 2))
				outlist := strings.Split(outstr[:len(outstr)-1], "\t")
				outdata = append(outdata, outlist)
			} else {
				out += fmt.Sprintln(url, "\t", fp.URLErr.CodeDict[url], "\t", strconv.Itoa(fp.Count()), "\t", FloatToString(float64(fp.Flux.CodeDict[url])/float64(logger.MB), 2), "MB\t", FloatToString(float64(fp.URLErr.CodeDict[url])/float64(fp.Count()), 2), "%")
			}
		}
		jsonapi["uri"] = outdata
	}

	if jsondata {
		jsonstr, _ := json.Marshal(jsonapi)
		return string(jsonstr)
	}
	return out
}

// FString 新版本输出
func (fp *FilterPro) FString(dirt bool, afi *FilterInfo) (out string) {
	var jsonapi = make(map[string][][]string, 0)
	var outdata [][]string
	var list []string
	if dirt {
		if afi.FluxSort {
			fp.Flux.Sort()
			list = fp.Flux.CodeList
		} else {
			fp.URLErr.Sort()
			list = fp.URLErr.CodeList
		}
		length := int64(len(fp.URLErr.CodeList))
		if length > afi.OutLine {
			length = afi.OutLine
		}
		for _, url := range list[:length] {
			if afi.Format {
				outstr := fmt.Sprintf("%s\t%s\t%s\t%s\t%s\n", url, strconv.Itoa(int(fp.URLErr.CodeDict[url])), strconv.Itoa(fp.Count()), FloatToString(float64(fp.Flux.CodeDict[url])/float64(logger.MB), 2), FloatToString(float64(fp.URLErr.CodeDict[url])/float64(fp.Count()), 2))
				outlist := strings.Split(outstr[:len(outstr)-1], "\t")
				outdata = append(outdata, outlist)
			} else {
				out += fmt.Sprintln(url, "\t", fp.URLErr.CodeDict[url], "\t", strconv.Itoa(fp.Count()), "\t", FloatToString(float64(fp.Flux.CodeDict[url])/float64(logger.MB), 2), "MB\t", FloatToString(float64(fp.URLErr.CodeDict[url])/float64(fp.Count()), 2), "%")
			}
		}
		jsonapi["uri"] = outdata

	} else {
		if afi.FluxSort {
			fp.Flux.Sort()
			list = fp.Flux.CodeList
		} else {
			fp.URLErr.Sort()
			list = fp.URLErr.CodeList
		}
		length := int64(len(fp.URLErr.CodeList))
		if length > afi.OutLine {
			length = afi.OutLine
		}
		for _, url := range list[:length] {
			if afi.Format {
				outstr := fmt.Sprintf("%s\t%s\t%s\t%s\t%s\n", url, strconv.Itoa(int(fp.URLErr.CodeDict[url])), strconv.Itoa(fp.Count()), FloatToString(float64(fp.Flux.CodeDict[url])/float64(logger.MB), 2), FloatToString(float64(fp.URLErr.CodeDict[url])/float64(fp.Count()), 2))
				outlist := strings.Split(outstr[:len(outstr)-1], "\t")
				outdata = append(outdata, outlist)
			} else {
				out += fmt.Sprintln(url, "\t", fp.URLErr.CodeDict[url], "\t", strconv.Itoa(fp.Count()), "\t", FloatToString(float64(fp.Flux.CodeDict[url])/float64(logger.MB), 2), "MB\t", FloatToString(float64(fp.URLErr.CodeDict[url])/float64(fp.Count()), 2), "%")
			}
		}
		jsonapi["uri"] = outdata
	}

	outdata = [][]string{}
	length := int64(len(fp.UA.CodeList))
	if length > afi.OutLine {
		length = afi.OutLine
	}
	fp.UA.Sort()
	list = fp.UA.CodeList[:length]
	out += "UA:\n"
	for _, ua := range list[:length] {
		if afi.Format {
			outstr := fmt.Sprintf("%s\t%s\t%s\t%s\t%s\n", ua, strconv.Itoa(int(fp.UA.CodeDict[ua])), strconv.Itoa(fp.Count()), fp.UA.CodeDict[ua], FloatToString(float64(fp.UA.CodeDict[ua])/float64(fp.Count()), 2))
			outlist := strings.Split(outstr[:len(outstr)-1], "\t")
			outdata = append(outdata, outlist)
		} else {
			out += fmt.Sprintln(ua, "\t", fp.UA.CodeDict[ua], "\t", strconv.Itoa(fp.Count()), "\t", fp.UA.CodeDict[ua], "\t", FloatToString(float64(fp.UA.CodeDict[ua])/float64(fp.Count()), 2), "%")
		}
	}
	jsonapi["ua"] = outdata

	if afi.Format {
		jsonstr, _ := json.Marshal(jsonapi)
		return string(jsonstr)
	}
	return out
}

// FloatToString Float转换string
func FloatToString(f float64, long int) string {
	str := fmt.Sprintf("%."+strconv.Itoa(long)+"f", f*100.0)
	return strings.Split(str, "!")[0]
}

func fproLogFile(all, some bool, linedata []byte, afi *FilterInfo, fpro *FilterPro, wg *sync.WaitGroup) {
	defer wg.Done()
	DeBugPrintln("prologfile:", all, some)
	if some {
		peach := afi.StartWarn.String()[:16]
		DeBugPrintln(afi.StartWarn, "\n\n\n", peach, "\n\n\n\n")
		// time.Sleep(100 * time.Second)
		match, _ := regexp.Compile(peach)
		index := match.FindAllIndex(linedata, 1)
		var indexlog int
		if len(index) == 0 {
			peach := afi.EndWarn.String()[:16]
			DeBugPrintln(afi.EndWarn, "\n\n\n", peach, "\n\n\n\n")
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
			DeBugPrintln(index[:1], len(linedata), indexlog)
		}
		DeBugPrintln(len(linedata), indexlog)
		linedata = (linedata)[indexlog:]
	}
	linebuf := bytes.NewBuffer(linedata)
	lineread := bufio.NewReader(linebuf)
	_, err := fReadLog(lineread, afi, fpro)
	if err == OutTimeZone {
		return
	}
}
