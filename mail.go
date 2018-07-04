//
// 功能：简单邮件系统
// 作者：Ease
// 日期：2018.7.3
// 说明：1. 在linux下可以语音提醒指定邮箱的邮件收到的信息
//      2.
// 问题：1. mail.126.com邮件收不到
//      2. 动态载入垃圾过滤文件，类似nginx -s reload
//      3. 响应不完整时，不建立临时文件
//      4. Web收邮件、查看邮件
// 其它:
//      nginx转发：
//         stream {
//             server {
//                listen 25;
//                proxy_pass a.a.a.a:2500;
//             }
//         }
//

package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"path"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type ReplyCode string
type Command int

const (
	ReplyServiceReady          ReplyCode = "220 mail.scwy.net Tu Mail Server"
	ReplyServiceClosing        ReplyCode = "221 goodbye"
	ReplyOkay                  ReplyCode = "250 yes sir"
	ReplyStartMailInput        ReplyCode = "354 fill 'er up"
	ReplyServiceNotAvailable   ReplyCode = "421 not at the moment"
	ReplyCommandNotImplemented ReplyCode = "502 *shrugs*"
)

const (
	CommandEhlo Command = iota
	CommandHelo
	CommandMail
	CommandRcpt
	CommandData
	CommandRset
	CommandVrfy
	CommandExpn
	CommandHelp
	CommandNoop
	CommandQuit
)

var replyTable = map[Command]ReplyCode{
	CommandEhlo: ReplyOkay,
	CommandMail: ReplyOkay,
	CommandRcpt: ReplyOkay,
	CommandData: ReplyStartMailInput,
	CommandRset: ReplyOkay,
	CommandVrfy: ReplyOkay,
	CommandExpn: ReplyCommandNotImplemented,
	CommandHelp: ReplyCommandNotImplemented,
	CommandNoop: ReplyOkay,
	CommandQuit: ReplyServiceClosing,
}

var commandTable = map[string]Command{
	"EHLO": CommandEhlo,
	"HELO": CommandEhlo,
	"MAIL": CommandMail,
	"RCPT": CommandRcpt,
	"DATA": CommandData,
	"RSET": CommandRset,
	"VRFY": CommandVrfy,
	"EXPN": CommandExpn,
	"HELP": CommandHelp,
	"NOOP": CommandNoop,
	"QUIT": CommandQuit,
}

var (
	messageNameFormat = "%v--%v--%v--%v.txt"
	serverBlocklist   = []string{} //垃圾邮件地址
	defaultAddr       = "invalid@addr"
	outputDirectory   string //邮件输出目录
	listeningPort     int    //侦听端口
	spamDetection     bool   //垃圾检测
	debug             bool   //调试信息
	badaddr           string //垃圾邮件列表文件
	ShowColorPrefix   string = "\033[49;34;1m"
	ShowColorSuffix   string = "\033[0m"
	MailAlter         string //邮件语音提醒
)

//显示调试(详细)信息
func DEBUG(info string) {
	if debug {
		log.Println(info)
	}
}

//读取垃圾邮件地址
func ReadBlocklist() {
	file, err := os.Open(badaddr)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	buf := bufio.NewReader(file)

	for line, err := []byte{0}, error(nil); len(line) > 0 && err == nil; {
		line, _, err = buf.ReadLine()
		if len(line) > 0 {
			serverBlocklist = append(serverBlocklist, string(line))
		}
	}
}

func readCommand(conn net.Conn, buf []byte) (int, error) {
	datum := make([]byte, 1)
	length := 0
	for {
		bytesRead, err := conn.Read(datum)
		if err != nil {
			return 0, err
		}
		if bytesRead == 1 && length < cap(buf) {
			buf[length] = datum[0]
			length += bytesRead
			if datum[0] == '\n' {
				return length, nil
			}
		}
	}
}

//服务器指令响应,返回指令
func replyCommand(conn net.Conn, line string) Command {
	line = strings.TrimSpace(line)
	args := strings.Split(line, " ")
	cmd, exists := commandTable[strings.ToUpper(args[0])]
	if exists {
		reply, exists := replyTable[cmd]
		if exists {
			fmt.Fprintln(conn, reply) //存在对应的回复指令
		} else {
			fmt.Fprintln(conn, ReplyCommandNotImplemented) //未知指令
		}
	} else {
		fmt.Fprintln(conn, ReplyOkay) //不存在对应的回复指令，直接回复OK
	}
	return cmd
}

func toIPAddress(addr net.Addr) string {
	ipAddress := strings.Split(addr.String(), ":")[0]
	dots := strings.Split(ipAddress, ".")

	/* https://stackoverflow.com/questions/34816489/reverse-slice-of-strings */
	last := len(dots) - 1
	for i := 0; i < len(dots)/2; i++ {
		dots[i], dots[last-i] = dots[last-i], dots[i]
	}

	return strings.Join(dots, ".")
}

//垃圾邮件地址检测
func isSpammerAddr(addr net.Addr) bool {
	ipAddress := toIPAddress(addr)
	for _, server := range serverBlocklist {
		_, err := net.LookupHost(ipAddress + server)
		if err == nil {
			return true
		}
	}
	return false
}

//审核地址
func sanitizeAddr(dirty string) string {
	re := regexp.MustCompile("(MAIL|RCPT|Mail) (FROM|TO|From|To|from|to):.*<([^>]+)>")
	subs := re.FindAllStringSubmatch(dirty, 1)
	if subs != nil && len(subs) > 0 && len(subs[0]) == 4 && len(subs[0][3]) > 0 {
		re = regexp.MustCompile("[^a-zA-Z0-9@]+")
		addr := subs[0][3]
		return re.ReplaceAllString(addr, ".")
	} else {
		return defaultAddr
	}
}

func copyFileContents(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	cerr := out.Close()
	if err != nil {
		return err
	}
	return cerr
}

func handleConn(conn net.Conn) {
	defer conn.Close()

	info := fmt.Sprintf("接受来自 %v 的邮件", conn.RemoteAddr())
	if isSpammerAddr(conn.RemoteAddr()) { //远程连接地址是垃圾邮件地址
		info = info + "，疑似垃圾地址"
		if spamDetection { //允许垃圾邮件检测
			info = info + "，丢弃！"
			log.Println(info)
			return
		}
	}
	log.Println(info)

	//建立临时文件接受邮件
	output, err := ioutil.TempFile("/tmp", "MailServer")
	if err != nil {
		fmt.Println(err)
		return
	}
	DEBUG("建立临时文件 " + output.Name() + " 接收邮件")
	defer output.Close()
	defer os.Remove(output.Name())

	var toAddr = defaultAddr
	var fromAddr = defaultAddr

	remoteIP := toIPAddress(conn.RemoteAddr())

	//邮件服务器响应
	DEBUG("服务器响应")
	_, err = conn.Write([]byte(ReplyServiceReady + "\n"))
	if err != nil {
		fmt.Println(err)
		return
	}

	rawData := make([]byte, 1024)
	readingData := false

CommandParse:
	for {

		//获取信息
		bytesRead, err := readCommand(conn, rawData)
		if err != nil {
			break
		}
		output.Write(rawData[:bytesRead])

		if readingData && rawData[0] == '.' {
			readingData = false
		}

		//信息反馈
		if !readingData {
			data := string(rawData[:bytesRead])
			cmd := replyCommand(conn, data) //获取到指令，反馈对方
			DEBUG("获取指令: " + data[:len(data)-1])
			switch cmd {
			case CommandMail:
				fromAddr = sanitizeAddr(data)
				DEBUG("发件邮箱: " + ShowColorPrefix + fromAddr + ShowColorSuffix)
				break
			case CommandRcpt:
				toAddr = sanitizeAddr(data)
				DEBUG("收件邮箱: " + ShowColorPrefix + toAddr + ShowColorSuffix)
				break
			case CommandData:
				readingData = true
				break
			case CommandQuit:
				break CommandParse
			}
		}
	}
	output.Sync()

	stats, err := output.Stat()
	output.Close()
	if err != nil {
		log.Println(err)
		return
	}

	if stats.Size() > 50 {
		messageName := fmt.Sprintf(messageNameFormat, toAddr, fromAddr, remoteIP, time.Now().Unix())
		mailPath := path.Join(outputDirectory, messageName)
		err = copyFileContents(output.Name(), mailPath)
		if err != nil {
			log.Println(err)
			return
		}
		DEBUG("建立邮件文件 " + ShowColorPrefix + mailPath + ShowColorSuffix)
		if runtime.GOOS == "linux" && MailAlter == toAddr {
			cmd := exec.Command("/bin/bash", "-c", "mplayer -really-quiet 'http://tts.baidu.com/text2audio?lan=zh&ie=UTF-8&spd=5&text=有一封来自"+fromAddr+"的邮件'")
			cmd.Run()
		}
	}
}

func main() {

	//非linux则取消显示颜色设置
	if runtime.GOOS != "linux" {
		ShowColorPrefix = ""
		ShowColorSuffix = ""
	}

	flag.StringVar(&outputDirectory, "out", "mail", "邮件输出目录")
	flag.IntVar(&listeningPort, "port", 25, "侦听端口")
	flag.BoolVar(&spamDetection, "spam", true, "垃圾邮件检测")
	flag.BoolVar(&debug, "debug", false, "调试信息")
	flag.StringVar(&badaddr, "bad", "MailBadAddr.txt", "垃圾地址过滤文件")
	flag.StringVar(&MailAlter, "alter", "", "邮件语音提醒")
	flag.Parse()

	log.Printf("侦听端口：%d  垃圾检测: %t  邮件目录: %s  调试信息: %t", listeningPort, spamDetection, outputDirectory, debug)

	err := os.MkdirAll(outputDirectory, 0400) //建立邮件目录
	if err != nil {
		log.Fatal(err)
	}

	ln, err := net.Listen("tcp", ":"+strconv.Itoa(listeningPort))
	if err != nil {
		log.Fatal(err)
	}

	ReadBlocklist() //读取垃圾邮件地址列表
	files, _ := ioutil.ReadDir(outputDirectory)
	log.Printf("获取垃圾地址 %s%d%s 个, 已有邮件 %s%d%s 个", ShowColorPrefix, len(serverBlocklist), ShowColorSuffix, ShowColorPrefix, len(files), ShowColorSuffix)

	log.Println("服务器运行中...")

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println(err)
		}
		go handleConn(conn)
	}
}
