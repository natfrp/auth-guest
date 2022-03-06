package main

import (
	"bytes"
	"crypto/tls"
	"embed"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
)

const (
	maxLength = 160
	trait     = "w6XDp+KIqw=="
)

var (
	version string
	commit  string
	date    string
)

// The request info and password is stored in embed file to be modified dynamically
//go:embed data.txt
var content embed.FS

var (
	u       string
	p       string
	output  string
	persist bool

	re     *regexp.Regexp
	notice *regexp.Regexp
)

func init() {
	re = regexp.MustCompile(`(?s)name="csrf" value="(?P<csrf>.*?)".*name="ip" value="(?P<ip>.*?)"`)
	notice = regexp.MustCompile(`(?s)<div class="notice">(.*?)</div>`)

	flag.StringVar(&u, "u", "", "开启了访问验证的隧道地址, e.g. https://something:12345")
	flag.StringVar(&p, "p", "", "访问验证密码")
	flag.BoolVar(&persist, "nopersist", false, "不记住认证(将于auth_time后失效)")
	flag.StringVar(&output, "o", "authpass_generated.exe", "生成专用客户端的存放路径")
	help := flag.Bool("h", false, "显示此帮助信息")
	flag.Parse()

	if *help {
		flag.PrintDefaults()
		os.Exit(0)
	}
}

type data struct {
	Url  string `json:"url"`
	Pass string `json:"pass"`
}

func parseEmbed() {
	c, _ := content.Open("data.txt")
	buf, _ := io.ReadAll(c)
	t, _ := base64.StdEncoding.DecodeString(trait)
	buf = bytes.TrimPrefix(buf, t)
	buf = buf[:bytes.IndexByte(buf, '}')+1]

	d := data{}
	if err := json.Unmarshal(buf, &d); err != nil {
		fatal("执行失败: 程序已损坏")
	}
	u = d.Url
	p = d.Pass
}

func genExe() {
	selfPath, err := os.Executable()
	if err != nil {
		fatal("载入程序失败:", err)
	}
	self, err := os.OpenFile(selfPath, os.O_RDONLY, os.ModePerm)
	if err != nil {
		fatal("载入程序失败:", err)
	}
	c, err := io.ReadAll(self)
	if err != nil {
		fatal("载入程序失败:", err)
	}

	t, _ := base64.StdEncoding.DecodeString(trait)
	index := bytes.Index(c, t)
	if index == -1 {
		fatal("处理失败: 程序已损坏")
	}
	index += len(t)

	d := data{
		Url:  u,
		Pass: p,
	}
	j, err := json.Marshal(d)
	if err != nil {
		fatal("序列化失败:", err)
	}
	if len(j) > maxLength {
		fatal("数据过长，请缩短密码再试")
	}

	copy(c[index:index+maxLength], j)

	out, err := os.Create(output)
	if err != nil {
		fatal("创建文件失败:", err)
	}
	n, err := out.Write(c)
	if err != nil {
		fatal("写入可执行文件失败:", err)
	}
	out.Close()
	fmt.Printf("文件生成成功，%d 字节已写入\n", n)
	pressKey()
}

func main() {
	fmt.Println("===== SakuraFrp AuthPanel GuestTool =====")
	fmt.Printf("version %s @ %s, %s\n", version, commit, date)

	if u == "" || p == "" {
		parseEmbed()
		if u == "" || p == "" {
			flag.PrintDefaults()
			return
		}
	} else {
		genExe()
		return
	}

	// Set skip tls verify
	tlsConfig := &tls.Config{InsecureSkipVerify: true}
	customTransport := http.DefaultTransport.(*http.Transport).Clone()
	customTransport.TLSClientConfig = tlsConfig
	client := http.Client{Transport: customTransport}

	// GET authpanel
	resp, err := client.Get(u)
	if err != nil {
		fatal("请求", u, "时发生错误:", err)
	}
	res, err := io.ReadAll(resp.Body)
	if err != nil {
		fatal("请求", u, "时发生错误:", err)
	}

	// parse to get csrf and ip
	groups := re.FindStringSubmatch(string(res))
	if len(groups) != 3 {
		fatal("解析服务器返回内容时发生错误，原始内容:\n", string(res))
	}

	// POST authpanel
	form := url.Values{}
	form.Set("csrf", groups[1])
	form.Set("ip", groups[2])
	form.Set("pw", p)
	resp, err = client.PostForm(u, form)
	if err != nil {
		fatal("提交", u, "时发生错误:", err)
	}
	res, err = io.ReadAll(resp.Body)
	if err != nil {
		fatal("提交", u, "时发生错误:", err)
	}

	// parse result
	groups = notice.FindStringSubmatch(string(res))
	if len(groups) != 2 {
		fatal("解析服务器返回内容时发生错误，原始内容:\n", string(res))
	}

	result := strings.TrimSpace(groups[1])
	if result == "认证成功, 现在可以关闭页面并正常连接隧道了" {
		fmt.Println("认证成功, 现在可以正常连接了")
		pressKey()
	} else {
		fatal("认证失败，原因:", result)
	}
}

func fatal(things ...interface{}) {
	fmt.Println(things...)
	pressKey()
	os.Exit(1)
}

func pressKey() {
	fmt.Println("===== 按任意键继续 =====")
	b := make([]byte, 1)
	os.Stdin.Read(b)
}
