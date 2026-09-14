package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
)

const (
	maxLength = 512
	trait     = "w6XDp+KIqw=="
)

var (
	version string
	commit  string
	date    string
)

// The request info and password is stored in embed file to be modified dynamically
//
//go:embed data.bin
var content embed.FS

var (
	u         string
	p         string
	totp      bool
	output    string
	nopersist bool

	re      *regexp.Regexp
	notice  *regexp.Regexp
	redir   *regexp.Regexp
	head    *regexp.Regexp
	meta    *regexp.Regexp
	attr    *regexp.Regexp
	refresh *regexp.Regexp
)

func init() {
	re = regexp.MustCompile(`(?s)name="csrf" value="(?P<csrf>.*?)".*name="ip" value="(?P<ip>.*?)"`)
	notice = regexp.MustCompile(`(?s)<div class="notice">(.*?)</div>`)
	redir = regexp.MustCompile(`(?is)window\.location(?:\.href)?\s*=\s*["'](.*?)["']|window\.location\.replace\(\s*["'](.*?)["']\s*\)`)
	head = regexp.MustCompile(`(?is)<head(?:\s[^>]*)?>(.*?)</head\s*>`)
	meta = regexp.MustCompile(`(?is)<meta\b[^>]*>`)
	attr = regexp.MustCompile(`(?is)([a-z_:][-a-z0-9_:.]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>` + "`" + `]+))`)
	refresh = regexp.MustCompile(`(?is)^\s*\d+(?:\.\d+)?\s*;\s*url\s*=\s*(.*?)\s*$`)
}

func parseFlags() {
	flag.StringVar(&u, "u", "", "开启了访问验证的隧道地址, e.g. https://something:12345")
	flag.StringVar(&p, "p", "", "访问验证密码")
	flag.BoolVar(&totp, "totp", false, "访问验证密码")
	flag.BoolVar(&nopersist, "nopersist", false, "不记住认证(将于auth_time后失效)")
	help := flag.Bool("h", false, "显示此帮助信息")

	if runtime.GOOS == "windows" {
		flag.StringVar(&output, "o", "authpass_generated.exe", "生成专用客户端的存放路径")
	} else {
		flag.StringVar(&output, "o", "authpass_generated", "生成专用客户端的存放路径")
	}

	flag.Parse()

	if *help {
		flag.PrintDefaults()
		os.Exit(0)
	}
}

func interactParam() {
	fmt.Printf("您未提供生成参数，请提供下面的参数: \n > 隧道访问地址(如 https://something:12345): ")
	fmt.Scanln(&u)
	u = strings.TrimSpace(u)
	if pu, err := url.Parse(u); err != nil || pu.Scheme != "https" {
		u = "https://" + u
		if _, err = url.Parse(u); err != nil {
			fmt.Println("您提供的隧道访问地址无法解析，请检查输入")
			return
		}
	}

	fmt.Printf(" > 访问验证密码（如只使用 TOTP 功能，请留空）: ")
	fmt.Scanln(&p)
	p = strings.TrimSpace(p)

	var s string

	if p != "" {
		fmt.Printf(" > 是否使用 TOTP(Y/N, 默认为N): ")
		fmt.Scanln(&s)
		totp = strings.ToLower(strings.TrimSpace(s)) == "y"
	} else {
		totp = true
	}

	fmt.Printf(" > 是否记住认证(Y/N, 默认为Y): ")
	fmt.Scanln(&s)
	nopersist = strings.ToLower(strings.TrimSpace(s)) == "n"
}

type data struct {
	Url     string `json:"url"`
	Pass    string `json:"pass"`
	Totp    bool   `json:"totp"`
	Persist bool   `json:"persist"`
}

func parseEmbed() {
	c, _ := content.Open("data.bin")
	buf, _ := io.ReadAll(c)
	t, _ := base64.StdEncoding.DecodeString(trait)
	buf = bytes.TrimPrefix(buf, t)
	buf = buf[:bytes.IndexByte(buf, 0x18)]

	d := data{}
	if err := json.Unmarshal(buf, &d); err != nil {
		fatal("执行失败: 程序已损坏")
	}
	u = d.Url
	p = d.Pass
	totp = d.Totp
	nopersist = !d.Persist
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
		Url:     u,
		Pass:    p,
		Totp:    totp,
		Persist: !nopersist,
	}
	j, err := json.Marshal(d)
	if err != nil {
		fatal("序列化失败:", err)
	}
	if len(j) > maxLength {
		fatal("数据过长，请缩短密码再试")
	}

	copy(c[index:index+maxLength], j)
	c[index+maxLength] = 0x18

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
	parseFlags()
	fmt.Println("===== SakuraFrp AuthPanel GuestTool =====")
	fmt.Printf("version %s\n", version)

	if u == "" || (p == "" && !totp) {
		parseEmbed()
		if u == "" || (p == "" && !totp) {
			interactParam()
			genExe()
			return
		}
	} else {
		genExe()
		return
	}

	uri, _ := url.Parse(u)

	// Set skip tls verify
	tlsConfig := &tls.Config{InsecureSkipVerify: true, MaxVersion: tls.VersionTLS12}

	customTransport := http.DefaultTransport.(*http.Transport).Clone()
	customTransport.TLSClientConfig = tlsConfig
	client := http.Client{Transport: customTransport}
	postClient := client
	postClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}

	// GET authpanel
	resp, err := client.Get(u)
	if err != nil {
		if uri.Port() == "443" || net.ParseIP(uri.Hostname()) != nil {
			fatal("请求", u, "时发生错误，您可能已经通过认证，无需再次认证:", err)
		}

		// retry ip as sni
		fmt.Println("直接请求失败，尝试替代 SNI 请求")
		ips, err2 := net.DefaultResolver.LookupIP(context.Background(), "ip4", uri.Hostname())
		if err2 != nil || len(ips) == 0 {
			fatal("请求", u, "时发生错误:", err, "，并且无法解析域名:", err2)
		}

		tlsConfig.ServerName = ips[0].To4().String()
		resp, err = client.Get(u)
		if err != nil {
			fatal("请求", u, "时发生错误，您可能已经通过认证，无需再次认证:", err)
		}
	}
	res, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		fatal("请求", u, "时发生错误，您可能已经通过认证，无需再次认证:", err)
	}

	// parse to get csrf and ip
	groups := re.FindStringSubmatch(string(res))
	if len(groups) != 3 {
		if resp.Header.Get("Server") != "SakuraFrp-frpc" {
			fatal("解析服务器返回内容时发生错误，您可能已经通过认证，无需再次认证，原始内容:\n\n", string(res), "\n\n解析服务器返回内容时发生错误，您可能已经通过认证，无需再次认证")
		}
		fatal("解析服务器返回内容时发生错误，请尝试更新此程序或使用网页认证")
	}

	// POST authpanel
	form := url.Values{}
	form.Set("csrf", groups[1])
	form.Set("ip", groups[2])
	form.Set("pw", p)
	if totp {
		var s string
		fmt.Printf(" > 请输入 TOTP 一次性密码: ")
		fmt.Scanln(&s)
		form.Set("totp", s)
	}
	if !nopersist {
		form.Set("persist_auth", "on")
	}
	resp, err = postClient.PostForm(u, form)
	if err != nil || resp == nil {
		fatal("提交", u, "时发生错误:", err)
	}
	res, err = io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		fatal("提交", u, "时发生错误:", err)
	}

	if destination := redirDst(resp, res); destination != "" {
		open(destination)
		return
	}

	// parse result
	groups = notice.FindStringSubmatch(string(res))
	if len(groups) != 2 {
		fatal("解析服务器返回内容时发生错误，原始内容:\n", string(res))
	}

	result := strings.TrimSpace(groups[1])
	switch {
	case strings.HasPrefix(result, "认证成功, 正在为您跳转到后续链接"):
		if destination := jsredirDst(resp, res); destination != "" {
			open(destination)
			return
		}
		fallthrough
	case result == "认证成功, 现在可以关闭页面并正常连接隧道了":
		fmt.Println("认证成功, 现在可以正常连接了")
		pressKey()
	default:
		fatal("认证失败，原因:", result)
	}
}

func redirDst(resp *http.Response, body []byte) string {
	if resp.Header.Get("Server") != "SakuraFrp-frpc" {
		return ""
	}

	if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusSeeOther {
		if location := strings.TrimSpace(resp.Header.Get("Location")); location != "" {
			return parseRedir(resp, location)
		}
	}

	content := string(body)
	if match := head.FindStringSubmatch(content); len(match) == 2 {
		for _, tag := range meta.FindAllString(match[1], -1) {
			attributes := make(map[string]string)
			for _, groups := range attr.FindAllStringSubmatch(tag, -1) {
				value := groups[2]
				if value == "" {
					value = groups[3]
				}
				if value == "" {
					value = groups[4]
				}
				attributes[strings.ToLower(groups[1])] = html.UnescapeString(value)
			}
			if strings.EqualFold(strings.TrimSpace(attributes["http-equiv"]), "refresh") {
				if groups := refresh.FindStringSubmatch(attributes["content"]); len(groups) == 2 {
					location := strings.Trim(strings.TrimSpace(groups[1]), `"'`)
					if location != "" {
						return parseRedir(resp, html.UnescapeString(location))
					}
				}
			}
		}
	}

	return ""
}

// Only called after the auth-panel notice confirms successful authentication.
func jsredirDst(resp *http.Response, body []byte) string {
	if resp.Header.Get("Server") != "SakuraFrp-frpc" {
		return ""
	}
	if groups := redir.FindStringSubmatch(string(body)); len(groups) > 0 {
		for _, location := range groups[1:] {
			if location != "" {
				return parseRedir(resp, html.UnescapeString(location))
			}
		}
	}
	return ""
}

func parseRedir(resp *http.Response, location string) string {
	destination, err := url.Parse(strings.TrimSpace(location))
	if err != nil {
		return ""
	}
	if resp != nil && resp.Request != nil && resp.Request.URL != nil {
		destination = resp.Request.URL.ResolveReference(destination)
	}
	return destination.String()
}

func open(url string) {
	var err error
	switch runtime.GOOS {
	case "windows":
		err = exec.Command("explorer", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	default:
		err = errors.New("os not supported")
	}

	if err == nil {
		fmt.Println("认证成功, 已为您打开后续链接")
	} else {
		fmt.Println("认证成功, 未能为您打开后续链接:", err)
	}
	pressKey()
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
