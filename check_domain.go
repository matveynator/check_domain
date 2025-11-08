// check_domain: Nagios/Icinga plugin to check domain expiration using RDAP with WHOIS fallback.
// Exit codes: 0 OK, 1 WARNING, 2 CRITICAL, 3 UNKNOWN.

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const version = "2.1.1-go-stable"

const (
	STATE_OK       = 0
	STATE_WARNING  = 1
	STATE_CRITICAL = 2
	STATE_UNKNOWN  = 3
)

var (
	flagDomain    string
	flagWarnDays  int
	flagCritDays  int
	flagWhoisPath string
	flagServer    string
	flagCacheAge  int
	flagCacheDir  string
	flagTimeout   int
)

// ---------- RDAP bootstrap (IANA) ----------

type ianaBootstrap struct {
	Services [][]interface{} `json:"services"`
}

type rdapDomain struct {
	Events   []rdapEvent  `json:"events"`
	Entities []rdapEntity `json:"entities"`
}

type rdapEvent struct {
	Action string    `json:"eventAction"`
	Date   time.Time `json:"eventDate"`
}

type rdapEntity struct {
	Roles      []string        `json:"roles"`
	VCardArray []interface{}   `json:"vcardArray"`
	Handle     string          `json:"handle"`
	Raw        json.RawMessage `json:"-"`
}

func (e rdapEntity) Name() string {
	if len(e.VCardArray) != 2 {
		return ""
	}
	items, ok := e.VCardArray[1].([]interface{})
	if !ok {
		return ""
	}
	for _, it := range items {
		row, ok := it.([]interface{})
		if !ok || len(row) < 4 {
			continue
		}
		prop, _ := row[0].(string)
		if prop == "fn" {
			if txt, ok := row[3].(string); ok {
				return strings.TrimSpace(txt)
			}
		}
	}
	return ""
}

// ---------- Defaults for problematic TLDs (RDAP/WHOIS) ----------

var tldDefaultRDAP = map[string]string{
	"co": "https://rdap.nic.co",
}

var tldDefaultWHOIS = map[string]string{
	"co": "whois.nic.co",
}

// ---------- Utils ----------

func die(rc int, msg string) {
	fmt.Println(msg)
	os.Exit(rc)
}

func usage() {
	fmt.Printf("check_domain v%s (Go)\n", version)
	fmt.Println("Usage: check_domain -d <domain> [-w <days>] [-c <days>] [-P <whois_path>] [-s <server>] [-a <cache_age_days>] [-C <cache_dir>] [--timeout <seconds>] [-V]")
}

func setDefaults() {
	if flagWarnDays == 0 {
		flagWarnDays = 30
	}
	if flagCritDays == 0 {
		flagCritDays = 7
	}
	if flagTimeout <= 0 {
		flagTimeout = 20
	}
}

func tldOf(domain string) (string, error) {
	labels := strings.Split(strings.TrimSpace(strings.ToLower(domain)), ".")
	if len(labels) < 2 {
		return "", errors.New("bad domain")
	}
	return labels[len(labels)-1], nil
}

// cache helpers
func isFresh(path string, maxAgeDays int) bool {
	if maxAgeDays <= 0 {
		return false
	}
	st, err := os.Stat(path)
	if err != nil {
		return false
	}
	maxAge := time.Duration(maxAgeDays) * 24 * time.Hour
	return time.Since(st.ModTime()) < maxAge
}

func readIfFresh(path string, maxAgeDays int) ([]byte, bool) {
	if !isFresh(path, maxAgeDays) {
		return nil, false
	}
	b, err := os.ReadFile(path)
	if err != nil || len(b) == 0 {
		return nil, false
	}
	return b, true
}

func writeFileAtomic(path string, data []byte) {
	tmp := path + ".tmp"
	_ = os.WriteFile(tmp, data, 0o644)
	_ = os.Rename(tmp, path)
}

// HTTP client
func httpClient(timeoutSec int) *http.Client {
	return &http.Client{
		Timeout: time.Duration(timeoutSec) * time.Second,
		Transport: &http.Transport{
			Proxy: nil,
			DialContext: (&net.Dialer{
				Timeout:   time.Duration(timeoutSec) * time.Second,
				KeepAlive: 15 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: time.Duration(timeoutSec) * time.Second,
			ExpectContinueTimeout: 2 * time.Second,
		},
	}
}

// RDAP bootstrap
func rdapBootstrapPath(cacheDir string) string {
	if cacheDir == "" {
		return ""
	}
	return filepath.Join(cacheDir, "rdap_bootstrap_dns.json")
}

func fetchIANAbootstrap(cacheDir string, cacheAgeDays int, timeoutSec int) (*ianaBootstrap, error) {
	var b []byte
	var ok bool
	path := rdapBootstrapPath(cacheDir)
	if path != "" {
		if b, ok = readIfFresh(path, cacheAgeDays); ok {
			var boot ianaBootstrap
			if json.Unmarshal(b, &boot) == nil {
				return &boot, nil
			}
		}
	}
	resp, err := httpClient(timeoutSec).Get("https://data.iana.org/rdap/dns.json")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("IANA bootstrap HTTP %d", resp.StatusCode)
	}
	b, err = io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var boot ianaBootstrap
	if err := json.Unmarshal(b, &boot); err != nil {
		return nil, err
	}
	if path != "" {
		writeFileAtomic(path, b)
	}
	return &boot, nil
}

func rdapServersForTLD(boot *ianaBootstrap, tld string) []string {
	tld = strings.ToLower(tld)
	var out []string
	for _, svc := range boot.Services {
		if len(svc) < 2 {
			continue
		}
		left, _ := svc[0].([]interface{})
		right, _ := svc[1].([]interface{})
		match := false
		for _, x := range left {
			if s, ok := x.(string); ok && strings.EqualFold(s, tld) {
				match = true
				break
			}
		}
		if !match {
			continue
		}
		for _, y := range right {
			if u, ok := y.(string); ok {
				out = append(out, strings.TrimRight(u, "/"))
			}
		}
	}
	return out
}

func rdapFetchDomain(base, domain string, timeoutSec int) ([]byte, *http.Response, error) {
	url := fmt.Sprintf("%s/domain/%s", strings.TrimRight(base, "/"), domain)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Accept", "application/rdap+json, application/json;q=0.9, */*;q=0.1")
	resp, err := httpClient(timeoutSec).Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return body, resp, fmt.Errorf("RDAP HTTP %d", resp.StatusCode)
	}
	return body, resp, nil
}

func parseRDAPExpiration(body []byte) (time.Time, string, error) {
	var d rdapDomain
	if err := json.Unmarshal(body, &d); err != nil {
		return time.Time{}, "", err
	}
	var exp time.Time
	for _, ev := range d.Events {
		a := strings.ToLower(ev.Action)
		if a == "expiration" || a == "expire" || a == "registration expiration" || a == "expires" {
			if ev.Date.After(exp) {
				exp = ev.Date
			}
		}
	}
	var registrar string
	for _, ent := range d.Entities {
		for _, r := range ent.Roles {
			if strings.ToLower(r) == "registrar" {
				if name := ent.Name(); name != "" {
					registrar = name
					break
				}
				if ent.Handle != "" {
					registrar = ent.Handle
				}
			}
		}
		if registrar != "" {
			break
		}
	}
	if exp.IsZero() {
		return time.Time{}, registrar, errors.New("no RDAP expiration event")
	}
	return exp, registrar, nil
}

// ---------- WHOIS fallback ----------

type whoisConfig struct {
	Path   string
	Server string
	TO     time.Duration
}

func runWhois(cfg whoisConfig, domain string) ([]byte, error) {
	path := cfg.Path
	if path == "" {
		path = "whois"
	}
	args := []string{}
	if cfg.Server != "" {
		args = append(args, "-h", cfg.Server)
	}
	args = append(args, domain)

	cmd := exec.Command(path, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	errCh := make(chan error, 1)
	go func() { errCh <- cmd.Run() }()
	select {
	case err := <-errCh:
		if out.Len() == 0 && err != nil {
			return nil, err
		}
		return out.Bytes(), nil
	case <-time.After(cfg.TO):
		_ = cmd.Process.Kill()
		return nil, errors.New("whois timeout")
	}
}

// Паттерны для WHOIS
var dateParsers = []struct {
	re   *regexp.Regexp
	keep int
}{
	// ISO (берём только YYYY-MM-DD, остальное игнорируем)
	{regexp.MustCompile(`(?i)\bRegistry\s+Expiry\s+Date\s*:\s*([0-9]{4}-[0-9]{2}-[0-9]{2})(?:[ T].*)?`), 1},
	{regexp.MustCompile(`(?i)\bRegistrar\s+Registration\s+Expiration\s+Date\s*:\s*([0-9]{4}-[0-9]{2}-[0-9]{2})(?:[ T].*)?`), 1},
	{regexp.MustCompile(`(?i)\b(Expiration|Expiry|Expire)\s*(Date|Time)?\s*:\s*([0-9]{4}-[0-9]{2}-[0-9]{2})(?:[ T].*)?`), 3},
	{regexp.MustCompile(`(?i)\bpaid-till\s*:\s*([0-9]{4}-[0-9]{2}-[0-9]{2})(?:[ T].*)?`), 1},

	// Остальные — вручную
	{regexp.MustCompile(`(?i)\b(Expiration|Expiry|Expire)\s*(Date|Time)?\s*:\s*([0-9]{2})-([A-Za-z]{3})-([0-9]{4})`), 0}, // dd-mon-YYYY
	{regexp.MustCompile(`(?i)\b(Expiration|Expiry|Expire|paid-till)\s*:\s*([0-9]{2})\.([0-9]{2})\.([0-9]{4})`), 0},    // dd.mm.yyyy
	{regexp.MustCompile(`(?i)\b(Expiration|Expiry|Expire)\s*:\s*([0-9]{2})/([0-9]{2})/([0-9]{4})`), 0},               // dd/mm/yyyy
	{regexp.MustCompile(`(?i)\bexpires\s*:\s*([0-9]{4})([0-9]{2})([0-9]{2})\b`), 0},                                  // yyyymmdd
}

var mon = map[string]time.Month{
	"jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
	"jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}

func parseDateFlex(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	// YYYY-MM-DD
	if m := regexp.MustCompile(`^([0-9]{4})-([0-9]{2})-([0-9]{2})$`).FindStringSubmatch(s); m != nil {
		y, M, d := atoi(m[1]), atoi(m[2]), atoi(m[3])
		return time.Date(y, time.Month(M), d, 0, 0, 0, 0, time.UTC), true
	}
	// YYYY.MM.DD
	if m := regexp.MustCompile(`^([0-9]{4})\.([0-9]{2})\.([0-9]{2})$`).FindStringSubmatch(s); m != nil {
		y, M, d := atoi(m[1]), atoi(m[2]), atoi(m[3])
		return time.Date(y, time.Month(M), d, 0, 0, 0, 0, time.UTC), true
	}
	// YYYY/MM/DD
	if m := regexp.MustCompile(`^([0-9]{4})/([0-9]{2})/([0-9]{2})$`).FindStringSubmatch(s); m != nil {
		y, M, d := atoi(m[1]), atoi(m[2]), atoi(m[3])
		return time.Date(y, time.Month(M), d, 0, 0, 0, 0, time.UTC), true
	}
	// dd-mon-YYYY
	if m := regexp.MustCompile(`^([0-9]{2})-([A-Za-z]{3})-([0-9]{4})$`).FindStringSubmatch(s); m != nil {
		d, monStr, y := atoi(m[1]), strings.ToLower(m[2]), atoi(m[3])
		if mm, ok := mon[monStr]; ok {
			return time.Date(y, mm, d, 0, 0, 0, 0, time.UTC), true
		}
	}
	// dd.mm.yyyy
	if m := regexp.MustCompile(`^([0-9]{2})\.([0-9]{2})\.([0-9]{4})$`).FindStringSubmatch(s); m != nil {
		d, M, y := atoi(m[1]), atoi(m[2]), atoi(m[3])
		return time.Date(y, time.Month(M), d, 0, 0, 0, 0, time.UTC), true
	}
	// dd/mm/yyyy
	if m := regexp.MustCompile(`^([0-9]{2})/([0-9]{2})/([0-9]{4})$`).FindStringSubmatch(s); m != nil {
		d, M, y := atoi(m[1]), atoi(m[2]), atoi(m[3])
		return time.Date(y, time.Month(M), d, 0, 0, 0, 0, time.UTC), true
	}
	// yyyymmdd
	if m := regexp.MustCompile(`^([0-9]{4})([0-9]{2})([0-9]{2})$`).FindStringSubmatch(s); m != nil {
		y, M, d := atoi(m[1]), atoi(m[2]), atoi(m[3])
		return time.Date(y, time.Month(M), d, 0, 0, 0, 0, time.UTC), true
	}
	return time.Time{}, false
}

func atoi(s string) int {
	n := 0
	for _, r := range s {
		if r >= '0' && r <= '9' {
			n = n*10 + int(r-'0')
		}
	}
	return n
}

func parseWhoisExpiration(whoisText string) (time.Time, error) {
	// 1) точечные «ISO» группы
	for _, pat := range dateParsers {
		m := pat.re.FindStringSubmatch(whoisText)
		if m == nil {
			continue
		}
		switch pat.keep {
		case 1, 2, 3, 4, 5:
			if t, ok := parseDateFlex(m[pat.keep]); ok {
				return t, nil
			}
		case 0:
			// разбираем ниже
		}
	}

	// 2) общий проход по строкам с «expir|paid-till|renewal»
	lines := strings.Split(whoisText, "\n")
	for _, ln := range lines {
		low := strings.ToLower(ln)
		if !(strings.Contains(low, "expir") ||
			strings.Contains(low, "paid-till") ||
			strings.Contains(low, "valid-date") ||
			strings.Contains(low, "expire-date") ||
			strings.Contains(low, "renewal")) {
			continue
		}
		clean := ln
		if idx := strings.Index(clean, ":"); idx >= 0 && idx+1 < len(clean) {
			clean = clean[idx+1:]
		}
		clean = strings.TrimSpace(strings.Trim(clean, "\r"))
		// токены
		toks := strings.Fields(clean)
		for _, tok := range toks {
			// отрезаем время/таймзону
			if i := strings.IndexAny(tok, "T "); i > 0 {
				if t, ok := parseDateFlex(tok[:i]); ok {
					return t, nil
				}
			}
			if t, ok := parseDateFlex(tok); ok {
				return t, nil
			}
		}
		// попробовать целиком
		if t, ok := parseDateFlex(clean); ok {
			return t, nil
		}
	}

	// 3) «супер-липкий» глобальный поиск: любая дата после ключа expir*
	reSticky := regexp.MustCompile(`(?is)expir[\w\s:/-]*?([0-9]{4}[-./][0-9]{2}[-./][0-9]{2})`)
	if m := reSticky.FindStringSubmatch(whoisText); m != nil {
		// нормализуем разделители в YYYY-MM-DD
		date := strings.NewReplacer(".", "-", "/", "-").Replace(m[1])
		if t, ok := parseDateFlex(date); ok {
			return t, nil
		}
	}

	// «не найден»?
	up := strings.ToUpper(whoisText)
	if strings.Contains(up, "NO MATCH") || strings.Contains(up, "NOT FOUND") || strings.Contains(up, "NO DOMAIN") {
		return time.Time{}, errors.New("domain does not exist")
	}
	return time.Time{}, errors.New("unable to parse WHOIS expiration")
}

func parseWhoisRegistrar(whoisText string) string {
	for _, key := range []string{"Registrar:", "registrar:", "Sponsoring Registrar:"} {
		if i := strings.Index(whoisText, key); i >= 0 {
			line := whoisText[i+len(key):]
			if j := strings.Index(line, "\n"); j >= 0 {
				line = line[:j]
			}
			return strings.TrimSpace(line)
		}
	}
	return ""
}

// ---------- Main check flow ----------

type result struct {
	Exp       time.Time
	Registrar string
	Source    string // RDAP | WHOIS
}

func check(domain string) (result, error) {
	var res result

	// 1) RDAP via IANA
	if boot, err := fetchIANAbootstrap(flagCacheDir, flagCacheAge, flagTimeout); err == nil {
		if t, e2 := tldOf(domain); e2 == nil {
			servers := rdapServersForTLD(boot, t)
			for _, base := range servers {
				cachePath := ""
				if flagCacheDir != "" {
					cachePath = filepath.Join(flagCacheDir, "rdap_"+strings.ReplaceAll(domain, ".", "_")+".json")
				}
				var body []byte
				var ok bool
				if cachePath != "" {
					if b, ok2 := readIfFresh(cachePath, flagCacheAge); ok2 {
						body = b
						ok = true
					}
				}
				if !ok {
					b, _, err := rdapFetchDomain(base, domain, flagTimeout)
					if err != nil || len(b) == 0 {
						continue
					}
					body = b
					if cachePath != "" {
						writeFileAtomic(cachePath, body)
					}
				}
				exp, reg, err := parseRDAPExpiration(body)
				if err == nil && !exp.IsZero() {
					res.Exp = exp.UTC()
					res.Registrar = reg
					res.Source = "RDAP"
					return res, nil
				}
			}
		}
	}

	// 1a) RDAP fallback by TLD defaults (e.g., .co)
	if t, e2 := tldOf(domain); e2 == nil {
		if base, ok := tldDefaultRDAP[strings.ToLower(t)]; ok {
			if b, _, err := rdapFetchDomain(base, domain, flagTimeout); err == nil && len(b) > 0 {
				if exp, reg, err := parseRDAPExpiration(b); err == nil && !exp.IsZero() {
					return result{Exp: exp.UTC(), Registrar: reg, Source: "RDAP"}, nil
				}
			}
		}
	}

	// 2) WHOIS fallback
	cfg := whoisConfig{
		Path:   flagWhoisPath,
		Server: flagServer,
		TO:     time.Duration(flagTimeout) * time.Second,
	}
	if cfg.Server == "" {
		if t, e2 := tldOf(domain); e2 == nil {
			if def, ok := tldDefaultWHOIS[strings.ToLower(t)]; ok {
				cfg.Server = def
			}
		}
	}

	var whoisText string
	cachePath := ""
	if flagCacheDir != "" {
		cachePath = filepath.Join(flagCacheDir, "whois_"+strings.ReplaceAll(domain, ".", "_")+".txt")
	}
	if b, ok := readIfFresh(cachePath, flagCacheAge); ok {
		whoisText = string(b)
	} else {
		b, err := runWhois(cfg, domain)
		if err != nil {
			return res, fmt.Errorf("WHOIS error: %v", err)
		}
		whoisText = string(b)
		if cachePath != "" {
			writeFileAtomic(cachePath, []byte(whoisText))
		}
	}

	exp, err := parseWhoisExpiration(whoisText)
	if err != nil {
		return res, err
	}
	res.Exp = exp.UTC()
	res.Registrar = parseWhoisRegistrar(whoisText)
	res.Source = "WHOIS"
	return res, nil
}

// ---------- main ----------

func main() {
	showHelp := false
	showVersion := false

	flag.StringVar(&flagDomain, "d", "", "domain to check")
	flag.StringVar(&flagDomain, "domain", "", "")
	flag.IntVar(&flagWarnDays, "w", 30, "warning threshold (days)")
	flag.IntVar(&flagWarnDays, "warning", 30, "")
	flag.IntVar(&flagCritDays, "c", 7, "critical threshold (days)")
	flag.IntVar(&flagCritDays, "critical", 7, "")
	flag.StringVar(&flagWhoisPath, "P", "", "path to whois binary")
	flag.StringVar(&flagWhoisPath, "path", "", "")
	flag.StringVar(&flagServer, "s", "", "force specific WHOIS server")
	flag.StringVar(&flagServer, "server", "", "")
	flag.IntVar(&flagCacheAge, "a", 0, "cache age (days)")
	flag.IntVar(&flagCacheAge, "cache-age", 0, "")
	flag.StringVar(&flagCacheDir, "C", "", "cache dir")
	flag.StringVar(&flagCacheDir, "cache-dir", "", "")
	flag.IntVar(&flagTimeout, "timeout", 20, "network/WHOIS timeout seconds")

	flag.BoolVar(&showHelp, "h", false, "help")
	flag.BoolVar(&showHelp, "help", false, "")
	flag.BoolVar(&showVersion, "V", false, "version")
	flag.BoolVar(&showVersion, "version", false, "")

	flag.Parse()
	setDefaults()

	if showHelp {
		usage()
		os.Exit(0)
	}
	if showVersion {
		fmt.Printf("check_domain - v%s\n", version)
		os.Exit(0)
	}
	if flagDomain == "" {
		die(STATE_UNKNOWN, "UNKNOWN - There is no domain name to check")
	}

	res, err := check(flagDomain)
	if err != nil {
		die(STATE_UNKNOWN, fmt.Sprintf("UNKNOWN - Unable to figure out expiration date for %s. %v", flagDomain, err))
	}

	now := time.Now().UTC()
	diff := res.Exp.Sub(now)
	days := int(diff.Hours() / 24)
	expDate := res.Exp.Format("2006-01-02")

	info := ""
	if res.Registrar != "" {
		info = " " + res.Registrar
	}
	prefix := ""
	if res.Source != "" {
		prefix = res.Source + " - "
	}

	if days >= 0 {
		if days < flagCritDays {
			die(STATE_CRITICAL, fmt.Sprintf("CRITICAL - %sDomain %s will expire in %d days (%s).%s", prefix, flagDomain, days, expDate, info))
		}
		if days < flagWarnDays {
			die(STATE_WARNING, fmt.Sprintf("WARNING - %sDomain %s will expire in %d days (%s).%s", prefix, flagDomain, days, expDate, info))
		}
		die(STATE_OK, fmt.Sprintf("OK - %sDomain %s will expire in %d days (%s).%s", prefix, flagDomain, days, expDate, info))
	}

	if days < flagCritDays {
		die(STATE_CRITICAL, fmt.Sprintf("CRITICAL - %sDomain %s expired %d days ago (%s).%s", prefix, flagDomain, -days, expDate, info))
	}
	if days < flagWarnDays {
		die(STATE_WARNING, fmt.Sprintf("WARNING - %sDomain %s expired %d days ago (%s).%s", prefix, flagDomain, -days, expDate, info))
	}
	die(STATE_OK, fmt.Sprintf("OK - %sDomain %s expired %d days ago (%s).%s", prefix, flagDomain, -days, expDate, info))
}
