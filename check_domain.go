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

const version = "2.0.0-go"

// ---- CLI flags ----
var (
	flagDomain    string
	flagWarnDays  int
	flagCritDays  int
	flagWhoisPath string
	flagServer    string
	flagCacheAge  int    // days
	flagCacheDir  string // dir
	flagTimeout   int    // seconds (network + whois)
)

const (
	STATE_OK       = 0
	STATE_WARNING  = 1
	STATE_CRITICAL = 2
	STATE_UNKNOWN  = 3
)

// ---- RDAP bootstrap (IANA) ----

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

// Extract "fn" (name) from vcardArray if present
func (e rdapEntity) Name() string {
	// vcardArray format: ["vcard", [ [ "fn", {}, "text", "Registrar Name"], ... ] ]
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

// ---- Utilities ----

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

// ---- Cache helpers ----

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
	if err != nil {
		return nil, false
	}
	if len(b) == 0 {
		return nil, false
	}
	return b, true
}

func writeFileAtomic(path string, data []byte) {
	tmp := path + ".tmp"
	_ = os.WriteFile(tmp, data, 0o644)
	_ = os.Rename(tmp, path)
}

// ---- HTTP client ----
func httpClient(timeoutSec int) *http.Client {
	// Conservative timeouts; no proxies by default.
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

// ---- RDAP logic ----

func tldOf(domain string) (string, error) {
	labels := strings.Split(strings.TrimSpace(strings.ToLower(domain)), ".")
	if len(labels) < 2 {
		return "", errors.New("bad domain")
	}
	return labels[len(labels)-1], nil
}

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
	// fetch fresh
	url := "https://data.iana.org/rdap/dns.json"
	resp, err := httpClient(timeoutSec).Get(url)
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
		// first element is slice of TLDs, second is slice of base URLs
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
	// RFC: domain path is /domain/<fqdn>
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
	// find expiration event
	var exp time.Time
	for _, ev := range d.Events {
		a := strings.ToLower(ev.Action)
		if a == "expiration" || a == "expire" || a == "registration expiration" || a == "expires" {
			if ev.Date.After(exp) {
				exp = ev.Date
			}
		}
	}
	// registrar (if present)
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

// ---- WHOIS fallback ----

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

	// crude timeout via goroutine
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

// A set of practical regexes for dates as seen in the wild.
var dateParsers = []struct {
	re   *regexp.Regexp
	keep int // index of the group to keep
}{
	// ISO-like first
	{regexp.MustCompile(`(?i)\b(Registry Expiry Date|Registrar Registration Expiration Date|Expiration Date|Expiry Date|Expire Date|paid-till|expire|expires|renewal date|Expired|Expiration Time)\s*[:]\s*([0-9]{4}-[0-9]{2}-[0-9]{2})\b`), 2},
	{regexp.MustCompile(`(?i)\b(Expiry date)\s*[:]\s*([0-9]{4}/[0-9]{2}/[0-9]{2})\b`), 2},
	{regexp.MustCompile(`(?i)\b(Expiration date|expire|paid-till)\s*[:]\s*([0-9]{4}\.[0-9]{2}\.[0-9]{2})\b`), 2},
	// With time -> take date part
	{regexp.MustCompile(`(?i)\b(Expiration Date|Expiry Date|Expired|Expiration Time|expires|paid-till)\s*[:]\s*([0-9]{4}-[0-9]{2}-[0-9]{2})[ T]([0-9]{2}:[0-9]{2}:[0-9]{2})`), 2},
	{regexp.MustCompile(`(?i)\b(Expiration Date|Expiry Date|Expired|Expiration Time|expires|paid-till)\s*[:]\s*([0-9]{4}\.[0-9]{2}\.[0-9]{2})[ T]([0-9]{2}:[0-9]{2}:[0-9]{2})`), 2},
	{regexp.MustCompile(`(?i)\b(Expiration Date|Expiry Date|Expired|Expiration Time|expires)\s*[:]\s*([0-9]{4}/[0-9]{2}/[0-9]{2})[ T]([0-9]{2}:[0-9]{2}:[0-9]{2})`), 2},
	// dd-mon-YYYY
	{regexp.MustCompile(`(?i)\b(Expiration Date|Expiry Date|Expire Date)\s*[:]\s*([0-9]{2})-([A-Za-z]{3})-([0-9]{4})`), 0},
	// dd.mm.yyyy
	{regexp.MustCompile(`(?i)\b(expiration date|expire|expires|paid-till)\s*[:]\s*([0-9]{2})\.([0-9]{2})\.([0-9]{4})`), 0},
	// dd/mm/yyyy
	{regexp.MustCompile(`(?i)\b(Expiry Date|expires at)\s*[:]\s*([0-9]{2})/([0-9]{2})/([0-9]{4})`), 0},
	// yyyymmdd
	{regexp.MustCompile(`(?i)\b(expires)\s*[:]\s*([0-9]{4})([0-9]{2})([0-9]{2})\b`), 0},
	// Day Mon DD HH:MM:SS TZ YYYY
	{regexp.MustCompile(`(?i)\b(Expiration Date|Domain Expiration Date)\s*[:]\s*[A-Za-z]{3}\s+([A-Za-z]{3})\s+([0-9]{2})\s+[0-9: ]+\s+[A-Z]+\s+([0-9]{4})`), 0},
}

var mon = map[string]time.Month{
	"jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
	"jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}

func parseDateFlex(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)

	// Try strict YYYY-MM-DD
	if m := regexp.MustCompile(`^([0-9]{4})-([0-9]{2})-([0-9]{2})$`).FindStringSubmatch(s); m != nil {
		y := atoi(m[1])
		M := atoi(m[2])
		d := atoi(m[3])
		return time.Date(y, time.Month(M), d, 0, 0, 0, 0, time.UTC), true
	}
	// YYYY.MM.DD
	if m := regexp.MustCompile(`^([0-9]{4})\.([0-9]{2})\.([0-9]{2})$`).FindStringSubmatch(s); m != nil {
		y := atoi(m[1])
		M := atoi(m[2])
		d := atoi(m[3])
		return time.Date(y, time.Month(M), d, 0, 0, 0, 0, time.UTC), true
	}
	// YYYY/MM/DD
	if m := regexp.MustCompile(`^([0-9]{4})/([0-9]{2})/([0-9]{2})$`).FindStringSubmatch(s); m != nil {
		y := atoi(m[1])
		M := atoi(m[2])
		d := atoi(m[3])
		return time.Date(y, time.Month(M), d, 0, 0, 0, 0, time.UTC), true
	}
	// dd-mon-YYYY
	if m := regexp.MustCompile(`^([0-9]{2})-([A-Za-z]{3})-([0-9]{4})$`).FindStringSubmatch(s); m != nil {
		d := atoi(m[1])
		monStr := strings.ToLower(m[2])
		y := atoi(m[3])
		if mm, ok := mon[monStr]; ok {
			return time.Date(y, mm, d, 0, 0, 0, 0, time.UTC), true
		}
	}
	// dd.mm.yyyy
	if m := regexp.MustCompile(`^([0-9]{2})\.([0-9]{2})\.([0-9]{4})$`).FindStringSubmatch(s); m != nil {
		d := atoi(m[1])
		M := atoi(m[2])
		y := atoi(m[3])
		return time.Date(y, time.Month(M), d, 0, 0, 0, 0, time.UTC), true
	}
	// dd/mm/yyyy
	if m := regexp.MustCompile(`^([0-9]{2})/([0-9]{2})/([0-9]{4})$`).FindStringSubmatch(s); m != nil {
		d := atoi(m[1])
		M := atoi(m[2])
		y := atoi(m[3])
		return time.Date(y, time.Month(M), d, 0, 0, 0, 0, time.UTC), true
	}
	// yyyymmdd
	if m := regexp.MustCompile(`^([0-9]{4})([0-9]{2})([0-9]{2})$`).FindStringSubmatch(s); m != nil {
		y := atoi(m[1])
		M := atoi(m[2])
		d := atoi(m[3])
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
	lines := strings.Split(whoisText, "\n")
	// First try direct regex matches
	for _, pat := range dateParsers {
		m := pat.re.FindStringSubmatch(whoisText)
		if m != nil {
			switch pat.keep {
			case 2:
				if t, ok := parseDateFlex(m[2]); ok {
					return t, nil
				}
			case 0:
				// reconstruct depending on pattern
				// We handle in subsequent code with line scanning
			}
		}
	}
	// Line-by-line flexible attempts
	for _, ln := range lines {
		low := strings.ToLower(ln)
		if !strings.Contains(low, "expir") && !strings.Contains(low, "paid-till") && !strings.Contains(low, "valid-date") && !strings.Contains(low, "expire-date") && !strings.Contains(low, "renewal date") {
			continue
		}
		// Extract probable date token(s)
		clean := strings.TrimSpace(strings.Trim(strings.SplitN(ln, ":", 2)[len(strings.SplitN(ln, ":", 2))-1], "\r"))
		clean = strings.TrimSpace(clean)
		// take first token that looks date-ish
		toks := strings.Fields(clean)
		for _, tok := range toks {
			if t, ok := parseDateFlex(tok); ok {
				return t, nil
			}
			// dd-mon-YYYY glued with time
			if i := strings.Index(tok, "T"); i > 0 {
				if t, ok := parseDateFlex(tok[:i]); ok {
					return t, nil
				}
			}
		}
		// try whole line
		for _, tok := range []string{clean} {
			if t, ok := parseDateFlex(tok); ok {
				return t, nil
			}
		}
	}
	// Some registries put "No match" or "NOT FOUND"
	if strings.Contains(strings.ToUpper(whoisText), "NO MATCH") ||
		strings.Contains(strings.ToUpper(whoisText), "NOT FOUND") ||
		strings.Contains(strings.ToUpper(whoisText), "NO DOMAIN") {
		return time.Time{}, errors.New("domain does not exist")
	}
	return time.Time{}, errors.New("unable to parse WHOIS expiration")
}

// rough registrar fetch from WHOIS (best effort)
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

// ---- Main check flow ----

type result struct {
	Exp       time.Time
	Registrar string
	Source    string // RDAP or WHOIS
}

func check(domain string) (result, error) {
	// 1) RDAP via IANA bootstrap
	var res result
	boot, err := fetchIANAbootstrap(flagCacheDir, flagCacheAge, flagTimeout)
	if err == nil {
		if tld, e2 := tldOf(domain); e2 == nil {
			servers := rdapServersForTLD(boot, tld)
			// Try servers in order
			for _, base := range servers {
				// Cache per-domain RDAP if requested
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
	// 2) WHOIS fallback
	cfg := whoisConfig{
		Path:   flagWhoisPath,
		Server: flagServer,
		TO:     time.Duration(flagTimeout) * time.Second,
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

// ---- main ----

func main() {
	// Support both short and GNU-like options
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

	// Not expired yet
	if days >= 0 {
		if days < flagCritDays {
			die(STATE_CRITICAL, fmt.Sprintf("CRITICAL - %sDomain %s will expire in %d days (%s).%s", prefix, flagDomain, days, expDate, info))
		}
		if days < flagWarnDays {
			die(STATE_WARNING, fmt.Sprintf("WARNING - %sDomain %s will expire in %d days (%s).%s", prefix, flagDomain, days, expDate, info))
		}
		die(STATE_OK, fmt.Sprintf("OK - %sDomain %s will expire in %d days (%s).%s", prefix, flagDomain, days, expDate, info))
	}

	// Already expired
	if days < flagCritDays {
		die(STATE_CRITICAL, fmt.Sprintf("CRITICAL - %sDomain %s expired %d days ago (%s).%s", prefix, flagDomain, -days, expDate, info))
	}
	if days < flagWarnDays {
		die(STATE_WARNING, fmt.Sprintf("WARNING - %sDomain %s expired %d days ago (%s).%s", prefix, flagDomain, -days, expDate, info))
	}
	die(STATE_OK, fmt.Sprintf("OK - %sDomain %s expired %d days ago (%s).%s", prefix, flagDomain, -days, expDate, info))
}

