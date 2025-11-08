# 🔍 check_domain — Nagios Domain Expiration Plugin

Lightweight cross-platform plugin written in Go.  
Checks when a domain will expire using **RDAP** (ICANN standard) with a **WHOIS fallback**.  
Works with `.com .net .org .ru .info .mobi .game .top .de .fr .pl .es .it` and more.

---

## 📦 Download

| Platform | Arch | Binary | SHA256 |
|:--|:--|:--|:--|
| 🐧 Linux | amd64 | [⬇️ check_domain-linux-amd64](https://github.com/matveynator/check_domain/releases/download/stable/check_domain-linux-amd64) | [📄](https://github.com/matveynator/check_domain/releases/download/stable/check_domain-linux-amd64.sha256) |
| 🐧 Linux | arm64 | [⬇️ check_domain-linux-arm64](https://github.com/matveynator/check_domain/releases/download/stable/check_domain-linux-arm64) | [📄](https://github.com/matveynator/check_domain/releases/download/stable/check_domain-linux-arm64.sha256) |
| 🍎 macOS | amd64 | [⬇️ check_domain-darwin-amd64](https://github.com/matveynator/check_domain/releases/download/stable/check_domain-darwin-amd64) | [📄](https://github.com/matveynator/check_domain/releases/download/stable/check_domain-darwin-amd64.sha256) |
| 🍎 macOS | arm64 | [⬇️ check_domain-darwin-arm64](https://github.com/matveynator/check_domain/releases/download/stable/check_domain-darwin-arm64) | [📄](https://github.com/matveynator/check_domain/releases/download/stable/check_domain-darwin-arm64.sha256) |
| 🪶 FreeBSD | amd64 | [⬇️ check_domain-freebsd-amd64](https://github.com/matveynator/check_domain/releases/download/stable/check_domain-freebsd-amd64) | [📄](https://github.com/matveynator/check_domain/releases/download/stable/check_domain-freebsd-amd64.sha256) |
| 🪶 NetBSD | amd64 | [⬇️ check_domain-netbsd-amd64](https://github.com/matveynator/check_domain/releases/download/stable/check_domain-netbsd-amd64) | [📄](https://github.com/matveynator/check_domain/releases/download/stable/check_domain-netbsd-amd64.sha256) |
| 🪟 Windows | amd64 | [⬇️ check_domain-windows-amd64.exe](https://github.com/matveynator/check_domain/releases/download/stable/check_domain-windows-amd64.exe) | [📄](https://github.com/matveynator/check_domain/releases/download/stable/check_domain-windows-amd64.exe.sha256) |

---

## ⚡ Installation (one command)

**Linux (x86_64):**
```bash
curl -L -o /usr/local/bin/check_domain \
  https://github.com/matveynator/check_domain/releases/download/stable/check_domain-linux-amd64
chmod +x /usr/local/bin/check_domain && check_domain -V
```

**macOS (Apple Silicon):**
```bash
curl -L -o /usr/local/bin/check_domain \
  https://github.com/matveynator/check_domain/releases/download/stable/check_domain-darwin-arm64
chmod +x /usr/local/bin/check_domain && check_domain -V
```

**Windows (PowerShell):**
```powershell
$u="https://github.com/matveynator/check_domain/releases/download/stable/check_domain-windows-amd64.exe"
$d="$env:ProgramFiles\check_domain\check_domain.exe"
New-Item -ItemType Directory -Force -Path (Split-Path $d)|Out-Null
Invoke-WebRequest -Uri $u -OutFile $d; & $d -V
```

---

## ⚙️ Options

| Flag | Description | Default |
|:--|:--|:--|
| `-d` | Domain name (required) | — |
| `-w` | Warning threshold (days) | 30 |
| `-c` | Critical threshold (days) | 7 |
| `-C` | Cache directory | — |
| `-a` | Cache age (days) | 0 |
| `-s` | WHOIS server | auto |
| `-P` | Path to `whois` binary | auto |
| `--timeout` | Timeout (sec) | 20 |
| `-V` | Show version | — |

---

## 🧩 Examples

```bash
check_domain -d example.com
check_domain -d example.org -w 25 -c 10
check_domain -d example.net -C /var/cache/check_domain -a 1
check_domain -d example.ru -s whois.tcinet.ru
```

**Nagios command:**
```
define command{
  command_name check_domain
  command_line /usr/local/bin/check_domain -d $ARG1$ -w 30 -c 7
}
```

---

## 🧾 Output

```
OK - RDAP - Domain example.org will expire in 155 days (2026-04-05)
WARNING - WHOIS - Domain example.com will expire in 12 days (2025-11-20)
CRITICAL - WHOIS - Domain site.ru expired 3 days ago (2025-11-05)
UNKNOWN - Unable to determine expiration date for domain.invalid
```

---

## 🗂 Recommended setup

```bash
sudo mkdir -p /var/cache/check_domain
sudo chown nagios:nagios /var/cache/check_domain
```

Use with Nagios/Icinga for daily checks.  
Static binary — no dependencies, no setup.

