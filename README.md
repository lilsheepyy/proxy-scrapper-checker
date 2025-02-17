# ProxyChecker

**ProxyChecker** is a high-performance Go-based proxy checker that supports **SOCKS4, SOCKS5, and HTTP** proxies. It fetches, sanitizes, and tests proxies against a given target, allowing users to efficiently verify working proxies.

---

## Features

- Supports **SOCKS4, SOCKS5, and HTTP** proxy types  
- Fetches proxies from URLs in a JSON file (`urls.json`)  
- **Concurrency support** with configurable worker limits  
- **Progress tracking** and logging  
- Saves working proxies in **categorized files**  
- Graceful cancellation support using **context**  

---

## Installation

Ensure you have **Go 1.18+** installed.  

```sh
git clone https://github.com/lilsheepyy/proxy-scrapper-checker
cd proxy-scrapper-checker
go run main.go
```


## Options

- -max-checks → Maximum concurrent proxy checks (default: 5000)
- -target → IP and port to test proxies against (default: 1.1.1.1:80)
