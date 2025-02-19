# ProxyChecker

**ProxyChecker** is a high-performance Go-based proxy checker that supports **SOCKS4, SOCKS5, and HTTP** proxies. It fetches, sanitizes, and tests proxies against a given target, allowing users to efficiently verify working proxies.

With the ability to **scrape approximately 350,000 proxies per type**, ProxyChecker ensures a vast selection of proxies to work with.

---

## Features

- Supports **SOCKS4, SOCKS5, and HTTP** proxy types  
- Fetches proxies from URLs in a JSON file (`urls.json`)  
- **Concurrency support** with configurable worker limits  
- **Progress tracking** and logging  
- Saves working proxies in **categorized files**  
- Graceful cancellation support using **context**
- Silly cat when running

---

## Installation

Ensure you have **Go 1.18+** installed.  

```sh
git clone https://github.com/lilsheepyy/proxy-scrapper-checker
cd proxy-scrapper-checker
go run main.go
```


## Options

- -max-checks → Maximum concurrent proxy checks (default: 1000) I recommend lowering this for a better output even if it takes more time, this also depends on your server
- -target → IP and port to test proxies against (default: 1.1.1.1:80)
- -timeout → Timeout in seconds for proxy connections

## Example
```sh
go run main.go -target 1.1.1.1:80 -max-checks 1000 -timeout 5
```
IF YOU ARE GETTING 5 PROXIES WORKING, LOWER YOUR SETTINGS

## TODO
- Make a better sanitization system
- Anything else that I think off

Thanks for using!
