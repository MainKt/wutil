# wutil
A simple WiFi utility CLI powered by `wpa_supplicant`

## Building
### Dependencies
`wutil` depends on [`libkqueue`](https://github.com/mheily/libkqueue)
and [`libbsd`](https://gitlab.freedesktop.org/libbsd/libbsd)

### Build with `gmake`
```console
$ make -f GNUMakefile
```

### Installation
```console
$ make -f GNUMakefile PREFIX=/usr/local install
```

## Usage
### The CLI
```console
$ wutil -h
Usage:  wutil {-h | subcommand [args...]}
        wutil [-c <wpa-ctrl-path>] known-networks
        wutil [-c <wpa-ctrl-path>] {known-network | forget} <ssid>
        wutil [-c <wpa-ctrl-path>] set
          [-p <priority>] [--autoconnect {y | n}] <ssid>
        wutil [-c <wpa-ctrl-path>] {scan | networks | status | disconnect}
        wutil [-c <wpa-ctrl-path>] connect
          [-i <eap-id>] [-p <password>] [-h] <ssid> [password]
```

### The TUI
```console
$ wutui
```
<img width="1694" height="1279" alt="image" src="https://github.com/user-attachments/assets/b100b134-fa9d-45cc-8e96-3115a3b55012" />
