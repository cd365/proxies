> proxies is a proxy tool that supports socks5 and http protocols.

```shell
# for build
git clone https://github.com/cd365/proxies.git
cd cmd/proxies
GOOS=linux GOARCH=amd64 CGO_ENABLED=1 CC=musl-gcc go build -ldflags '-linkmode external -extldflags "-static" -s -w' -o proxies
# start proxy server
proxies -d
```