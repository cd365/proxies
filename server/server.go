package main

import (
	"flag"
	"fmt"
	"github.com/cd365/proxies"
	"os"
	"os/exec"
)

var (
	// daemon Background run.
	daemon bool

	// listen Proxy server listen address.
	listen string

	// proxy Next level proxy address.
	proxy string
)

func main() {
	flag.BoolVar(&daemon, "d", false, "daemon run")
	flag.StringVar(&listen, "l", ":1080", "proxy server listen address")
	flag.StringVar(&proxy, "t", "", "next level proxy address")
	flag.Parse()
	if daemon {
		args := os.Args[1:]
		length := len(args)
		for i := 0; i < length; i++ {
			if args[i] == "-d" {
				args[i] = "-d=false"
				break
			}
		}
		cmd := exec.Command(os.Args[0], args...)
		if err := cmd.Start(); err != nil {
			fmt.Println(err.Error())
			return
		}
		fmt.Println("pid", cmd.Process.Pid)
		return
	}

	app := proxies.NewProxy()
	if proxy != "" {
		app.ProxyAddress = &proxy
	}
	if err := app.Listen(listen); err != nil {
		fmt.Println(err.Error())
	}
}
