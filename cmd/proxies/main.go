package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"

	"github.com/cd365/proxies"
)

var (
	// daemon Background run.
	daemon bool

	// listen Program listen address.
	listen string

	// serverMode Is server mode.
	serverMode bool

	// username Client mode auth username.
	username string

	// password Client mode auth password.
	password string

	// remoteAddress Proxy server address.
	remoteAddress string

	// remoteSecret Auth connect server secret.
	remoteSecret string
)

func main() {
	flag.BoolVar(&daemon, "d", false, "daemon run")
	flag.StringVar(&listen, "l", ":1080", "proxy listen address")
	flag.BoolVar(&serverMode, "r", false, "server mode")
	flag.StringVar(&username, "u", "", "client mode auth username(for client mode)")
	flag.StringVar(&password, "p", "", "client mode auth password(for client mode)")
	flag.StringVar(&remoteAddress, "t", "", "proxy server address(for client mode)")
	flag.StringVar(&remoteSecret, "s", "Example123;", "client connect server auth secret")
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

	if serverMode {
		app := proxies.NewServer(listen, remoteSecret)
		if err := app.Start(context.TODO()); err != nil {
			fmt.Println(err.Error())
		}
		return
	}

	app := proxies.NewClient(listen, username, password, remoteAddress, remoteSecret)
	if err := app.Start(context.TODO()); err != nil {
		fmt.Println(err.Error())
	}
}
