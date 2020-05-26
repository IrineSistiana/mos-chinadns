//     Copyright (C) 2020, IrineSistiana
//
//     This file is part of mos-chinadns.
//
//     mos-chinadns is free software: you can redistribute it and/or modify
//     it under the terms of the GNU General Public License as published by
//     the Free Software Foundation, either version 3 of the License, or
//     (at your option) any later version.
//
//     mos-chinadns is distributed in the hope that it will be useful,
//     but WITHOUT ANY WARRANTY; without even the implied warranty of
//     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//     GNU General Public License for more details.
//
//     You should have received a copy of the GNU General Public License
//     along with this program.  If not, see <https://www.gnu.org/licenses/>.

package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/miekg/dns"

	// dev only
	// "net/http"
	// _ "net/http/pprof"

	"github.com/sirupsen/logrus"
)

var (
	version = "dev/unknown"

	configPath  = flag.String("c", "config.yaml", "[path] load config from file")
	genConfigTo = flag.String("gen", "", "[path] generate a config template here")

	dir                 = flag.String("dir", "", "[path] change working directory to here")
	dirFollowExecutable = flag.Bool("dir2exe", false, "change working directory to the executable that started the current process")

	debug = flag.Bool("debug", false, "more log")
	quiet = flag.Bool("quiet", false, "no log")

	cpu         = flag.Int("cpu", runtime.NumCPU(), "the maximum number of CPUs that can be executing simultaneously")
	showVersion = flag.Bool("v", false, "show verison")

	probeDoTTimeout = flag.String("probe-dot-timeout", "", "[ip:port] probe dot server's timeout")
)

func main() {

	flag.Parse()
	runtime.GOMAXPROCS(*cpu)

	logger := logrus.New()
	entry := logrus.NewEntry(logger)

	switch {
	case *quiet:
		logger.SetLevel(logrus.ErrorLevel)
	case *debug:
		logger.SetLevel(logrus.DebugLevel)
		// dev only
		// go http.ListenAndServe("localhost:8080", nil)
		go printStatus(entry, time.Second*5)
	default:
		logger.SetLevel(logrus.InfoLevel)
	}

	// show version
	if *showVersion {
		fmt.Printf("%s\n", version)
		return
	}

	// dot test
	if len(*probeDoTTimeout) != 0 {
		probTLSTimeout(*probeDoTTimeout, entry)
		return
	}

	// show summary
	entry.Infof("main: mos-chinadns ver: %s", version)
	entry.Infof("main: arch: %s os: %s", runtime.GOARCH, runtime.GOOS)

	//gen config
	if len(*genConfigTo) != 0 {
		err := genConfig(*genConfigTo)
		if err != nil {
			entry.Errorf("main: can not generate config template, %v", err)
		} else {
			entry.Info("main: config template generated")
		}
		return
	}

	// try to change working dir to os.Executable() or *dir
	var wd string
	if *dirFollowExecutable {
		ex, err := os.Executable()
		if err != nil {
			entry.Fatalf("main: get executable path: %v", err)
		}
		wd = filepath.Dir(ex)
	} else {
		if len(*dir) != 0 {
			wd = *dir
		}
	}
	if len(wd) != 0 {
		err := os.Chdir(wd)
		if err != nil {
			entry.Fatalf("main: change the current working directory: %v", err)
		}
		entry.Infof("main: current working directory: %s", wd)
	}

	//checking
	if len(*configPath) == 0 {
		entry.Fatal("main: need a config file")
	}

	c, err := loadConfig(*configPath)
	if err != nil {
		entry.Fatalf("main: can not load config file, %v", err)
	}

	d, err := initDispatcher(c, entry)
	if err != nil {
		entry.Fatalf("main: init dispatcher: %v", err)
	}

	startServerExitWhenFailed := func(network string) {
		entry.Infof("main: %s server started", network)
		if err := d.ListenAndServe(network, c.Bind.Addr, maxUDPSize); err != nil {
			entry.Fatalf("main: %s server exited with err: %v", network, err)
		} else {
			entry.Infof("main: %s server exited", network)
			os.Exit(0)
		}
	}

	switch c.Bind.Protocol {
	case "all", "":
		go startServerExitWhenFailed("tcp")
		go startServerExitWhenFailed("udp")
	case "udp":
		go startServerExitWhenFailed("udp")
	case "tcp":
		go startServerExitWhenFailed("tcp")
	default:
		entry.Fatalf("main: unknown bind protocol: %s", c.Bind.Protocol)
	}

	//wait signals
	osSignals := make(chan os.Signal, 1)
	signal.Notify(osSignals, os.Interrupt, os.Kill, syscall.SIGTERM)
	s := <-osSignals
	entry.Infof("main: exiting: signal: %v", s)
	os.Exit(0)
}

func printStatus(entry *logrus.Entry, d time.Duration) {
	m := new(runtime.MemStats)
	for {
		time.Sleep(d)
		runtime.ReadMemStats(m)
		entry.Infof("printStatus: HeapObjects: %d NumGC: %d PauseTotalNs: %d, NumGoroutine: %d", m.HeapObjects, m.NumGC, m.PauseTotalNs, runtime.NumGoroutine())
	}
}

func probTLSTimeout(addr string, entry *logrus.Entry) {
	q := new(dns.Msg)
	q.SetQuestion("www.google.com.", dns.TypeA)

	tlsConfig := new(tls.Config)
	tlsConfig.InsecureSkipVerify = true

	entry.Infof("connecting to %s", addr)
	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		entry.Fatal(err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(time.Second * 5))
	entry.Info("connected, handshaking")
	conn.Handshake()
	entry.Info("handshake completed")

	conn.SetDeadline(time.Now().Add(time.Second * 5))
	dc := dns.Conn{Conn: conn}
	err = dc.WriteMsg(q)
	if err != nil {
		entry.Fatal(err)
	}
	_, err = dc.ReadMsg()
	if err != nil {
		entry.Fatal(err)
	}

	entry.Info("dummy msg sent")
	entry.Info("waiting peer to close the connection...")
	entry.Info("this may take a while...")
	entry.Info("if you think its long enough, to cancel the test, press Ctrl + C")
	conn.SetDeadline(time.Now().Add(time.Minute * 60))

	start := time.Now()
	conn.Read(make([]byte, 1))

	entry.Infof("connection cloesed by peer after %s", time.Since(start))
}
