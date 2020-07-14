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

package dispatcher

import (
	"context"
	"fmt"
	"github.com/IrineSistiana/mos-chinadns/dispatcher/pool"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	"net"
	"time"
)

const (
	serverTimeout = time.Second * 30
)

func StartServer(c *Config, entry *logrus.Entry) error {

	d, err := InitDispatcher(c, entry)
	if err != nil {
		return fmt.Errorf("init dispatcher failed, %v", err)
	}

	var doTCP, doUDP bool
	switch c.Bind.Protocol {
	case "all", "":
		doTCP = true
		doUDP = true
	case "udp":
		doUDP = true
	case "tcp":
		doTCP = true
	default:
		return fmt.Errorf("unknown bind protocol: %s", c.Bind.Protocol)
	}

	g := new(errgroup.Group)

	if doTCP {
		l, err := net.Listen("tcp", c.Bind.Addr)
		if err != nil {
			return err
		}
		defer l.Close()

		entry.Infof("StartServer: tcp server is started at %s", l.Addr())
		g.Go(func() error { return d.StartTCPServerAt(l) })
	}

	if doUDP {
		l, err := net.ListenPacket("udp", c.Bind.Addr)
		if err != nil {
			return err
		}
		defer l.Close()

		entry.Infof("StartServer: udp server is started at %s", l.LocalAddr())
		g.Go(func() error { return d.StartUDPServerAt(l) })
	}

	if err := g.Wait(); err != nil {
		return fmt.Errorf("server exited: %v", err)
	}

	return nil
}

// StartTCPServer starts a tcp dns server at given address. Will always return a non-nil err.
func (d *Dispatcher) StartTCPServer(network, addr string) error {
	l, err := net.Listen(network, addr)
	if err != nil {
		return err
	}
	defer l.Close()

	return d.StartTCPServerAt(l)
}

// StartTCPServerAt starts a tcp dns server at given net.Listener. Will always return a non-nil err.
// To close the server, close the l.
func (d *Dispatcher) StartTCPServerAt(l net.Listener) error {

	for {
		c, err := l.Accept()

		if err != nil {
			er, ok := err.(net.Error)
			if ok && er.Temporary() {
				d.entry.Warnf("StartTCPServer: Accept: temporary err: %v", err)
				time.Sleep(time.Millisecond * 100)
				continue
			} else {
				return fmt.Errorf("Accept: %s", err)
			}
		}

		go func() {
			defer c.Close()
			tcpConnCtx, cancel := context.WithCancel(context.Background())
			defer cancel()

			for {
				c.SetReadDeadline(time.Now().Add(serverTimeout))
				q, _, _, err := readMsgFromTCP(c)
				if err != nil {
					return // read err, close the conn
				}

				go func() {
					queryCtx, cancel := context.WithTimeout(tcpConnCtx, queryTimeout)
					defer cancel()

					requestLogger := pool.GetRequestLogger(d.entry.Logger, q)
					defer pool.ReleaseRequestLogger(requestLogger)

					r, err := d.ServeDNS(queryCtx, q)
					if err != nil {
						requestLogger.Warnf("query failed, %v", err)
						return // ignore it, result is empty
					}

					c.SetWriteDeadline(time.Now().Add(serverTimeout))
					_, err = writeMsgToTCP(c, r)
					if err != nil {
						requestLogger.Warnf("failed to send reply back, writeMsgToTCP: %v", err)
					}
				}()
			}
		}()
	}
}

// StartUDPServer starts a udp dns server at given address. Will always return a non-nil err.
func (d *Dispatcher) StartUDPServer(network, addr string) error {
	l, err := net.ListenPacket(network, addr)
	if err != nil {
		return err
	}
	defer l.Close()

	return d.StartUDPServerAt(l)
}

// StartUDPServer starts a udp dns server at net.PacketConn. Will always return a non-nil err.
// The max UDP package size is dispatcher.MaxUDPSize.
// To close the server, close the l.
func (d *Dispatcher) StartUDPServerAt(l net.PacketConn) error {

	readBuf := make([]byte, MaxUDPSize)
	for {
		n, from, err := l.ReadFrom(readBuf)
		if err != nil {
			er, ok := err.(net.Error)
			if ok && er.Temporary() {
				d.entry.Warnf("StartUDPServer: ReadFrom(): temporary err: %v", err)
				time.Sleep(time.Millisecond * 100)
				continue
			} else {
				return fmt.Errorf("ReadFrom: %s", err)
			}
		}

		// if we received an invalid package, do nothing, even logging, to avoid Denial-of-service attack.
		if n < 12 {
			continue // msg small than headerSize
		}

		q := new(dns.Msg)
		err = q.Unpack(readBuf[:n])
		if err != nil {
			continue // invalid msg
		}

		go func() {
			queryCtx, cancel := context.WithTimeout(context.Background(), queryTimeout)
			defer cancel()

			requestLogger := pool.GetRequestLogger(d.entry.Logger, q)
			defer pool.ReleaseRequestLogger(requestLogger)

			r, err := d.ServeDNS(queryCtx, q)
			if err != nil {
				requestLogger.Warnf("query failed, %v", err)
				return
			}

			buf := pool.AcquirePackBuf()
			defer pool.ReleasePackBuf(buf)

			rRaw, err := r.PackBuffer(buf)
			if err != nil {
				requestLogger.Warnf("failed to send reply back, PackBuffer, %v", err)
				return
			}

			l.SetWriteDeadline(time.Now().Add(serverTimeout))
			_, err = l.WriteTo(rRaw, from)
			if err != nil {
				requestLogger.Warnf("failed to send reply back, WriteTo: %v", err)
			}
		}()
	}
}
