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
	"github.com/miekg/dns"
	"net"
	"time"

	"github.com/IrineSistiana/mos-chinadns/dispatcher/pool"
)

const (
	serverTimeout = time.Second * 30
)

// ListenAndServe listen on a port and start the server. Only support tcp and udp network.
// Will always return a non-nil err.
func (d *Dispatcher) ListenAndServe(network, addr string, maxUDPSize int) error {

	switch network {
	case "tcp":
		l, err := net.Listen("tcp", addr)
		if err != nil {
			return err
		}

		for {
			c, err := l.Accept()

			if err != nil {
				er, ok := err.(net.Error)
				if ok && er.Temporary() {
					d.entry.Warnf("ListenAndServe: Accept: temporary err: %v", err)
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

						r, err := d.serveDNS(queryCtx, q)
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
	case "udp":
		l, err := net.ListenPacket("udp", addr)
		if err != nil {
			return err
		}

		readBuf := make([]byte, maxUDPSize)
		for {
			n, from, err := l.ReadFrom(readBuf)
			if err != nil {
				er, ok := err.(net.Error)
				if ok && er.Temporary() {
					d.entry.Warnf("ListenAndServe: ReadFrom(): temporary err: %v", err)
					time.Sleep(time.Millisecond * 100)
					continue
				} else {
					return fmt.Errorf("ReadFrom: %s", err)
				}
			}

			// msg small than headerSize
			// do nothing, avoid ddos
			if n < 12 {
				continue
			}

			q := new(dns.Msg)
			err = q.Unpack(readBuf[:n])
			if err != nil {
				continue
			}

			go func() {
				queryCtx, cancel := context.WithTimeout(context.Background(), queryTimeout)
				defer cancel()

				requestLogger := pool.GetRequestLogger(d.entry.Logger, q)
				defer pool.ReleaseRequestLogger(requestLogger)

				r, err := d.serveDNS(queryCtx, q)
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
	return fmt.Errorf("unknown network: %s", network)
}
