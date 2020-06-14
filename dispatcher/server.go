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
	"net"
	"time"

	"github.com/IrineSistiana/mos-chinadns/dispatcher/bufpool"
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
					qRaw, _, _, err := readMsgFromTCP(c)
					if err != nil {
						return
					}

					q := getMsg()
					err = q.Unpack(qRaw.Bytes())
					if err != nil { // invalid msg, drop it
						bufpool.ReleaseMsgBuf(qRaw)
						releaseMsg(q)
						continue
					}

					requestLogger := getRequestLogger(d.entry.Logger, c.RemoteAddr(), q.Id, q.Question, "tcp")
					go func() {
						queryCtx, cancel := context.WithTimeout(tcpConnCtx, queryTimeout)
						defer cancel()

						rRaw, _ := d.serveRawDNS(queryCtx, q, qRaw, requestLogger, true)
						if rRaw == nil {
							return // ignore it, result is empty
						}
						defer bufpool.ReleaseMsgBuf(rRaw)

						c.SetWriteDeadline(time.Now().Add(serverTimeout))
						_, err = writeMsgToTCP(c, rRaw.Bytes())
						if err != nil {
							d.entry.Warnf("ListenAndServe: writeMsgToTCP: %v", err)
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

			q := getMsg()
			err = q.Unpack(readBuf[:n])
			if err != nil {
				releaseMsg(q)
				continue
			}

			// copy it to a new and maybe smaller buf for the new goroutine
			qRaw := bufpool.AcquireMsgBufAndCopy(readBuf[:n])
			requestLogger := getRequestLogger(d.entry.Logger, from, q.Id, q.Question, "udp")
			go func() {
				queryCtx, cancel := context.WithTimeout(context.Background(), queryTimeout)
				defer cancel()

				rRaw, _ := d.serveRawDNS(queryCtx, q, qRaw, requestLogger, true)
				if rRaw == nil {
					return
				}
				defer bufpool.ReleaseMsgBuf(rRaw)

				l.SetWriteDeadline(time.Now().Add(serverTimeout))
				_, err = l.WriteTo(rRaw.Bytes(), from)
				if err != nil {
					d.entry.Warnf("ListenAndServe: WriteTo: %v", err)
				}
			}()
		}
	}
	return fmt.Errorf("unknown network: %s", network)
}
