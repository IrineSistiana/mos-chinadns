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
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"

	"github.com/IrineSistiana/mos-chinadns/bufpool"
)

const (
	serverTimeout = time.Second * 3
)

func (d *dispatcher) ListenAndServe(network, addr string, maxUDPSize int) error {

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

				for {
					c.SetDeadline(time.Now().Add(serverTimeout))
					qRaw, _, _, err := readMsgFromTCP(c)
					if err != nil {
						return
					}

					q := new(dns.Msg)
					err = q.Unpack(qRaw.B)
					if err != nil { // invalid msg, drop it
						bufpool.ReleaseMsgBuf(qRaw)
						continue
					}

					requestLogger := getRequestLogger(d.entry.Logger, c.RemoteAddr(), q.Id, q.Question, "tcp")
					go func() {
						rRaw := d.handleClientRawDNS(q, qRaw, requestLogger)
						if rRaw == nil {
							return // ignore it, result is empty
						}
						defer bufpool.ReleaseMsgBuf(rRaw)

						_, err = writeMsgToTCP(c, rRaw.B)
						if err != nil {
							requestLogger.Warnf("ListenAndServe: writeMsgToTCP: %v", err)
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

		readBuf := bufpool.AcquireMsgBuf(maxUDPSize)
		for {
			n, from, err := l.ReadFrom(readBuf.B)

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
			err = q.Unpack(readBuf.B[:n])
			if err != nil {
				continue
			}

			// copy it to a new and maybe smaller buf for the new goroutine
			qRaw := bufpool.AcquireMsgBufAndCopy(readBuf.B[:n])
			requestLogger := getRequestLogger(d.entry.Logger, from, q.Id, q.Question, "udp")
			go func() {
				rRaw := d.handleClientRawDNS(q, qRaw, requestLogger)
				if rRaw == nil {
					return
				}
				defer bufpool.ReleaseMsgBuf(rRaw)

				l.SetWriteDeadline(time.Now().Add(serverTimeout))
				_, err = l.WriteTo(rRaw.B, from)
				if err != nil {
					requestLogger.Warnf("ListenAndServe: WriteTo: %v", err)
				}
			}()
		}
	}
	return fmt.Errorf("unknown network: %s", network)
}

type bucket struct {
	sync.Mutex
	i   int
	max int
}

func newBucket(max int) *bucket {
	return &bucket{
		i:   0,
		max: max,
	}
}

func (b *bucket) aquire() bool {
	b.Lock()
	defer b.Unlock()

	if b.i >= b.max {
		return false
	}

	b.i++
	return true
}

func (b *bucket) release() {
	b.Lock()
	defer b.Unlock()

	if b.i < 0 {
		panic("nagetive num in bucket")
	}

	b.i--
}

func getRequestLogger(logger *logrus.Logger, from net.Addr, id uint16, question []dns.Question, protocol string) *logrus.Entry {
	f := make(logrus.Fields, 3+4) // Default is three fields
	f["from"] = from
	f["id"] = id
	f["question"] = question
	f["protocol"] = protocol
	e := &logrus.Entry{
		Logger: logger,
		Data:   f,
	}

	return e
}
