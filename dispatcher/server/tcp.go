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

package server

import (
	"context"
	"fmt"
	"github.com/IrineSistiana/mos-chinadns/dispatcher/logger"
	"github.com/IrineSistiana/mos-chinadns/dispatcher/utils"
	"net"
	"time"
)

const (
	serverTCPReadTimeout  = time.Second * 8
	serverTCPWriteTimeout = time.Second
)

type tcpServer struct {
	l       net.Listener
	timeout time.Duration
}

func NewTCPServer(c *Config) Server {
	s := new(tcpServer)
	s.l = c.Listener
	if c.Timeout > 0 {
		s.timeout = c.Timeout
	} else {
		s.timeout = serverTCPReadTimeout
	}
	return s
}

func (s *tcpServer) ListenAndServe(h Handler) error {
	listenerCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	for {
		c, err := s.l.Accept()

		if err != nil {
			er, ok := err.(net.Error)
			if ok && er.Temporary() {
				logger.GetStd().Warnf("tcp server: listener: temporary err: %v", err)
				time.Sleep(time.Millisecond * 100)
				continue
			} else {
				return fmt.Errorf("listener: %s", err)
			}
		}

		go func() {
			defer c.Close()
			tcpConnCtx, cancel := context.WithCancel(listenerCtx)
			defer cancel()

			for {
				c.SetReadDeadline(time.Now().Add(serverTCPReadTimeout))
				q, _, err := utils.ReadMsgFromTCP(c)
				if err != nil {
					return // read err, close the conn
				}

				go func() {
					queryCtx, cancel := context.WithTimeout(tcpConnCtx, queryTimeout)
					defer cancel()

					logger.GetStd().Debugf("tcp server %s: [%v %d]: new query from %s,", s.l.Addr(), q.Question, q.Id, c.RemoteAddr())

					r, err := h.ServeDNS(queryCtx, q)
					if err != nil {
						logger.GetStd().Warnf("tcp server %s: [%v %d]: query failed: %v", s.l.Addr(), q.Question, q.Id, err)
					}

					if r != nil {
						c.SetWriteDeadline(time.Now().Add(serverTCPWriteTimeout))
						_, err = utils.WriteMsgToTCP(c, r)
						if err != nil {
							logger.GetStd().Warnf("tcp server %s: [%v %d]: failed to send reply back, WriteMsgToTCP: %v", s.l.Addr(), q.Question, q.Id, err)
						}
					}
				}()

			}
		}()
	}
}
