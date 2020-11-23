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
	"github.com/miekg/dns"
	"net"
	"time"
)

const (
	serverUDPWriteTimeout = time.Second
)

type udpServer struct {
	socket      net.PacketConn
	readBufSize int
}

func NewUDPServer(c *Config) Server {
	s := new(udpServer)

	switch {
	case c.MaxUDPPayloadSize < dns.MinMsgSize:
		s.readBufSize = dns.MinMsgSize
	case c.MaxUDPPayloadSize > dns.MaxMsgSize:
		s.readBufSize = dns.MaxMsgSize
	default:
		s.readBufSize = c.MaxUDPPayloadSize
	}

	s.socket = c.PacketConn

	return s
}

func (s *udpServer) ListenAndServe(h Handler) error {
	listenerCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	for {
		q, from, _, err := utils.ReadUDPMsgFrom(s.socket, s.readBufSize)
		if err != nil {
			netErr, ok := err.(net.Error)
			if ok { // is a net err
				if netErr.Temporary() {
					logger.GetStd().Warnf("udp server: listener temporary err: %v", err)
					time.Sleep(time.Millisecond * 100)
					continue
				} else {
					return fmt.Errorf("udp server: unexpected listener err: %w", err)
				}
			} else { // invalid msg
				continue
			}
		}

		go func() {
			queryCtx, cancel := context.WithTimeout(listenerCtx, queryTimeout)
			defer cancel()

			logger.GetStd().Debugf("udp server %s: [%v %d]: new query from %s", s.socket.LocalAddr(), q.Question, q.Id, from)

			r, err := h.ServeDNS(queryCtx, q)
			if err != nil {
				logger.GetStd().Warnf("udp server %s: [%v %d]: query failed: %v", s.socket.LocalAddr(), q.Question, q.Id, err)
			}

			if r != nil {
				// truncate
				var udpSize int
				if opt := q.IsEdns0(); opt != nil {
					udpSize = int(opt.Hdr.Class)
				} else {
					udpSize = dns.MinMsgSize
				}

				r.Truncate(udpSize)

				s.socket.SetWriteDeadline(time.Now().Add(serverUDPWriteTimeout))
				_, err = utils.WriteUDPMsgTo(r, s.socket, from)
				if err != nil {
					logger.GetStd().Warnf("udp server %s: [%v %d]: failed to send reply back: %v", s.socket.LocalAddr(), q.Question, q.Id, err)
				}
			}
		}()
	}
}
