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
	"github.com/miekg/dns"
	"net"
	"time"
)

type Server interface {
	ListenAndServe(h Handler) error
}

type Handler interface {
	ServeDNS(ctx context.Context, q *dns.Msg) (r *dns.Msg, err error)
}

const (
	queryTimeout = time.Second * 5
)

type Config struct {
	// listener for tcp server
	Listener net.Listener

	// socket for udp server
	PacketConn net.PacketConn

	// tcp idle timeout
	Timeout time.Duration

	// udp read buffer size
	MaxUDPPayloadSize int
}
