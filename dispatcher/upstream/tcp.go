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

package upstream

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/IrineSistiana/mos-chinadns/dispatcher/upstream/tcp_client"
	"github.com/miekg/dns"
)

// tcpUpstream represents a udp upstream
type tcpUpstream struct {
	addr, socks5 string
	isTLS        bool
	tlsConf      *tls.Config

	cp *tcpClient.Client
}

func NewTCPUpstream(addr, socks5 string, idleTimeout time.Duration) Upstream {
	return newTCPUpstream(addr, socks5, idleTimeout, false, nil)
}

func NewDoTUpstream(addr, socks5 string, idleTimeout time.Duration, tlsConfig *tls.Config) Upstream {
	return newTCPUpstream(addr, socks5, idleTimeout, true, tlsConfig)
}
func newTCPUpstream(addr, socks5 string, idleTimeout time.Duration, isTLS bool, tlsConfig *tls.Config) *tcpUpstream {
	u := &tcpUpstream{
		socks5:  socks5,
		addr:    addr,
		isTLS:   isTLS,
		tlsConf: tlsConfig,
	}
	u.cp = tcpClient.New(context.Background(), u.dial, generalReadTimeout, generalWriteTimeout, idleTimeout)
	return u
}

func (u *tcpUpstream) Exchange(ctx context.Context, q *dns.Msg) (r *dns.Msg, err error) {
	return u.exchange(ctx, q)
}

func (u *tcpUpstream) exchange(ctx context.Context, q *dns.Msg) (r *dns.Msg, err error) {
	if contextIsDone(ctx) == true {
		return nil, ctx.Err()
	}
	return u.cp.Query(ctx, q)
}

func (u *tcpUpstream) dial() (conn net.Conn, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), dialTCPTimeout)
	defer cancel()
	return u.dialContext(ctx)
}

func (u *tcpUpstream) dialContext(ctx context.Context) (conn net.Conn, err error) {

	// dial tcp connection
	if len(u.socks5) != 0 {
		conn, err = dialTCPViaSocks5(ctx, "tcp", u.addr, u.socks5)
		if err != nil {
			return nil, fmt.Errorf("failed to dial socks5 connection: %w", err)
		}
	} else {
		d := net.Dialer{}
		conn, err = d.DialContext(ctx, "tcp", u.addr)
		if err != nil {
			return nil, fmt.Errorf("failed to dial tcp connection: %w", err)
		}
	}

	// upgrade to tls
	if u.isTLS {
		tlsConn := tls.Client(conn, u.tlsConf)
		tlsConn.SetDeadline(time.Now().Add(tlsHandshakeTimeout))
		// handshake now
		if err := tlsConn.Handshake(); err != nil {
			tlsConn.Close()
			return nil, fmt.Errorf("tls handshake failed: %w", err)
		}
		tlsConn.SetDeadline(time.Time{})
		conn = tlsConn
	}

	return conn, err
}
