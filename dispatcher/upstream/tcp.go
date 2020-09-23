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
	"golang.org/x/net/proxy"
	"net"
	"time"

	"github.com/IrineSistiana/mos-chinadns/dispatcher/upstream/cpool"
	"github.com/IrineSistiana/mos-chinadns/dispatcher/utils"
	"github.com/miekg/dns"
)

// tcpUpstream represents a udp upstream
type tcpUpstream struct {
	addr, socks5 string
	isTLS        bool
	tlsConf      *tls.Config

	cp *cpool.Pool
}

func NewTCPUpstream(addr, socks5 string, idleTimeout time.Duration) Upstream {
	return &tcpUpstream{
		socks5: socks5,
		addr:   addr,
		isTLS:  false,
		cp:     cpool.New(0xffff, idleTimeout, cpool.PoolCleanerInterval),
	}
}

func NewDoTUpstream(addr, socks5 string, idleTimeout time.Duration, tlsConfig *tls.Config) Upstream {
	return &tcpUpstream{
		socks5:  socks5,
		addr:    addr,
		isTLS:   true,
		tlsConf: tlsConfig,
		cp:      cpool.New(0xffff, idleTimeout, cpool.PoolCleanerInterval),
	}
}

func (u *tcpUpstream) Exchange(ctx context.Context, q *dns.Msg) (r *dns.Msg, err error) {
	return u.exchange(ctx, q)
}

func (u *tcpUpstream) exchange(ctx context.Context, q *dns.Msg) (r *dns.Msg, err error) {
	if contextIsDone(ctx) == true {
		return nil, ctx.Err()
	}

	if c := u.cp.Get(); c != nil {
		r, err := u.exchangeViaTCPConn(q, c)
		if err != nil {
			c.Close()
			if contextIsDone(ctx) == true {
				return nil, fmt.Errorf("reused connection err: %w, no time to retry: %w", err, ctx.Err())
			} else {
				goto exchangeViaNewConn // we might have time to retry this query on a new connection
			}
		}
		u.cp.Put(c)
		return r, nil
	}

exchangeViaNewConn:

	// dial new conn
	c, err := u.dial()
	if err != nil {
		return nil, err
	}

	// dialing a new connection might take some time, check if ctx is done
	if contextIsDone(ctx) == true {
		u.cp.Put(c)
		return nil, ctx.Err()
	}

	r, err = u.exchangeViaTCPConn(q, c)
	if err != nil {
		c.Close()
		return nil, err
	}

	u.cp.Put(c)
	return r, nil
}

func (u *tcpUpstream) exchangeViaTCPConn(q *dns.Msg, c net.Conn) (r *dns.Msg, err error) {
	// write first
	c.SetWriteDeadline(time.Now().Add(generalWriteTimeout)) // give write enough time to complete, avoid broken write.
	_, err = utils.WriteMsgToTCP(c, q)
	if err != nil { // write err typically is a fatal err
		return nil, fmt.Errorf("failed to write msg: %w", err)
	}

	c.SetReadDeadline(time.Now().Add(generalReadTimeout))
	r, _, err = utils.ReadMsgFromTCP(c)
	if err != nil {
		return nil, fmt.Errorf("failed to read msg: %w", err)
	}
	return r, nil
}

func (u *tcpUpstream) dial() (conn net.Conn, err error) {

	// dial tcp connection
	if len(u.socks5) != 0 {
		conn, err = dialTCPViaSocks5("tcp", u.addr, u.socks5, dialTCPTimeout)
		if err != nil {
			return nil, fmt.Errorf("failed to dial socks5 connection: %w", err)
		}
	} else {
		d := net.Dialer{Timeout: dialTCPTimeout}
		conn, err = d.Dial("tcp", u.addr)
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

func dialTCPViaSocks5(network, addr, socks5 string, timeout time.Duration) (c net.Conn, err error) {
	socks5Dialer, err := proxy.SOCKS5(network, socks5, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to init socks5 dialer: %w", err)
	}

	dialCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	c, err = socks5Dialer.(proxy.ContextDialer).DialContext(dialCtx, network, addr)
	if err != nil {
		return nil, err
	}
	return c, err
}
