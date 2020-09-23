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
	"fmt"
	"github.com/IrineSistiana/mos-chinadns/dispatcher/upstream/cpool"
	"github.com/IrineSistiana/mos-chinadns/dispatcher/utils"
	"github.com/miekg/dns"
	"net"
	"time"
)

// udpUpstream represents a udp upstream
type udpUpstream struct {
	addr string
	cp   *cpool.Pool
}

func NewUDPUpstream(addr string) Upstream {
	return &udpUpstream{
		addr: addr,
		cp:   cpool.New(0xffff, time.Second*10, cpool.PoolCleanerInterval),
	}
}

func (u *udpUpstream) Exchange(ctx context.Context, q *dns.Msg) (r *dns.Msg, err error) {
	return u.exchange(ctx, q)
}

func (u *udpUpstream) exchange(ctx context.Context, q *dns.Msg) (r *dns.Msg, err error) {
	if contextIsDone(ctx) == true {
		return nil, ctx.Err()
	}

	if c := u.cp.Get(); c != nil {
		r, err := u.exchangeViaUDPConn(q, c)
		if err != nil {
			c.Close()
			if contextIsDone(ctx) == true {
				return nil, fmt.Errorf("reused connection err: %v, no time to retry: %w", err, ctx.Err())
			} else {
				goto exchangeViaNewConn // we might have time to retry this query on a new connection
			}
		}
		u.cp.Put(c)
		return r, nil
	}

exchangeViaNewConn:
	dialer := net.Dialer{Timeout: dialUDPTimeout}
	c, err := dialer.Dial("udp", u.addr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial new conntion: %w", err)
	}

	// dialing a new connection might take some time, check if ctx is done
	if contextIsDone(ctx) == true {
		u.cp.Put(c)
		return nil, ctx.Err()
	}

	r, err = u.exchangeViaUDPConn(q, c)
	if err != nil {
		c.Close()
		return nil, err
	}

	u.cp.Put(c)
	return r, nil
}

func (u *udpUpstream) exchangeViaUDPConn(q *dns.Msg, c net.Conn) (r *dns.Msg, err error) {
	// write first
	c.SetWriteDeadline(time.Now().Add(generalWriteTimeout)) // give write enough time to complete, avoid broken write.
	_, err = utils.WriteMsgToUDP(c, q)
	if err != nil { // write err typically is a fatal err
		return nil, fmt.Errorf("failed to write msg: %w", err)
	}
	c.SetReadDeadline(time.Now().Add(generalReadTimeout))

	for {
		r, _, err = utils.ReadMsgFromUDP(c, utils.IPv4UdpMaxPayload)
		if err != nil {
			return nil, fmt.Errorf("failed to read msg: %w", err)
		}

		// id mismatch, ignore it and read again.
		// It's quite usual for udp connection. Especially when someone wants to poison you.
		if r.Id != q.Id {
			continue
		}
		return r, nil
	}
}
