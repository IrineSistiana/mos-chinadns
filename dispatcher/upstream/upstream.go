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
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/IrineSistiana/mos-chinadns/dispatcher/bufpool"
	"github.com/IrineSistiana/mos-chinadns/dispatcher/config"
	"github.com/IrineSistiana/mos-chinadns/dispatcher/ecs"
	"github.com/miekg/dns"
	"golang.org/x/net/proxy"
	"golang.org/x/sync/singleflight"
	"net"
	"time"
)

// Upstream represents a dns upstream
type Upstream interface {
	Exchange(ctx context.Context, q *dns.Msg) (r *dns.Msg, err error)
}

type BasicUpstream struct {
	edns0 struct {
		clientSubnet *dns.EDNS0_SUBNET
		overwriteECS bool
	}
	deduplicate bool

	sfGroup singleflight.Group
	backend Upstream
}

func (u *BasicUpstream) Exchange(ctx context.Context, q *dns.Msg) (r *dns.Msg, err error) {
	if u.deduplicate == false {
		return u.exchange(ctx, q)
	}

	key, err := getMsgKey(q)
	if err != nil {
		return nil, fmt.Errorf("failed to caculate msg key, %v", err)
	}

	v, err, shared := u.sfGroup.Do(key, func() (interface{}, error) {
		defer u.sfGroup.Forget(key)
		return u.exchange(ctx, q)
	})

	if err != nil {
		return nil, err
	}

	rUnsafe := v.(*dns.Msg)

	if shared && rUnsafe != nil { // shared reply may has different id and is not safe to modify.
		r = rUnsafe.Copy()
		r.Id = q.Id
		return r, nil
	}

	return rUnsafe, nil
}

func (u *BasicUpstream) exchange(ctx context.Context, q *dns.Msg) (r *dns.Msg, err error) {
	// try to append edns0 client subnet
	if u.edns0.clientSubnet != nil {
		if ecs.CheckMsgHasECS(q) == false || u.edns0.overwriteECS {
			q = q.Copy()
			ecs.SetECS(q, u.edns0.clientSubnet)
		}
	}

	return u.backend.Exchange(ctx, q)
}

func getMsgKey(m *dns.Msg) (string, error) {
	buf, err := bufpool.GetMsgBufFor(m)
	if err != nil {
		return "", err
	}
	defer bufpool.ReleaseMsgBuf(buf)

	wireMsg, err := m.PackBuffer(buf)
	if err != nil {
		return "", err
	}

	wireMsg[0] = 0
	wireMsg[1] = 1
	return string(wireMsg), nil
}

func NewUpstreamServer(c *config.BasicUpstreamConfig, rootCAs *x509.CertPool) (Upstream, error) {
	var backend Upstream
	switch c.Protocol {
	case "udp", "":
		backend = NewUDPUpstream(c.Addr)

	case "tcp":
		backend = NewTCPUpstream(c.Addr, c.Socks5, time.Duration(c.TCP.IdleTimeout)*time.Second)

	case "dot":
		if len(c.DoT.ServerName) == 0 {
			return nil, fmt.Errorf("dot server needs a server name")
		}
		tlsConf := &tls.Config{
			ServerName:         c.DoT.ServerName,
			RootCAs:            rootCAs,
			ClientSessionCache: tls.NewLRUClientSessionCache(64),

			// for test only
			InsecureSkipVerify: c.InsecureSkipVerify,
		}

		backend = NewDoTUpstream(c.Addr, c.Socks5, time.Duration(c.TCP.IdleTimeout)*time.Second, tlsConf)

	case "doh":
		if len(c.DoH.URL) == 0 {
			return nil, fmt.Errorf("protocol [%s] needs additional argument: url", c.Protocol)
		}

		tlsConf := &tls.Config{
			// don't have to set servername here, net.http will do it itself.
			RootCAs:            rootCAs,
			ClientSessionCache: tls.NewLRUClientSessionCache(64),

			// for test only
			InsecureSkipVerify: c.InsecureSkipVerify,
		}

		var dialContext func(ctx context.Context, _, _ string) (net.Conn, error)
		if len(c.Socks5) != 0 {
			d, err := proxy.SOCKS5("tcp", c.Socks5, nil, nil)
			if err != nil {
				return nil, fmt.Errorf("failed to init socks5 dialer: %v", err)
			}
			contextDialer := d.(proxy.ContextDialer)

			dialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
				return contextDialer.DialContext(ctx, "tcp", c.Addr)
			}
		} else {
			dialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
				d := net.Dialer{}
				return d.DialContext(ctx, "tcp", c.Addr)
			}
		}

		var err error
		backend, err = NewDoHUpstream(c.DoH.URL, dialContext, tlsConf)
		if err != nil {
			return nil, fmt.Errorf("failed to init DoH: %v", err)
		}

	default:
		return nil, fmt.Errorf("unsupport protocol: %s", c.Protocol)
	}

	u := new(BasicUpstream)
	u.backend = backend

	// load ecs
	if len(c.EDNS0.ClientSubnet) != 0 {
		subnet, err := ecs.NewEDNS0SubnetFromStr(c.EDNS0.ClientSubnet)
		if err != nil {
			return nil, fmt.Errorf("invaild ecs, %w", err)
		}
		u.edns0.clientSubnet = subnet
	}
	u.edns0.overwriteECS = c.EDNS0.OverwriteECS

	u.deduplicate = c.Deduplicate

	return u, nil
}

func getUpstreamDialContextFunc(network, dstAddress, sock5Address string) (func(ctx context.Context, _, _ string) (net.Conn, error), error) {
	if len(sock5Address) != 0 { // proxy through sock5
		d, err := proxy.SOCKS5(network, sock5Address, nil, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to init socks5 dialer: %v", err)
		}
		contextDialer, ok := d.(proxy.ContextDialer)
		if !ok {
			return nil, errors.New("internal err: socks5 dialer is not a proxy.ContextDialer")
		}
		return func(ctx context.Context, _, _ string) (net.Conn, error) {
			return contextDialer.DialContext(ctx, network, dstAddress)
		}, nil
	}
	return func(ctx context.Context, _, _ string) (net.Conn, error) {
		d := net.Dialer{}
		return d.DialContext(ctx, network, dstAddress)
	}, nil
}
