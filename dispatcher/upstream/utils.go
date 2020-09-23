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
	"github.com/miekg/dns"
	"golang.org/x/net/proxy"
	"net"
	"time"
)

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

func contextIsDone(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}

func checkQueryType(m *dns.Msg, typ uint16) bool {
	if len(m.Question) > 0 && m.Question[0].Qtype == typ {
		return true
	}
	return false
}
