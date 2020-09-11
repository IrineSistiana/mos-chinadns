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
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

const (
	// MaxUDPSize max udp packet size in edns0
	MaxUDPSize = 1480
)

func checkMsgHasECS(m *dns.Msg) bool {
	opt := m.IsEdns0()
	if opt == nil { // no opt, no ecs
		return false
	}

	// find ecs in opt
	for o := range opt.Option {
		if opt.Option[o].Option() == dns.EDNS0SUBNET {
			return true
		}
	}
	return false
}

// applyECS applies ecs to m.
func applyECS(m *dns.Msg, ecs *dns.EDNS0_SUBNET) *dns.Msg {
	opt := m.IsEdns0()
	if opt == nil { // no opt, we need a new opt
		o := new(dns.OPT)
		o.SetUDPSize(MaxUDPSize)
		o.Hdr.Name = "."
		o.Hdr.Rrtype = dns.TypeOPT
		o.Option = []dns.EDNS0{ecs}
		m.Extra = append(m.Extra, o)
		return m
	}

	// if m has a opt, search ecs section
	for o := range opt.Option {
		if opt.Option[o].Option() == dns.EDNS0SUBNET { // overwrite
			opt.Option[o] = ecs
			return m
		}
	}

	// no ecs section, append it
	opt.Option = append(opt.Option, ecs)
	return m
}

func newEDNS0SubnetFromStr(s string) (*dns.EDNS0_SUBNET, error) {
	ipAndMask := strings.SplitN(s, "/", 2)
	if len(ipAndMask) != 2 {
		return nil, fmt.Errorf("invalid ECS address [%s], not a CIDR notation", s)
	}

	ip := net.ParseIP(ipAndMask[0])
	if ip == nil {
		return nil, fmt.Errorf("invalid ECS address [%s], invalid ip", s)
	}
	sourceNetmask, err := strconv.Atoi(ipAndMask[1])
	if err != nil || sourceNetmask > 128 || sourceNetmask < 0 {
		return nil, fmt.Errorf("invalid ECS address [%s], invalid net mask", s)
	}

	edns0Subnet := new(dns.EDNS0_SUBNET)
	// edns family: https://www.iana.org/assignments/address-family-numbers/address-family-numbers.xhtml
	// ipv4 = 1
	// ipv6 = 2
	if ip4 := ip.To4(); ip4 != nil {
		edns0Subnet.Family = 1
		edns0Subnet.SourceNetmask = uint8(sourceNetmask)
		ip = ip4
	} else {
		if ip6 := ip.To16(); ip6 != nil {
			edns0Subnet.Family = 2
			edns0Subnet.SourceNetmask = uint8(sourceNetmask)
			ip = ip6
		} else {
			return nil, fmt.Errorf("invalid ECS address [%s], it's not an ipv4 or ipv6 address", s)
		}
	}

	edns0Subnet.Code = dns.EDNS0SUBNET
	edns0Subnet.Address = ip

	// SCOPE PREFIX-LENGTH, an unsigned octet representing the leftmost
	// number of significant bits of ADDRESS that the response covers.
	// In queries, it MUST be set to 0.
	// https://tools.ietf.org/html/rfc7871
	edns0Subnet.SourceScope = 0
	return edns0Subnet, nil
}
