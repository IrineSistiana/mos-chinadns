// +build linux

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

package ipset

import (
	"net"
	"syscall"

	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

const (
	IPSET_ATTR_IPADDR_IPV4 = 1
	IPSET_ATTR_IPADDR_IPV6 = 2
)

func AddCIDR4(setName string, ip net.IP, ones uint8) error {
	return AddCIDR(setName, ip, ones, false)
}

func AddCIDR6(setName string, ip net.IP, ones uint8) error {
	return AddCIDR(setName, ip, ones, true)
}

func AddCIDR(setName string, ip net.IP, ones uint8, isNET6 bool) error {
	req := nl.NewNetlinkRequest(nl.IPSET_CMD_ADD|(unix.NFNL_SUBSYS_IPSET<<8), nl.GetIpsetFlags(nl.IPSET_CMD_ADD))

	var nfgenFamily uint8
	if isNET6 {
		nfgenFamily = uint8(unix.AF_INET6)
	} else {
		nfgenFamily = uint8(unix.AF_INET)
	}
	req.AddData(
		&nl.Nfgenmsg{
			NfgenFamily: nfgenFamily,
			Version:     nl.NFNETLINK_V0,
			ResId:       0,
		},
	)

	req.AddData(nl.NewRtAttr(nl.IPSET_ATTR_PROTOCOL, nl.Uint8Attr(nl.IPSET_PROTOCOL)))
	req.AddData(nl.NewRtAttr(nl.IPSET_ATTR_SETNAME, nl.ZeroTerminated(setName)))
	data := nl.NewRtAttr(nl.IPSET_ATTR_DATA|int(nl.NLA_F_NESTED), nil)

	// set ip
	addr := nl.NewRtAttr(nl.IPSET_ATTR_IP|int(nl.NLA_F_NESTED), nil)
	if isNET6 {
		addr.AddRtAttr(IPSET_ATTR_IPADDR_IPV6|int(nl.NLA_F_NET_BYTEORDER), ip)
	} else {
		addr.AddRtAttr(IPSET_ATTR_IPADDR_IPV4|int(nl.NLA_F_NET_BYTEORDER), ip)
	}
	data.AddChild(addr)

	// set mask
	data.AddRtAttr(nl.IPSET_ATTR_CIDR, nl.Uint8Attr(ones))

	req.AddData(data)

	_, err := req.Execute(unix.NETLINK_NETFILTER, 0)

	if err != nil {
		if errno := int(err.(syscall.Errno)); errno >= nl.IPSET_ERR_PRIVATE {
			err = nl.IPSetError(uintptr(errno))
		}
	}
	return err
}
