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

package main

import (
	"encoding/binary"
	"io"
	"net"

	"github.com/IrineSistiana/mos-chinadns/bufpool"
	"github.com/miekg/dns"
)

// readMsgFromTCP reads msg from a tcp connection, m should be
// released by bufpool.ReleaseMsgBuf when m is no longer used.
func readMsgFromTCP(c net.Conn) (mRaw []byte, err error) {
	lengthRaw := bufpool.AcquireMsgBuf(2)
	defer bufpool.ReleaseMsgBuf(lengthRaw)
	if _, err := io.ReadFull(c, lengthRaw); err != nil {
		return nil, err
	}

	// dns headerSize
	length := binary.BigEndian.Uint16(lengthRaw)
	if length < 12 {
		return nil, dns.ErrShortRead
	}

	buf := bufpool.AcquireMsgBuf(int(length))
	if _, err := io.ReadFull(c, buf); err != nil {
		bufpool.ReleaseMsgBuf(buf)
		return nil, err
	}

	return buf, nil
}

func writeMsgToTCP(c net.Conn, m []byte) (err error) {
	l := bufpool.AcquireMsgBuf(2)
	defer bufpool.ReleaseMsgBuf(l)
	binary.BigEndian.PutUint16(l, uint16(len(m)))

	_, err = (&net.Buffers{l, m}).WriteTo(c)
	return err
}

func writeMsgToUDP(c net.Conn, m []byte) (err error) {
	_, err = c.Write(m)
	return err
}

func readMsgFromUDP(c net.Conn, maxSize int) (m []byte, err error) {
	buf := bufpool.AcquireMsgBuf(maxSize)

	n, err := c.Read(buf)
	if err != nil {
		bufpool.ReleaseMsgBuf(buf)
		return nil, err
	}
	if n < 12 {
		bufpool.ReleaseMsgBuf(buf)
		return nil, dns.ErrShortRead
	}
	return buf[:n], err
}
