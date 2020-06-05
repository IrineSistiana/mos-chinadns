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
	"fmt"
	"io"
	"net"

	"github.com/IrineSistiana/mos-chinadns/bufpool"
	"github.com/miekg/dns"
)

const (
	unknownBrokenDataSize = -1
)

// readMsgFromTCP reads msg from a tcp connection, m should be
// released by bufpool.ReleaseMsgBuf when m is no longer used.
// brokenDataLeft indicates the frame size which have not be read from c.
// if brokenDataLeft is unknownBrokenDataSize(-1), c should not be reused anymore.
// if brokenDataLeft > 0, means some data has be read from c.
func readMsgFromTCP(c net.Conn) (mRaw *bufpool.MsgBuf, brokenDataLeft int, n int, err error) {
	lengthRaw := bufpool.AcquireMsgBuf(2)
	defer bufpool.ReleaseMsgBuf(lengthRaw)

	n1, err := io.ReadFull(c, lengthRaw.B)
	n = n + n1
	if err != nil {
		if n1 == 0 {
			return nil, 0, 0, err
		}
		return nil, unknownBrokenDataSize, n, err
	}

	// dns headerSize
	length := binary.BigEndian.Uint16(lengthRaw.B)
	if length < 12 {
		return nil, unknownBrokenDataSize, n, dns.ErrShortRead
	}

	buf := bufpool.AcquireMsgBuf(int(length))
	n2, err := io.ReadFull(c, buf.B)
	n = n + n2
	if err != nil {
		bufpool.ReleaseMsgBuf(buf)
		return nil, int(length) - n2, n, err
	}

	return buf, 0, n, nil
}

func writeMsgToTCP(c net.Conn, m []byte) (n int, err error) {
	l := bufpool.AcquireMsgBuf(2 + len(m))
	defer bufpool.ReleaseMsgBuf(l)
	binary.BigEndian.PutUint16(l.B, uint16(len(m)))
	copy(l.B[2:], m)
	n, err = c.Write(l.B)
	if n != 0 && n < len(l.B) {
		return n, fmt.Errorf("%s: net.Conn.Write(): %s", io.ErrShortWrite, err)
	}
	return 0, err
}

func writeMsgToUDP(c net.Conn, m []byte) (n int, err error) {
	return c.Write(m)
}

func readMsgFromUDP(c net.Conn, maxSize int) (m *bufpool.MsgBuf, n int, err error) {
	buf := bufpool.AcquireMsgBuf(maxSize)

	n, err = c.Read(buf.B)
	if err != nil {
		bufpool.ReleaseMsgBuf(buf)
		return nil, n, err
	}
	if n < 12 {
		bufpool.ReleaseMsgBuf(buf)
		return nil, n, dns.ErrShortRead
	}
	buf.B = buf.B[:n]
	return nil, n, err
}
