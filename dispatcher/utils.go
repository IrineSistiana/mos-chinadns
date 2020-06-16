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
	"encoding/binary"
	"errors"
	"io"
	"net"

	"github.com/IrineSistiana/mos-chinadns/dispatcher/bufpool"
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
func readMsgFromTCP(c io.Reader) (mRaw *bufpool.MsgBuf, brokenDataLeft int, n int, err error) {
	lengthRaw := getTCPHeaderBuf()
	defer releaseTCPHeaderBuf(lengthRaw)

	n1, err := io.ReadFull(c, lengthRaw)
	n = n + n1
	if err != nil {
		if n1 != 0 {
			return nil, unknownBrokenDataSize, n, err
		}
		return nil, 0, n, err
	}

	// dns headerSize
	length := binary.BigEndian.Uint16(lengthRaw)
	if length < 12 {
		return nil, unknownBrokenDataSize, n, dns.ErrShortRead
	}

	buf := bufpool.AcquireMsgBuf(int(length))
	n2, err := io.ReadFull(c, buf.Bytes())
	n = n + n2
	if err != nil {
		bufpool.ReleaseMsgBuf(buf)
		return nil, int(length) - n2, n, err
	}

	return buf, 0, n, nil
}

var err = errors.New("payload is bigger than dns.MaxMsgSize")

func writeMsgToTCP(c io.Writer, m []byte) (n int, err error) {
	if len(m) > dns.MaxMsgSize {
		return
	}

	if tcpConn, ok := c.(*net.TCPConn); ok {
		h := getTCPHeaderBuf()
		defer releaseTCPHeaderBuf(h)
		h[0] = byte(len(m) >> 8)
		h[1] = byte(len(m))

		n, err := (&net.Buffers{h, m}).WriteTo(tcpConn)
		n = n - 2
		if n < 0 {
			n = 0
		}
		return int(n), err
	}

	mb := bufpool.AcquireMsgBuf(len(m) + 2)
	defer bufpool.ReleaseMsgBuf(mb)
	buf := mb.Bytes()
	buf[0] = byte(len(m) >> 8)
	buf[1] = byte(len(m))
	copy(buf[2:], m)

	n, err = c.Write(buf)
	n = n - 2
	if n < 0 {
		n = 0
	}
	return n, err
}

func writeMsgToUDP(c io.Writer, m []byte) (n int, err error) {
	return c.Write(m)
}

func readMsgFromUDP(c io.Reader) (m *bufpool.MsgBuf, brokenDataLeft int, n int, err error) {
	m, n, err = readMsgFromUDPWithLimit(c, MaxUDPSize)
	return
}

func readMsgFromUDPWithLimit(c io.Reader, maxSize int) (m *bufpool.MsgBuf, n int, err error) {
	buf := bufpool.AcquireMsgBuf(maxSize)

	n, err = c.Read(buf.Bytes())
	if err != nil {
		bufpool.ReleaseMsgBuf(buf)
		return nil, n, err
	}
	if n < 12 {
		bufpool.ReleaseMsgBuf(buf)
		return nil, n, dns.ErrShortRead
	}
	buf.SetLength(n)
	return buf, n, err
}
