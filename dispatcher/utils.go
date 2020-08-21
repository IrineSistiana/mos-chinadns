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
	"github.com/IrineSistiana/mos-chinadns/dispatcher/pool"
	"github.com/miekg/dns"
	"io"
)

const (
	unknownBrokenDataSize = -1
)

// readMsgFromTCP reads msg from a tcp connection.
// brokenDataLeft indicates the frame size which have not be read from c.
// if brokenDataLeft is unknownBrokenDataSize(-1), c should not be reused anymore.
// n represents how many bytes are read from c.
func readMsgFromTCP(c io.Reader) (m *dns.Msg, brokenDataLeft int, n int, err error) {
	lengthRaw := pool.GetTCPHeaderBuf()
	defer pool.ReleaseTCPHeaderBuf(lengthRaw)

	n1, err := io.ReadFull(c, lengthRaw)
	n = n + n1
	if err != nil {
		if n1 != 0 {
			return nil, unknownBrokenDataSize, n, err
		}
		return nil, 0, n, err
	}

	// dns length
	length := binary.BigEndian.Uint16(lengthRaw)
	if length < 12 {
		return nil, unknownBrokenDataSize, n, dns.ErrShortRead
	}

	buf := pool.GetMsgBuf(int(length))
	defer pool.ReleaseMsgBuf(buf)

	n2, err := io.ReadFull(c, buf)
	n = n + n2
	if err != nil {
		return nil, int(length) - n2, n, err
	}

	m = new(dns.Msg)
	err = m.Unpack(buf)
	if err != nil {
		return nil, int(length) - n2, n, err
	}
	return m, 0, n, nil
}

var errMsgTooBig = errors.New("payload is bigger than dns.MaxMsgSize")

// writeMsgToTCP writes m to c.
// n represents how many bytes are wrote to c. This includes 2 bytes tcp length header.
func writeMsgToTCP(c io.Writer, m *dns.Msg) (n int, err error) {
	buf := pool.AcquirePackBuf()
	defer pool.ReleasePackBuf(buf)

	mRaw, err := m.PackBuffer(buf)
	if err != nil {
		return 0, err
	}

	return writeRawMsgToTCP(c, mRaw)
}

// writeRawMsgToTCP writes b to c.
// n represents how many bytes are wrote to c. This includes 2 bytes tcp length header.
func writeRawMsgToTCP(c io.Writer, b []byte) (n int, err error) {
	if len(b) > dns.MaxMsgSize {
		return 0, errMsgTooBig
	}

	wb := pool.GetTCPWriteBuf()
	defer pool.ReleaseTCPWriteBuf(wb)

	wb[0] = byte(len(b) >> 8)
	wb[1] = byte(len(b))
	nc := copy(wb[2:], b)
	nw, err := c.Write(wb[:2+nc]) // write first chunk
	n = n + nw
	if err != nil {
		return
	}

	if len(b) > nw { // write remaining data
		nw, err := c.Write(b[nw:])
		n = n + nw
		return n, err
	}
	return
}

func readMsgFromUDP(c io.Reader) (m *dns.Msg, _ int, n int, err error) {
	m, n, err = readMsgFromUDPWithLimit(c, MaxUDPSize)
	return m, 0, n, err
}

func readMsgFromUDPWithLimit(c io.Reader, maxSize int) (m *dns.Msg, n int, err error) {
	buf := pool.GetMsgBuf(maxSize)
	defer pool.ReleaseMsgBuf(buf)

	n, err = c.Read(buf)
	if err != nil {
		return nil, n, err
	}
	if n < 12 {
		return nil, n, dns.ErrShortRead
	}

	m = new(dns.Msg)
	err = m.Unpack(buf[:n])
	if err != nil {
		return nil, n, err
	}
	return m, n, nil
}

func writeMsgToUDP(c io.Writer, m *dns.Msg) (n int, err error) {
	buf := pool.AcquirePackBuf()
	defer pool.ReleasePackBuf(buf)

	mRaw, err := m.PackBuffer(buf)
	if err != nil {
		return 0, err
	}

	return writeRawMsgToUDP(c, mRaw)
}

func writeRawMsgToUDP(c io.Writer, b []byte) (n int, err error) {
	return c.Write(b)
}
