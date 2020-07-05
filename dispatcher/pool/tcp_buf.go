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

package pool

import (
	"fmt"
	"github.com/miekg/dns"
	"sync"
)

var (
	tcpHeaderBufPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 2)
		},
	}

	// for msg that small or equal than 2kb
	tcpWriteSmallBufPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 2048)
		},
	}

	// for msg that bigger than 2kb, return a 64kb + 2byte buf
	tcpWriteLargeBufPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, dns.MaxMsgSize+2)
		},
	}
)

func GetTCPHeaderBuf() []byte {
	return tcpHeaderBufPool.Get().([]byte)
}

func ReleaseTCPHeaderBuf(buf []byte) {
	tcpHeaderBufPool.Put(buf)
}

func GetTCPWriteBuf(l int) []byte {
	if l > dns.MaxMsgSize+2 || l <= 0 {
		panic(fmt.Sprintf("pool GetTCPWriteBuf: invalid buf size %d", l))
	}

	if l <= 2048 {
		return tcpWriteSmallBufPool.Get().([]byte)[:l]
	}
	return tcpWriteLargeBufPool.Get().([]byte)[:l]
}

func ReleaseTCPWriteBuf(buf []byte) {
	c := cap(buf)
	buf = buf[:c]
	switch c {
	case 2048:
		tcpWriteSmallBufPool.Put(buf)
	case dns.MaxMsgSize + 2:
		tcpWriteLargeBufPool.Put(buf)
	default:
		panic(fmt.Sprintf("pool ReleaseTCPWriteBuf: invalid buf size %d", c))
	}
}
