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
	"sync"
)

var (
	tcpHeaderBufPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 2)
		},
	}

	tcpWriteBufPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 2048)
		},
	}
)

func GetTCPHeaderBuf() []byte {
	return tcpHeaderBufPool.Get().([]byte)
}

func ReleaseTCPHeaderBuf(buf []byte) {
	tcpHeaderBufPool.Put(buf)
}

// GetTCPWriteBuf returns a 2048-byte slice buf
func GetTCPWriteBuf() []byte {
	return tcpWriteBufPool.Get().([]byte)
}

func ReleaseTCPWriteBuf(buf []byte) {
	if len(buf) != 2048 {
		panic("invalid buf size")
	}
	tcpWriteBufPool.Put(buf)
}
