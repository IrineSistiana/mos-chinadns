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

//     This file is a modified version from github.com/xtaci/smux/blob/master/alloc.go f386d90
//     license of smux: MIT https://github.com/xtaci/smux/blob/master/LICENSE

package bufpool

import (
	"sync"
)

var (
	defaultAllocator = newAllocator()
)

type Allocator struct {
	buffers []sync.Pool
}

type MsgBuf struct {
	B []byte
}

// newAllocator initiates a []byte allocator for dns.Msg less than 65536 bytes,
// the waste(memory fragmentation) of space allocation is guaranteed to be
// no more than 50%.
func newAllocator() *Allocator {
	alloc := new(Allocator)
	alloc.buffers = make([]sync.Pool, 17) // 1B -> 64K
	for k := range alloc.buffers {
		i := k
		alloc.buffers[k].New = func() interface{} {
			return &MsgBuf{B: make([]byte, 1<<uint32(i))}
		}
	}
	return alloc
}

func AcquireMsgBuf(size int) *MsgBuf {
	return defaultAllocator.get(size)
}

func AcquireMsgBufAndCopy(src []byte) *MsgBuf {
	if src == nil {
		return nil
	}
	dst := AcquireMsgBuf(len(src))
	copy(dst.B, src)
	return dst
}

func ReleaseMsgBuf(buf *MsgBuf) {
	defaultAllocator.put(buf)
}

// get a *MsgBuf from pool with most appropriate cap
func (alloc *Allocator) get(size int) *MsgBuf {
	if size <= 0 || size > 65536 {
		panic("unexpected size")
	}

	var buf *MsgBuf
	bits := msb(size)
	if size == 1<<bits {
		buf = alloc.buffers[bits].Get().(*MsgBuf)
	} else {
		buf = alloc.buffers[bits+1].Get().(*MsgBuf)
	}
	buf.B = buf.B[:size]
	return buf
}

// put returns a *MsgBuf to pool for future use,
// which the cap must be exactly 2^n
func (alloc *Allocator) put(buf *MsgBuf) {
	bits := msb(cap(buf.B))
	if cap(buf.B) == 0 || cap(buf.B) > 65536 || cap(buf.B) != 1<<bits {
		panic("unexpected cap size")
	}
	alloc.buffers[bits].Put(buf)
}

// msb return the pos of most significiant bit
func msb(size int) uint16 {
	var pos uint16
	size >>= 1
	for size > 0 {
		size >>= 1
		pos++
	}
	return pos
}
