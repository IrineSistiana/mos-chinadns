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

	"github.com/miekg/dns"
)

var (
	defaultallocator = newAllocator()
)

type allocator struct {
	buffers []sync.Pool
}

// newAllocator initiates a []byte allocator for dns.Msg less than 65536 bytes,
// the waste(memory fragmentation) of space allocation is guaranteed to be
// no more than 50%.
func newAllocator() *allocator {
	alloc := new(allocator)
	alloc.buffers = make([]sync.Pool, 17) // 1B -> 64K
	for k := range alloc.buffers {
		i := k
		alloc.buffers[k].New = func() interface{} {
			return &MsgBuf{buf: make([]byte, 1<<uint32(i))}
		}
	}
	return alloc
}

type MsgBuf struct {
	buf  []byte
	size int
}

func AcquireMsgBuf(size int) *MsgBuf {
	return defaultallocator.get(size)
}

func AcquireMsgBufAndCopy(src []byte) *MsgBuf {
	if src == nil {
		return nil
	}
	dst := AcquireMsgBuf(len(src))
	copy(dst.buf, src)
	return dst
}

func AcquireMsgBufAndPack(m *dns.Msg) (*MsgBuf, error) {
	buf := AcquirePackBuf()
	mRaw, err := m.PackBuffer(buf)
	if err != nil {
		ReleasePackBuf(buf)
		return nil, err
	}
	msgBuf := AcquireMsgBufAndCopy(mRaw)
	ReleasePackBuf(mRaw)
	return msgBuf, nil
}

func ReleaseMsgBuf(buf *MsgBuf) {
	defaultallocator.put(buf)
}

func (b *MsgBuf) Bytes() []byte {
	return b.buf[:b.size]
}

func (b *MsgBuf) SetSize(n int) {
	if n > len(b.buf) {
		panic("buffer overflow")
	}
	b.size = n
}

func (b *MsgBuf) Size() int {
	return b.size
}

// get a *MsgBuf from pool with most appropriate cap
func (alloc *allocator) get(size int) *MsgBuf {
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
	buf.size = size
	return buf
}

// put returns a *MsgBuf to pool for future use,
// which the cap must be exactly 2^n
func (alloc *allocator) put(b *MsgBuf) {
	bits := msb(cap(b.buf))
	if cap(b.buf) == 0 || cap(b.buf) > 65536 || cap(b.buf) != 1<<bits {
		panic("unexpected cap size")
	}
	alloc.buffers[bits].Put(b)
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
