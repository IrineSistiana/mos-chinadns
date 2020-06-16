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

package bufpool

import (
	"fmt"
	"sync"

	"github.com/miekg/dns"
)

var packBufPool = sync.Pool{}

// AcquirePackBuf should only be used by dns.Msg.PackBuffer()
func AcquirePackBuf() []byte {
	buf, _ := packBufPool.Get().([]byte)
	return buf // it's ok that buf is nil
}

func AcquirePackBufAndPack(m *dns.Msg) ([]byte, error) {
	buf := AcquirePackBuf()
	mRaw, err := m.PackBuffer(buf)
	if err != nil {
		ReleasePackBuf(buf)
		return nil, err
	}

	if len(mRaw) > dns.MaxMsgSize { // seems PackBuffer won't check msg size
		ReleasePackBuf(mRaw)
		return nil, fmt.Errorf("msg wire size %d is bigger than dns.MaxMsgSize", len(mRaw))
	}
	return mRaw, nil
}

// ReleasePackBuf should only releases the buf returned by dns.Msg.PackBuffer()
func ReleasePackBuf(buf []byte) {
	bufCap := cap(buf)
	if cap(buf) > 0 {
		packBufPool.Put(buf[:bufCap])
	}
}
