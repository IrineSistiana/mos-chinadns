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

package cache

import (
	"github.com/miekg/dns"
	"strconv"
	"testing"
	"time"
)

func TestCache(t *testing.T) {
	size := 8
	c := New(size)

	// add
	q := dns.Question{Name: "example.com."}
	c.Add(q, nil, time.Now().Add(time.Minute)) // add a nil msg
	if c.Len() != 0 {
		t.Fatal("nil msg was added to cache")
	}
	c.Add(q, new(dns.Msg), time.Time{}) // add a expired msg
	if c.Len() != 0 {
		t.Fatal("expired msg was added to cache")
	}

	for i := 0; i < size*2; i++ {
		q := dns.Question{Name: strconv.Itoa(i)}
		c.Add(q, new(dns.Msg), time.Now().Add(time.Minute))
	}
	if c.Len() != size {
		t.Fatal("cache is bigger than its size limit")
	}

	// get
	c.Add(q, new(dns.Msg), time.Now().Add(time.Minute)) // add a nil msg
	if c.Get(q, 0) == nil {
		t.Fatal("cache Get failed")
	}
}
