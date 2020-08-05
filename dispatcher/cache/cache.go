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
	"sync"
	"time"

	"github.com/IrineSistiana/mos-chinadns/dispatcher/pool"
	"github.com/IrineSistiana/mos-chinadns/dispatcher/utils"
	"github.com/miekg/dns"
)

type Cache struct {
	l            sync.RWMutex
	size         int
	writeCounter int

	m map[dns.Question]*elem
}

type elem struct {
	expiredAt time.Time
	m         *dns.Msg
}

func New(size int) *Cache {
	return &Cache{
		size: size,
		m:    make(map[dns.Question]*elem, size),
	}
}

// Add adds a copy of r to the cache
func (c *Cache) Add(q dns.Question, r *dns.Msg, expireAt time.Time) {
	if r == nil {
		return
	}

	c.l.Lock()
	defer c.l.Unlock()

	if c.writeCounter >= c.size/2 {
		c.scanAndEvict()
	}
	empty := c.size - len(c.m)
	if empty < 1 {
		c.evict(1 - empty)
	}

	rCopy := pool.GetMsg()
	r.CopyTo(rCopy)
	c.m[q] = &elem{m: rCopy, expiredAt: expireAt}
	c.writeCounter++
}

func (c *Cache) Get(q dns.Question) *dns.Msg {
	c.l.RLock()
	e, ok := c.m[q]
	c.l.RUnlock()

	if ok {
		ttl := e.expiredAt.Sub(time.Now())
		if ttl < time.Second { // expired
			pool.ReleaseMsg(e.m)

			c.l.Lock()
			delete(c.m, q)
			c.l.Unlock()
			return nil
		}
		r := new(dns.Msg)
		e.m.CopyTo(r)
		utils.SetAnswerTTL(r, uint32(ttl/time.Second)) // set rr ttl sections
		return r
	}

	return nil // not in the cache
}

func (c *Cache) Len() int {
	c.l.RLock()
	defer c.l.RUnlock()

	return len(c.m)
}

func (c *Cache) Reset() {
	c.l.Lock()
	defer c.l.Unlock()

	c.writeCounter = 0
	c.m = make(map[dns.Question]*elem, c.size)
}

func (c *Cache) evict(n int) {
	for k, e := range c.m {
		if n <= 0 {
			break
		}
		pool.ReleaseMsg(e.m)
		delete(c.m, k)
		n--
	}
}

func (c *Cache) scanAndEvict() {
	now := time.Now()
	for k, e := range c.m {
		if now.After(e.expiredAt) {
			pool.ReleaseMsg(e.m)
			delete(c.m, k)
		}
	}
	c.writeCounter = 0
}
