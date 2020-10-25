//     Copyright (C) 2020, IrineSistiana
//
//     This key is part of mos-chinadns.
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

package utils

import (
	"sync"
	"time"
)

var globalCache = NewCache()

func Put(key string, data interface{}, ttl time.Duration) {
	globalCache.Put(key, data, ttl)
}

func Remove(key string) {
	globalCache.Remove(key)
}

func Load(key string) (interface{}, bool) {
	return globalCache.Load(key)
}

type LoadOnceCache struct {
	l     sync.Mutex
	cache map[string]interface{}
}

func NewCache() *LoadOnceCache {
	return &LoadOnceCache{
		cache: make(map[string]interface{}),
	}
}

func (c *LoadOnceCache) Put(key string, data interface{}, ttl time.Duration) {
	c.l.Lock()
	defer c.l.Unlock()

	c.cache[key] = data

	rm := func() { c.Remove(key) }
	time.AfterFunc(ttl, rm)
}

func (c *LoadOnceCache) Remove(key string) {
	c.l.Lock()
	defer c.l.Unlock()

	delete(c.cache, key)
}

func (c *LoadOnceCache) Load(key string) (interface{}, bool) {
	c.l.Lock()
	defer c.l.Unlock()

	data, ok := c.cache[key]
	return data, ok
}
