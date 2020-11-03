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

package matcher

import (
	"github.com/IrineSistiana/mos-chinadns/dispatcher/logger"
	"github.com/IrineSistiana/mos-chinadns/dispatcher/utils"
	"io/ioutil"
	"os"
	"time"
)

var matcherCache = utils.NewCache()

func loadFromCacheOrRawDisk(file string) (interface{}, []byte, error) {
	// load from cache
	data, ok := loadFromCache(file)
	if ok {
		return data, nil, nil
	}

	// load from disk
	logger.GetStd().Infof("loadFromCacheOrRawDisk: open file %s", file)
	f, err := os.Open(file)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	b, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, nil, err
	}

	return nil, b, nil
}

func loadFromCache(key string) (interface{}, bool) {
	return matcherCache.Load(key)
}

func cacheData(key string, value interface{}) {
	matcherCache.Put(key, value, time.Second*15)
}
