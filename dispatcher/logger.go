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
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"sync"
)

var (
	logger = logrus.New()
)

func SetLoggerLevel(level logrus.Level) {
	logger.SetLevel(level)
}

var requestLoggerPool = sync.Pool{
	New: func() interface{} {
		f := make(logrus.Fields, 3+2) // default is three fields, we add 2 more
		f["id"] = nil
		f["question"] = nil
		e := &logrus.Entry{
			Data: f,
		}
		return e
	},
}

func getRequestLogger(q *dns.Msg) *logrus.Entry {
	entry := requestLoggerPool.Get().(*logrus.Entry)
	entry.Logger = logger
	entry.Data["id"] = q.Id
	entry.Data["question"] = q.Question
	return entry
}

func releaseRequestLogger(entry *logrus.Entry) {
	entry.Data["id"] = nil
	entry.Data["question"] = nil
	entry.Logger = nil
	requestLoggerPool.Put(entry)
}
