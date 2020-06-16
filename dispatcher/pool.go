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
	"sync"
	"time"

	"github.com/IrineSistiana/mos-chinadns/dispatcher/bufpool"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

var (
	timerPool = sync.Pool{}
)

func getTimer(t time.Duration) *time.Timer {
	timer, ok := timerPool.Get().(*time.Timer)
	if !ok {
		return time.NewTimer(t)
	}
	if timer.Reset(t) {
		panic("dispatcher.go getTimer: active timer trapped in timerPool")
	}
	return timer
}

func releaseTimer(timer *time.Timer) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timerPool.Put(timer)
}

var notificationChanPool = sync.Pool{
	New: func() interface{} {
		return make(chan notification, 1)
	},
}

func getNotificationChan() chan notification {
	return notificationChanPool.Get().(chan notification)
}

func releaseNotificationChan(c chan notification) {
	for {
		select {
		case <-c:
		default:
			notificationChanPool.Put(c)
			return
		}
	}
}

var resChanPool = sync.Pool{
	New: func() interface{} {
		return make(chan *bufpool.MsgBuf, 1)
	},
}

func getResChan() chan *bufpool.MsgBuf {
	return resChanPool.Get().(chan *bufpool.MsgBuf)
}

func releaseResChan(c chan *bufpool.MsgBuf) {
	for {
		select {
		case rRaw := <-c:
			if rRaw != nil {
				bufpool.ReleaseMsgBuf(rRaw)
			}
		default:
			resChanPool.Put(c)
			return
		}
	}
}

var dnsMsgPool = sync.Pool{
	New: func() interface{} {
		return new(dns.Msg)
	},
}

func getMsg() *dns.Msg {
	return dnsMsgPool.Get().(*dns.Msg)
}

func releaseMsg(m *dns.Msg) {
	m.Question = nil
	m.Answer = nil
	m.Ns = nil
	m.Extra = nil
	dnsMsgPool.Put(m)
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

func (d *Dispatcher) getRequestLogger(q *dns.Msg) *logrus.Entry {
	entry := requestLoggerPool.Get().(*logrus.Entry)
	f := entry.Data
	f["id"] = q.Id
	f["question"] = q.Question
	entry.Logger = d.entry.Logger
	return entry
}

func releaseRequestLogger(entry *logrus.Entry) {
	f := entry.Data
	f["id"] = nil
	f["question"] = nil
	entry.Logger = nil
	requestLoggerPool.Put(entry)
}

var (
	// []byte with len() = 2
	tcpHeaderBufPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 2)
		},
	}
)

func getTCPHeaderBuf() []byte {
	return tcpHeaderBufPool.Get().([]byte)
}

func releaseTCPHeaderBuf(buf []byte) {
	tcpHeaderBufPool.Put(buf)
}
