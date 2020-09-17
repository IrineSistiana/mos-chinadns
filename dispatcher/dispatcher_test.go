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
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func Test_dispatch(t *testing.T) {
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.ClassINET)

	u1ip := net.ParseIP("1.2.3.4")
	u2ip := net.ParseIP("4.3.2.1")

	d := new(Dispatcher)
	d.entriesSlice = make([]*upstreamEntry, 0)
	d.entriesSlice = append(d.entriesSlice, &upstreamEntry{backend: &fakeUpstream{latency: time.Millisecond * 0, ip: u1ip}})
	d.entriesSlice = append(d.entriesSlice, &upstreamEntry{backend: &fakeUpstream{latency: time.Millisecond * 300, ip: u2ip}})

	r, err := d.dispatch(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}

	if r.Answer[0].(*dns.A).A.Equal(u1ip) == false {
		t.Fatal("expect u1, but got something else")
	}
}

type fakeUpstream struct {
	latency time.Duration
	ip      net.IP
}

func (u *fakeUpstream) getName() string {
	return "fake upstream"
}

func (u *fakeUpstream) Exchange(_ context.Context, q *dns.Msg) (r *dns.Msg, err error) {
	r = new(dns.Msg)
	r.SetReply(q)

	rr := &dns.A{Hdr: dns.RR_Header{
		Name:     q.Question[0].Name,
		Rrtype:   dns.TypeA,
		Class:    dns.ClassINET,
		Ttl:      300,
		Rdlength: 0,
	}, A: u.ip}
	r.Answer = append(r.Answer, rr)

	time.Sleep(u.latency)

	return r, err
}
