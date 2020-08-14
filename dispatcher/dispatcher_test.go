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
	"bytes"
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/IrineSistiana/mos-chinadns/dispatcher/domainlist"

	"github.com/sirupsen/logrus"

	netlist "github.com/IrineSistiana/net-list"

	"github.com/miekg/dns"
)

func Test_dispatcher(t *testing.T) {
	logrus.SetLevel(logrus.WarnLevel)

	testDispatcher := func(testID, domain string, ll, rl int, lIP, rIP net.IP, want uint8, ipPo *ipPolicies, doPo *domainPolicies) {
		d, err := initTestDispatcherAndServer(time.Duration(ll)*time.Millisecond, time.Duration(rl)*time.Millisecond, lIP, rIP, ipPo, doPo)
		if err != nil {
			t.Fatalf("[%s] init dispatcher, %v", testID, err)
		}

		q := new(dns.Msg)
		q.SetQuestion(dns.Fqdn(domain), dns.TypeA)
		r, err := d.ServeDNS(context.Background(), q)
		if err != nil {
			t.Fatal(err)
		}

		a := r.Answer[0].(*dns.A)
		var w net.IP
		if want == wantLocal {
			w = lIP
		} else {
			w = rIP
		}
		if !a.A.Equal(w) {
			t.Fatalf("[%s] not the server we want, want: %s, got %s", testID, w, a.A)
		}
	}

	// FastServer

	//应该接受local的回复
	testDispatcher("fs1", "test.com", 0, 500, ip("0.0.0.1"), ip("0.0.0.2"), wantLocal, nil, nil)

	//应该接受remote的回复
	testDispatcher("fs2", "test.com", 500, 0, ip("0.0.0.1"), ip("0.0.0.2"), wantRemote, nil, nil)

	// ip policies

	//即使local延时更低，但结果被过滤，应该接受remote的回复
	testDispatcher("ip1", "test.com", 0, 500, ip("192.168.1.1"), ip("0.0.0.2"), wantRemote, genTestIPPolicies("192.168.0.0/24", ""), nil)
	testDispatcher("ip2", "test.com", 0, 500, ip("192.168.1.1"), ip("0.0.0.2"), wantRemote, genTestIPPolicies("192.168.0.0/16", "192.168.1.0/24"), nil)
	//允许的IP, 接受
	testDispatcher("ip3", "test.com", 0, 500, ip("192.168.0.1"), ip("0.0.0.2"), wantLocal, genTestIPPolicies("192.168.0.0/24", "192.168.1.0/24"), nil)

	// domain policies

	//forced local
	testDispatcher("dp1", "test.com", 500, 0, ip("0.0.0.1"), ip("0.0.0.2"), wantLocal, nil, genTestDomainPolicies("com", "", ""))
	testDispatcher("dp2", "test.cn", 500, 0, ip("0.0.0.1"), ip("0.0.0.2"), wantRemote, nil, genTestDomainPolicies("com", "", ""))

	testDispatcher("dp3", "test.com", 0, 500, ip("0.0.0.1"), ip("0.0.0.2"), wantLocal, nil, genTestDomainPolicies("", "com", ""))
	testDispatcher("dp4", "test.com", 500, 0, ip("0.0.0.1"), ip("0.0.0.2"), wantRemote, nil, genTestDomainPolicies("", "com", ""))

	testDispatcher("dp5", "test.cn", 0, 500, ip("0.0.0.1"), ip("0.0.0.2"), wantRemote, nil, genTestDomainPolicies("", "com", "cn"))

}

///////////////////////////////////////////

type fakeUpstream struct {
	latency time.Duration
	ip      net.IP
}

func (u *fakeUpstream) Exchange(ctx context.Context, q *dns.Msg) (r *dns.Msg, err error) {
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

func initTestDispatcherAndServer(lLatency, rLatency time.Duration, lIP, rIP net.IP, ipPo *ipPolicies, doPo *domainPolicies) (*Dispatcher, error) {
	c := Config{}

	// just set the value for initDispatcher() inner checks, we will hijack the upstream later.
	c.Server.Local.Addr = "127.0.0.1:0"
	c.Server.Remote.Addr = "127.0.0.1:0"

	d, err := InitDispatcher(&c, logrus.NewEntry(logrus.StandardLogger()))
	if err != nil {
		return nil, err
	}

	d.local.ipPolicies = ipPo
	d.local.domainPolicies = doPo

	d.local.client = &fakeUpstream{latency: lLatency, ip: lIP}
	d.remote.client = &fakeUpstream{latency: rLatency, ip: rIP}

	return d, nil
}

// deny -> accept -> deny all
func genTestIPPolicies(accept, deny string) *ipPolicies {
	acceptList, err := netlist.NewListFromReader(bytes.NewReader([]byte(accept)))
	if err != nil {
		panic(err.Error)
	}

	denyList, err := netlist.NewListFromReader(bytes.NewReader([]byte(deny)))
	if err != nil {
		panic(err.Error)
	}
	p := &ipPolicies{}
	p.policies = append(p.policies, ipPolicy{action: policyActionDeny, list: denyList})
	p.policies = append(p.policies, ipPolicy{action: policyActionAccept, list: acceptList})
	p.policies = append(p.policies, ipPolicy{action: policyActionDenyAll})
	return p
}

// deny -> accept -> force -> accept all
func genTestDomainPolicies(force, accept, deny string) *domainPolicies {
	acceptList, err := domainlist.LoadFormReader(bytes.NewReader([]byte(accept)))
	if err != nil {
		panic(err.Error)
	}

	denyList, err := domainlist.LoadFormReader(bytes.NewReader([]byte(deny)))
	if err != nil {
		panic(err.Error)
	}

	forceList, err := domainlist.LoadFormReader(bytes.NewReader([]byte(force)))
	if err != nil {
		panic(err.Error)
	}
	p := &domainPolicies{}
	p.policies = append(p.policies, domainPolicy{action: policyActionDeny, list: denyList})
	p.policies = append(p.policies, domainPolicy{action: policyActionAccept, list: acceptList})
	p.policies = append(p.policies, domainPolicy{action: policyActionForce, list: forceList})
	return p
}

var ip = func(s string) net.IP {
	ip := net.ParseIP(s)
	if ip == nil {
		panic(fmt.Sprintf("invalid ip: %s", s))
	}
	return ip
}

const (
	wantLocal uint8 = iota
	wantRemote
)
