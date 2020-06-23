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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/IrineSistiana/mos-chinadns/dispatcher/bufpool"

	"github.com/IrineSistiana/mos-chinadns/dispatcher/domainlist"

	"github.com/sirupsen/logrus"

	netlist "github.com/IrineSistiana/net-list"

	"github.com/miekg/dns"
)

func Test_dispatcher(t *testing.T) {
	logrus.SetLevel(logrus.WarnLevel)

	testDispatcher := func(testID, domain string, ll, rl int, lIP, rIP net.IP, want uint8, ipPo *ipPolicies, doPo *domainPolicies) {
		d, err := initTestDispatherAndServer(time.Duration(ll)*time.Millisecond, time.Duration(rl)*time.Millisecond, lIP, rIP, ipPo, doPo)
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

const (
	benchFlow uint8 = iota
	benchConcurrent
	benchConcurrentCPUThread
)

func bench(testID string, mode uint8, b *testing.B, domain string, ll, rl int, lIP, rIP net.IP, ipPo *ipPolicies, doPo *domainPolicies) {
	q := new(dns.Msg).SetQuestion(dns.Fqdn(domain), dns.TypeA)
	qRaw, err := q.Pack()
	if err != nil {
		b.Fatalf("[%s] q.Pack: %v", testID, err)
	}

	r := new(dns.Msg)
	r.SetReply(q)
	var rr dns.RR
	hdr := dns.RR_Header{
		Name:     q.Question[0].Name,
		Class:    dns.ClassINET,
		Ttl:      300,
		Rdlength: 0,
	}
	hdr.Rrtype = dns.TypeA

	rr = &dns.A{Hdr: hdr, A: net.IPv4(222, 222, 222, 222)}
	r.Answer = append(r.Answer, rr)
	rRawBytes, err := r.Pack()
	if err != nil {
		b.Fatalf("[%s] Pack, %v", testID, err)
	}

	d, err := initBenchDispatherAndServer(rRawBytes)
	if err != nil {
		b.Fatalf("[%s] init dispatcher, %v", testID, err)
	}

	b.ResetTimer()
	switch mode {
	case benchFlow:
		for i := 0; i < b.N; i++ {
			rRaw, err := d.serveRawDNS(context.Background(), q.CopyTo(getMsg()), bufpool.AcquireMsgBufAndCopy(qRaw))
			if err != nil {
				b.Fatal(err)
			}
			bufpool.ReleaseMsgBuf(rRaw)
		}
	case benchConcurrent:
		wg := sync.WaitGroup{}
		var ec int32
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			for j := 0; j < 1000; j++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					rRaw, err := d.serveRawDNS(context.Background(), q.CopyTo(getMsg()), bufpool.AcquireMsgBufAndCopy(qRaw))
					if err != nil {
						atomic.AddInt32(&ec, 1)
						// panic("err")
					}
					bufpool.ReleaseMsgBuf(rRaw)
				}()
			}
			wg.Wait()
		}
		if ec > 0 {
			b.Fatal(fmt.Sprintf("err: %d\n", ec))
		}
	case benchConcurrentCPUThread:
		var ec int32
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				rRaw, err := d.serveRawDNS(context.Background(), q.CopyTo(getMsg()), bufpool.AcquireMsgBufAndCopy(qRaw))
				if err != nil {
					atomic.AddInt32(&ec, 1)
				}
				bufpool.ReleaseMsgBuf(rRaw)
			}
		})
		if ec > 0 {
			b.Fatal(fmt.Sprintf("err: %d\n", ec))
		}
	}
}

func Benchmark_dispatcher_flow(b *testing.B) {
	logrus.SetLevel(logrus.WarnLevel)
	b.ReportAllocs()

	bench("dp", benchFlow, b, "test.com", 0, 0, ip("0.0.0.1"), ip("0.0.0.2"), nil, genTestDomainPolicies("", "com", "cn"))
}

func Benchmark_dispatcher_concurrent(b *testing.B) {
	logrus.SetLevel(logrus.WarnLevel)
	b.ReportAllocs()

	bench("dp", benchConcurrent, b, "test.com", 0, 0, ip("0.0.0.1"), ip("0.0.0.2"), nil, genTestDomainPolicies("", "com", "cn"))
}

func Benchmark_dispatcher_concurrent_cpu_thread(b *testing.B) {
	logrus.SetLevel(logrus.WarnLevel)
	b.ReportAllocs()

	bench("dp", benchConcurrentCPUThread, b, "test.com", 0, 0, ip("0.0.0.1"), ip("0.0.0.2"), nil, genTestDomainPolicies("", "com", "cn"))
}

///////////////////////////////////////////

type fakeUpstream struct {
	latency time.Duration
	ip      net.IP
	rRaw    []byte
}

func (u *fakeUpstream) Exchange(ctx context.Context, qRaw []byte) (rRaw *bufpool.MsgBuf, err error) {
	if u.rRaw != nil {
		return bufpool.AcquireMsgBufAndCopy(u.rRaw), nil
	}

	q := new(dns.Msg)
	err = q.Unpack(qRaw)
	if err != nil {
		return nil, err
	}
	name := q.Question[0].Name
	r := new(dns.Msg)
	r.SetReply(q)
	var rr dns.RR
	hdr := dns.RR_Header{
		Name:     name,
		Class:    dns.ClassINET,
		Ttl:      300,
		Rdlength: 0,
	}
	hdr.Rrtype = dns.TypeA

	rr = &dns.A{Hdr: hdr, A: u.ip}
	r.Answer = append(r.Answer, rr)
	rRawBytes, err := r.Pack()
	time.Sleep(u.latency)
	if err != nil {
		return nil, err
	}

	return bufpool.AcquireMsgBufAndCopy(rRawBytes), err
}

func initBenchDispatherAndServer(rRaw []byte) (*Dispatcher, error) {
	ipPo, err := newIPPolicies("accept:../chn.list|deny_all", logrus.NewEntry(logrus.StandardLogger()))
	if err != nil {
		return nil, fmt.Errorf("loading ip policies, %w", err)
	}
	doPo, err := newDomainPolicies("force:../chn_domain.list", logrus.NewEntry(logrus.StandardLogger()))
	if err != nil {
		return nil, fmt.Errorf("loading domain policies, %w", err)
	}
	return initDispatherAndServer(0, 0, nil, nil, ipPo, doPo, rRaw)
}
func initTestDispatherAndServer(lLatency, rLatency time.Duration, lIP, rIP net.IP, ipPo *ipPolicies, doPo *domainPolicies) (*Dispatcher, error) {
	return initDispatherAndServer(lLatency, rLatency, lIP, rIP, ipPo, doPo, nil)
}
func initDispatherAndServer(lLatency, rLatency time.Duration, lIP, rIP net.IP, ipPo *ipPolicies, doPo *domainPolicies, rRaw []byte) (*Dispatcher, error) {
	c := Config{}

	// just set the vaule for initDispatcher() inner checks, we will hijeck the upstream later.
	c.Server.Local.Addr = "127.0.0.1:0"
	c.Server.Remote.Addr = "127.0.0.1:0"
	c.Bind.Addr = "127.0.0.1:0"

	c.ECS.Local = "1.2.3.0/24"
	c.ECS.Remote = "4.3.2.0/24"

	d, err := InitDispatcher(&c, logrus.NewEntry(logrus.StandardLogger()))
	if err != nil {
		return nil, err
	}

	d.local.ipPolicies = ipPo
	d.local.domainPolicies = doPo

	d.local.client = &fakeUpstream{latency: lLatency, ip: lIP, rRaw: rRaw}
	d.remote.client = &fakeUpstream{latency: rLatency, ip: rIP, rRaw: rRaw}

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
