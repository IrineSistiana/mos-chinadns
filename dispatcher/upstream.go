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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/IrineSistiana/mos-chinadns/dispatcher/logger"
	"github.com/IrineSistiana/mos-chinadns/dispatcher/upstream"
	"net"
	"sync"
	"time"

	"github.com/IrineSistiana/mos-chinadns/dispatcher/netlist"
	"golang.org/x/sync/singleflight"

	"github.com/IrineSistiana/mos-chinadns/dispatcher/pool"
	"github.com/miekg/dns"
	"golang.org/x/net/proxy"
)

type upstreamWithName interface {
	upstream.Upstream
	getName() string
}

// enhancedUpstream represents a mos-chinadns upstream.
type enhancedUpstream struct {
	name string

	edns0 struct {
		clientSubnet *dns.EDNS0_SUBNET
		overwriteECS bool
	}
	policies struct {
		ip     *ipPolicies
		domain *domainPolicies

		denyErrorRcode       bool
		denyUnhandlableTypes bool
		denyEmptyIPReply     bool
		checkCNAME           bool
	}

	deduplicate bool

	basicUpstream upstream.Upstream

	bk                *bucket
	singleFlightGroup singleflight.Group
}

func isUnhandlableType(q *dns.Msg) bool {
	return q.Opcode != dns.OpcodeQuery || len(q.Question) != 1 || q.Question[0].Qclass != dns.ClassINET || (q.Question[0].Qtype != dns.TypeA && q.Question[0].Qtype != dns.TypeAAAA)
}

var (
	errTooManyConcurrentQueries = errors.New("too many concurrent queries")
)

func (u *enhancedUpstream) getName() string {
	return u.name
}

func (u *enhancedUpstream) Exchange(ctx context.Context, q *dns.Msg) (r *dns.Msg, err error) {
	// deduplicate
	if u.deduplicate {
		key, err := getMsgKey(q)
		if err != nil {
			return nil, fmt.Errorf("failed to caculate msg key, %v", err)
		}

		v, err, shared := u.singleFlightGroup.Do(key, func() (interface{}, error) {
			defer u.singleFlightGroup.Forget(key)
			return u.exchange(ctx, q)
		})

		if err != nil {
			return nil, err
		}

		rUnsafe := v.(*dns.Msg)

		if rUnsafe == nil {
			return nil, nil
		}

		if shared { // shared reply may has different id and is not safe to modify.
			logger.GetStd().Debugf("upstream %s: [%v %d]: duplicate query, relay shared", u.name, q.Question, q.Id)
			r = rUnsafe.Copy()
			r.Id = q.Id
			return r, nil
		}

		return rUnsafe, nil
	}

	return u.exchange(ctx, q)
}

func (u *enhancedUpstream) exchange(ctx context.Context, q *dns.Msg) (r *dns.Msg, err error) {
	// get token
	if u.bk != nil {
		if u.bk.acquire() == false {
			return nil, errTooManyConcurrentQueries
		}
		defer u.bk.release()
	}

	// check msg type
	if isUnhandlableType(q) {
		if u.policies.denyUnhandlableTypes {
			logger.GetStd().Debugf("upstream %s: [%v %d]: query denied, query is unhandlable type", u.name, q.Question, q.Id)
			return nil, nil
		} else {
			logger.GetStd().Debugf("upstream %s: [%v %d]: query accepted, query is unhandlable type", u.name, q.Question, q.Id)
			return u.basicUpstream.Exchange(ctx, q)
		}
	}

	// check domain
	var domainPolicyAction = policyFinalActionOnHold
	if u.policies.domain != nil {
		domainPolicyAction = u.policies.domain.check(q.Question[0].Name)
		if domainPolicyAction == policyFinalActionDeny {
			logger.GetStd().Debugf("upstream %s: [%v %d]: query denied, matched my domain", u.name, q.Question, q.Id)
			return nil, nil
		}
	}

	// append edns0 client subnet
	if u.edns0.clientSubnet != nil {
		if checkMsgHasECS(q) == false || u.edns0.overwriteECS {
			q = q.Copy()
			applyECS(q, u.edns0.clientSubnet)
		}
	}

	// send to upstream
	r, err = u.basicUpstream.Exchange(ctx, q)
	if err != nil {
		return nil, err
	}

	// this reply should be accepted right away, skip other checks.
	if domainPolicyAction == policyFinalActionAccept {
		return r, nil
	}

	// check Rcode
	if u.policies.denyErrorRcode && r.Rcode != dns.RcodeSuccess {
		logger.GetStd().Debugf("upstream %s: [%v %d]: reply denied, rcode is %d", u.name, q.Question, q.Id, r.Rcode)
		return nil, nil
	}

	// check CNAME
	if u.policies.domain != nil && u.policies.checkCNAME == true {
		switch checkMsgCNAME(u.policies.domain, r) {
		case policyFinalActionDeny:
			logger.GetStd().Debugf("upstream %s: [%v %d]: reply denied, matched by cname", u.name, q.Question, q.Id)
			return nil, nil
		case policyFinalActionAccept:
			logger.GetStd().Debugf("upstream %s: [%v %d]: reply accepted, matched by cname", u.name, q.Question, q.Id)
			return r, nil
		}
	}

	// check ip
	if u.policies.denyEmptyIPReply && checkMsgHasValidIP(r) == false {
		logger.GetStd().Debugf("upstream %s: [%v %d]: reply denied, no valid ip", u.name, q.Question, q.Id)
		return nil, nil
	}
	if u.policies.ip != nil {
		if checkMsgIP(u.policies.ip, r) == policyFinalActionDeny {
			logger.GetStd().Debugf("upstream %s: [%v %d]: reply denied, matched by ip", u.name, q.Question, q.Id)
			return nil, nil
		}
	}

	return r, err
}

func getMsgKey(m *dns.Msg) (string, error) {
	l := m.Len()
	if l > dns.MaxMsgSize {
		return "", fmt.Errorf("m length %d is too large", l)
	}

	buf := pool.GetMsgBuf(l)
	defer pool.ReleaseMsgBuf(buf)

	mWithZeroID := pool.GetMsg()
	defer pool.ReleaseMsg(mWithZeroID)
	*mWithZeroID = *m  // shadow copy
	mWithZeroID.Id = 0 // change id to 0

	wireMsg, err := mWithZeroID.PackBuffer(buf)
	if err != nil {
		return "", err
	}
	return string(wireMsg), nil
}

// checkMsgIP checks m's ip RR in answer section. If ip is a
func checkMsgIP(p *ipPolicies, m *dns.Msg) policyFinalAction {
	for i := range m.Answer {
		var ip net.IP
		switch rr := m.Answer[i].(type) {
		case *dns.A:
			ip = rr.A
		case *dns.AAAA:
			ip = rr.AAAA
		default:
			continue
		}

		if ipv6 := ip.To16(); ipv6 == nil {
			logger.GetStd().Warnf("checkMsgIP: internal err: failed to convert ip %v to ipv6", ip)
			continue
		} else {
			ip = ipv6
		}

		pfa := p.check(netlist.Conv(ip))
		switch pfa {
		case policyFinalActionAccept, policyFinalActionDeny:
			return pfa
		default: // policyFinalActionOnHold
			continue
		}
	}
	return policyFinalActionOnHold
}

func checkMsgCNAME(p *domainPolicies, m *dns.Msg) policyFinalAction {
	for i := range m.Answer {
		if cname, ok := m.Answer[i].(*dns.CNAME); ok {
			pfa := p.check(cname.Target)
			switch pfa {
			case policyFinalActionAccept, policyFinalActionDeny:
				return pfa
			default: // policyFinalActionOnHold
				continue
			}
		}
	}
	return policyFinalActionOnHold
}

func checkMsgHasValidIP(m *dns.Msg) bool {
	for i := range m.Answer {
		switch m.Answer[i].(type) {
		case *dns.A, *dns.AAAA:
			return true
		default:
			continue
		}
	}
	return false
}

// NewUpstream inits a upstream instance base on the config.
// rootCAs will be used in dot/doh upstream in tls server verification.
func NewUpstream(name string, sc *BasicUpstreamConfig, rootCAs *x509.CertPool) (*enhancedUpstream, error) {
	if sc == nil {
		return nil, errors.New("no server config")
	}

	u := new(enhancedUpstream)
	u.name = name

	// set MaxConcurrentQueries
	if sc.MaxConcurrentQueries > 0 {
		u.bk = newBucket(sc.MaxConcurrentQueries)
	}

	// load edns0
	if len(sc.EDNS0.ClientSubnet) != 0 {
		subnet, err := newEDNS0SubnetFromStr(sc.EDNS0.ClientSubnet)
		if err != nil {
			return nil, fmt.Errorf("invaild ecs, %w", err)
		}
		u.edns0.clientSubnet = subnet
	}
	u.edns0.overwriteECS = sc.EDNS0.OverwriteECS

	// load policies
	if len(sc.Policies.IP) != 0 {
		p, err := newIPPolicies(sc.Policies.IP)
		if err != nil {
			return nil, fmt.Errorf("failed to load ip policies, %w", err)
		}
		u.policies.ip = p
	}
	if len(sc.Policies.Domain) != 0 {
		p, err := newDomainPolicies(sc.Policies.Domain)
		if err != nil {
			return nil, fmt.Errorf("failed to load domain policies, %w", err)
		}
		u.policies.domain = p
	}
	u.policies.checkCNAME = sc.Policies.CheckCNAME
	u.policies.denyUnhandlableTypes = sc.Policies.DenyUnhandlableTypes
	u.policies.denyErrorRcode = sc.Policies.DenyErrorRcode
	u.policies.denyEmptyIPReply = sc.Policies.DenyEmptyIPReply

	u.deduplicate = sc.Deduplicate

	switch sc.Protocol {
	case "udp", "":
		u.basicUpstream = upstream.NewUDPUpstream(sc.Addr)

	case "tcp":
		u.basicUpstream = upstream.NewTCPUpstream(sc.Addr, sc.Socks5, time.Duration(sc.TCP.IdleTimeout)*time.Second)

	case "dot":
		if len(sc.DoT.ServerName) == 0 {
			return nil, fmt.Errorf("dot server needs a server name")
		}
		tlsConf := &tls.Config{
			ServerName:         sc.DoT.ServerName,
			RootCAs:            rootCAs,
			ClientSessionCache: tls.NewLRUClientSessionCache(64),

			// for test only
			InsecureSkipVerify: sc.InsecureSkipVerify,
		}

		u.basicUpstream = upstream.NewDoTUpstream(sc.Addr, sc.Socks5, time.Duration(sc.TCP.IdleTimeout)*time.Second, tlsConf)

	case "doh":
		if len(sc.DoH.URL) == 0 {
			return nil, fmt.Errorf("protocol [%s] needs additional argument: url", sc.Protocol)
		}

		tlsConf := &tls.Config{
			// don't have to set servername here, net.http will do it itself.
			RootCAs:            rootCAs,
			ClientSessionCache: tls.NewLRUClientSessionCache(64),

			// for test only
			InsecureSkipVerify: sc.InsecureSkipVerify,
		}

		dialContext, err := getUpstreamDialContextFunc("tcp", sc.Addr, sc.Socks5)
		if err != nil {
			return nil, fmt.Errorf("failed to init dialContext: %v", err)
		}

		u.basicUpstream, err = upstream.NewDoHUpstream(sc.DoH.URL, dialContext, tlsConf)
		if err != nil {
			return nil, fmt.Errorf("failed to init DoH: %v", err)
		}

	default:
		return nil, fmt.Errorf("unsupport protocol: %s", sc.Protocol)
	}

	return u, nil
}

func getUpstreamDialContextFunc(network, dstAddress, sock5Address string) (func(ctx context.Context, _, _ string) (net.Conn, error), error) {
	if len(sock5Address) != 0 { // proxy through sock5
		d, err := proxy.SOCKS5(network, sock5Address, nil, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to init socks5 dialer: %v", err)
		}
		contextDialer, ok := d.(proxy.ContextDialer)
		if !ok {
			return nil, errors.New("internal err: socks5 dialer is not a proxy.ContextDialer")
		}
		return func(ctx context.Context, _, _ string) (net.Conn, error) {
			return contextDialer.DialContext(ctx, network, dstAddress)
		}, nil
	}
	return func(ctx context.Context, _, _ string) (net.Conn, error) {
		d := net.Dialer{}
		return d.DialContext(ctx, network, dstAddress)
	}, nil
}

type bucket struct {
	sync.Mutex
	i   int
	max int
}

func newBucket(max int) *bucket {
	return &bucket{
		i:   0,
		max: max,
	}
}

func (b *bucket) acquire() bool {
	b.Lock()
	defer b.Unlock()

	if b.i >= b.max {
		return false
	}

	b.i++
	return true
}

func (b *bucket) release() {
	b.Lock()
	defer b.Unlock()

	if b.i < 0 {
		panic("nagetive num in bucket")
	}

	b.i--
}
