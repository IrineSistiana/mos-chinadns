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
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/IrineSistiana/mos-chinadns/dispatcher/bufpool"
	"github.com/IrineSistiana/mos-chinadns/dispatcher/domainlist"

	"github.com/miekg/dns"

	netlist "github.com/IrineSistiana/net-list"
	"github.com/sirupsen/logrus"
)

const (
	// MaxUDPSize max udp packet size
	MaxUDPSize = 1480

	queryTimeout = time.Second * 3
)

var (
	// ErrServerFailed all upstreams are failed
	ErrServerFailed = errors.New("server failed")
)

// Dispatcher represents a dns query dispatcher
type Dispatcher struct {
	entry                *logrus.Entry
	maxConcurrentQueries int

	local struct {
		client Upstream

		denyUnusualTypes    bool
		denyResultWithoutIP bool
		checkCNAME          bool
		ipPolicies          *ipPolicies
		domainPolicies      *domainPolicies
	}

	remote struct {
		client     Upstream
		delayStart time.Duration
	}

	ecs struct {
		local  *edns0subnet
		remote *edns0subnet
	}
}

type edns0subnet struct {
	subnet *dns.EDNS0_SUBNET
	opt    *dns.OPT
}

func newEDNS0subnet(subnet *dns.EDNS0_SUBNET) *edns0subnet {
	e := new(edns0subnet)
	o := new(dns.OPT)
	o.SetUDPSize(MaxUDPSize)
	o.Hdr.Name = "."
	o.Hdr.Rrtype = dns.TypeOPT
	o.Option = []dns.EDNS0{subnet}
	e.subnet = subnet
	e.opt = o
	return e
}

// InitDispatcher inits a dispatche from configuration
func InitDispatcher(conf *Config, entry *logrus.Entry) (*Dispatcher, error) {
	d := new(Dispatcher)
	d.entry = entry
	if conf.Dispatcher.MaxConcurrentQueries <= 0 {
		d.maxConcurrentQueries = 150
	} else {
		d.maxConcurrentQueries = conf.Dispatcher.MaxConcurrentQueries
	}

	var rootCAs *x509.CertPool
	var err error
	if len(conf.CA.Path) != 0 {
		rootCAs, err = caPath2Pool(conf.CA.Path)
		if err != nil {
			return nil, fmt.Errorf("caPath2Pool: %w", err)
		}
		d.entry.Info("initDispatcher: CA cert loaded")
	}

	if len(conf.Server.Local.Addr) == 0 && len(conf.Server.Remote.Addr) == 0 {
		return nil, errors.New("missing args: both local server and remote server are empty")
	}

	if len(conf.Server.Local.Addr) != 0 {
		client, err := NewUpstream(&conf.Server.Local.BasicServerConfig, conf.Dispatcher.MaxConcurrentQueries, rootCAs)
		if err != nil {
			return nil, fmt.Errorf("init local server: %w", err)
		}
		d.local.client = client
		d.local.denyUnusualTypes = conf.Server.Local.DenyUnusualTypes
		d.local.denyResultWithoutIP = conf.Server.Local.DenyResultsWithoutIP
		d.local.checkCNAME = conf.Server.Local.CheckCNAME
	}

	if len(conf.Server.Remote.Addr) != 0 {
		client, err := NewUpstream(&conf.Server.Remote.BasicServerConfig, conf.Dispatcher.MaxConcurrentQueries, rootCAs)
		if err != nil {
			return nil, fmt.Errorf("init remote server: %w", err)
		}
		d.remote.client = client
		d.remote.delayStart = time.Millisecond * time.Duration(conf.Server.Remote.DelayStart)
		if d.remote.delayStart >= queryTimeout {
			return nil, fmt.Errorf("init remote server: remoteServerDelayStart is longer than globle query timeout %s", queryTimeout)
		}
	}

	if len(conf.Server.Local.IPPolicies) != 0 {
		p, err := newIPPolicies(conf.Server.Local.IPPolicies, d.entry)
		if err != nil {
			return nil, fmt.Errorf("loading ip policies, %w", err)
		}
		d.local.ipPolicies = p
	}

	if len(conf.Server.Local.DomainPolicies) != 0 {
		p, err := newDomainPolicies(conf.Server.Local.DomainPolicies, d.entry)
		if err != nil {
			return nil, fmt.Errorf("loading domain policies, %w", err)
		}
		d.local.domainPolicies = p
	}

	if len(conf.ECS.Local) != 0 {
		subnet, err := newEDNSSubnet(conf.ECS.Local)
		if err != nil {
			return nil, fmt.Errorf("parsing local ECS subnet, %w", err)
		}
		d.ecs.local = newEDNS0subnet(subnet)
		d.entry.Info("initDispatcher: local server ECS enabled")
	}

	if len(conf.ECS.Remote) != 0 {
		subnet, err := newEDNSSubnet(conf.ECS.Remote)
		if err != nil {
			return nil, fmt.Errorf("parsing remote ECS subnet, %w", err)
		}
		d.ecs.remote = newEDNS0subnet(subnet)
		d.entry.Info("initDispatcher: remote server ECS enabled")
	}

	return d, nil
}

func newEDNSSubnet(strECSSubnet string) (*dns.EDNS0_SUBNET, error) {
	strs := strings.SplitN(strECSSubnet, "/", 2)
	if len(strs) != 2 {
		return nil, fmt.Errorf("invalid ECS address [%s], not a CIDR notation", strECSSubnet)
	}

	ip := net.ParseIP(strs[0])
	if ip == nil {
		return nil, fmt.Errorf("invalid ECS address [%s], invalid ip", strECSSubnet)
	}
	sourceNetmask, err := strconv.Atoi(strs[1])
	if err != nil || sourceNetmask > 128 || sourceNetmask < 0 {
		return nil, fmt.Errorf("invalid ECS address [%s], invalid net mask", strECSSubnet)
	}

	ednsSubnet := new(dns.EDNS0_SUBNET)
	// edns family: https://www.iana.org/assignments/address-family-numbers/address-family-numbers.xhtml
	// ipv4 = 1
	// ipv6 = 2
	if ip4 := ip.To4(); ip4 != nil {
		ednsSubnet.Family = 1
		ednsSubnet.SourceNetmask = uint8(sourceNetmask)
		ip = ip4
	} else {
		if ip6 := ip.To16(); ip6 != nil {
			ednsSubnet.Family = 2
			ednsSubnet.SourceNetmask = uint8(sourceNetmask)
			ip = ip6
		} else {
			return nil, fmt.Errorf("invalid ECS address [%s], it's not an ipv4 or ipv6 address", strECSSubnet)
		}
	}

	ednsSubnet.Code = dns.EDNS0SUBNET
	ednsSubnet.Address = ip

	// SCOPE PREFIX-LENGTH, an unsigned octet representing the leftmost
	// number of significant bits of ADDRESS that the response covers.
	// In queries, it MUST be set to 0.
	// https://tools.ietf.org/html/rfc7871
	ednsSubnet.SourceScope = 0
	return ednsSubnet, nil
}

func isUnusualType(q *dns.Msg) bool {
	return q.Opcode != dns.OpcodeQuery || len(q.Question) != 1 || q.Question[0].Qclass != dns.ClassINET || (q.Question[0].Qtype != dns.TypeA && q.Question[0].Qtype != dns.TypeAAAA)
}

// ServeDNS send q to upstreams and return first valid result.
func (d *Dispatcher) ServeDNS(ctx context.Context, q *dns.Msg) (r *dns.Msg, err error) {

	qCopy := getMsg()
	q.CopyTo(qCopy)
	entry := getRequestLogger(d.entry.Logger, nil, qCopy.Id, qCopy.Question, "internel")

	qRaw, err := bufpool.AcquireMsgBufAndPack(q)
	if err != nil {
		return nil, fmt.Errorf("invalid dns msg q: pack err: %v", err)
	}

	rRaw, err := d.serveRawDNS(ctx, q, qRaw, entry, false)
	if err != nil {
		return nil, err
	}

	r = new(dns.Msg)
	err = r.Unpack(rRaw.Bytes())
	bufpool.ReleaseMsgBuf(rRaw)
	if err != nil {
		return nil, fmt.Errorf("invalid reply: unpack err: %v", err)
	}
	return r, nil
}

type notification int

const (
	failed notification = iota
	succeed
)

func noBlockNotify(c chan notification, n notification) {
	select {
	case c <- n:
	default:
		return
	}
}

// serveRawDNS: The error will be ErrServerFailed or ctx err
// Note: serveRawDNS will release q, qRaw, requestLogger.
func (d *Dispatcher) serveRawDNS(ctx context.Context, q *dns.Msg, qRawBuf *bufpool.MsgBuf, requestLogger *logrus.Entry, wantFailureReply bool) (*bufpool.MsgBuf, error) {
	qRaw := qRawBuf.Bytes()
	queryCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	resChan := getResChan()
	upstreamFailedNotificationChan := getNotificationChan()

	serveDNSWG := sync.WaitGroup{}
	serveDNSWG.Add(1)
	defer serveDNSWG.Done()

	go func() {
		var doLocal, doRemote, forceLocal bool
		if d.local.client != nil {
			doLocal = true
			if isUnusualType(q) {
				doLocal = !d.local.denyUnusualTypes
			} else {
				if d.local.domainPolicies != nil {
					p := d.local.domainPolicies.check(q.Question[0].Name)
					switch p {
					case policyActionForce:
						doLocal = true
						forceLocal = true
					case policyActionAccept:
						doLocal = true
					case policyActionDeny:
						doLocal = false
					}
					requestLogger.Debugf("serveDNS: localDomainPolicies: dl: %v, fl: %v", doLocal, forceLocal)
				}
			}
		}

		if d.remote.client != nil {
			doRemote = true
			switch {
			case forceLocal:
				doRemote = false
			}
		}

		upstreamWG := sync.WaitGroup{}
		var localNotificationChan chan notification

		// local
		if doLocal {
			localNotificationChan = getNotificationChan()
			upstreamWG.Add(1)
			go func() {
				defer upstreamWG.Done()

				queryStart := time.Now()
				rRaw, err := d.queryLocal(queryCtx, q, qRaw)
				rtt := time.Since(queryStart).Milliseconds()
				if err != nil {
					if err != context.Canceled && err != context.DeadlineExceeded {
						requestLogger.Warnf("serveDNS: local server failed after %dms: %v, ", rtt, err)
					}
					noBlockNotify(localNotificationChan, failed)
					return
				}

				if !forceLocal && !d.acceptRawLocalRes(rRaw.Bytes(), requestLogger) {
					requestLogger.Debugf("serveDNS: local result denied, rtt: %dms", rtt)
					bufpool.ReleaseMsgBuf(rRaw)
					noBlockNotify(localNotificationChan, failed)
					return
				}

				select {
				case resChan <- rRaw:
					requestLogger.Debugf("serveDNS: local result accepted, rtt: %dms", rtt)
				default:
					bufpool.ReleaseMsgBuf(rRaw)
					requestLogger.Debugf("serveDNS: local result dropped, rtt: %dms", rtt)
				}
				noBlockNotify(localNotificationChan, succeed)
			}()
		}

		// remote
		if doRemote {
			if doLocal && d.remote.delayStart > 0 {
				delayTimer := getTimer(d.remote.delayStart)
				defer releaseTimer(delayTimer)
				select {
				case n := <-localNotificationChan:
					if n == succeed {
						goto skipRemote
					}
				case <-delayTimer.C:
				}
			}

			queryStart := time.Now()
			rRaw, err := d.queryRemote(queryCtx, q, qRaw)
			rtt := time.Since(queryStart).Milliseconds()
			if err != nil {
				if err != context.Canceled && err != context.DeadlineExceeded {
					requestLogger.Warnf("serveDNS: remote server failed after %dms: %v", rtt, err)
				}
				return
			}
			requestLogger.Debugf("serveDNS: get reply from remote, rtt: %dms", rtt)

			select {
			case resChan <- rRaw:
			default:
				bufpool.ReleaseMsgBuf(rRaw)
			}
		}
	skipRemote:

		// local and remote upstreams are returned
		upstreamWG.Wait()
		// avoid below select{} choose upstreamFailedNotificationChan
		// if both resChan and upstreamFailedNotificationChan are selectable
		if len(resChan) == 0 {
			noBlockNotify(upstreamFailedNotificationChan, failed)
		}

		// serveDNS is done
		serveDNSWG.Wait()

		// time to finial cleanup
		releaseMsg(q)
		bufpool.ReleaseMsgBuf(qRawBuf)
		releaseRequestLogger(requestLogger)
		releaseResChan(resChan)
		releaseNotificationChan(upstreamFailedNotificationChan)
		if localNotificationChan != nil {
			releaseNotificationChan(localNotificationChan)
		}
	}()

	var rRaw *bufpool.MsgBuf
	var err error
	select {
	case rRaw = <-resChan:
	case <-upstreamFailedNotificationChan:
		err = ErrServerFailed
	case <-ctx.Done():
		err = ctx.Err()
	}

	if err != nil {
		if wantFailureReply {
			requestLogger.Warnf("serveRawDNS: %v", err)
			return genFailureReply(q), nil
		}
		return nil, err
	}
	return rRaw, nil
}

func genFailureReply(q *dns.Msg) *bufpool.MsgBuf {
	r := getMsg()
	defer releaseMsg(r)
	r.SetReply(q)
	r.Rcode = dns.RcodeServerFailure

	rRaw, err := bufpool.AcquireMsgBufAndPack(r)
	if err != nil {
		return nil // just ignore the err, it won't happen.
	}
	return rRaw
}

func (d *Dispatcher) queryUpstream(ctx context.Context, q *dns.Msg, qRaw []byte, u Upstream, ecs *edns0subnet) (rRaw *bufpool.MsgBuf, err error) {
	if ecs != nil {
		qWithECS, appended := appendECSIfNotExist(q, ecs)
		if appended {
			qRawWithECS, err := bufpool.AcquirePackBufAndPack(qWithECS)
			if err != nil {
				return nil, fmt.Errorf("pack ecs appended msg err: %v", err)
			}
			defer bufpool.ReleasePackBuf(qRawWithECS)
			defer releaseMsg(qWithECS)
			return u.Exchange(ctx, qRawWithECS)
		}
	}
	return u.Exchange(ctx, qRaw)
}

func (d *Dispatcher) queryLocal(ctx context.Context, q *dns.Msg, qRaw []byte) (rRaw *bufpool.MsgBuf, err error) {
	return d.queryUpstream(ctx, q, qRaw, d.local.client, d.ecs.local)
}

func (d *Dispatcher) queryRemote(ctx context.Context, q *dns.Msg, qRaw []byte) (rRaw *bufpool.MsgBuf, err error) {
	return d.queryUpstream(ctx, q, qRaw, d.remote.client, d.ecs.remote)
}

// both q and ecs shouldn't be nil, the returned m is a shadow copy of q if ecs is appended.
func appendECSIfNotExist(q *dns.Msg, ecs *edns0subnet) (m *dns.Msg, appended bool) {
	opt := q.IsEdns0()
	if opt == nil { // we need a new opt
		qWithECS := getMsg()
		//shadow copy
		*qWithECS = *q
		qWithECS.Extra = append(q.Extra, ecs.opt)
		return qWithECS, true
	}

	hasECS := false // check if msg q already has a ECS section
	for o := range opt.Option {
		if opt.Option[o].Option() == dns.EDNS0SUBNET {
			hasECS = true
			break
		}
	}

	if !hasECS {
		qCopy := getMsg()
		//shadow copy
		*qCopy = *q

		// deep copy Extra
		qCopy.Extra = append(q.Extra[:0:0], q.Extra...)
		opt := qCopy.IsEdns0()
		if opt == nil {
			panic("broken copy or corrupted data")
		}
		opt.Option = append(opt.Option, ecs.subnet)
		return qCopy, true
	}

	return q, false
}
func (d *Dispatcher) acceptLocalRes(res *dns.Msg, requestLogger *logrus.Entry) (ok bool) {
	if res == nil {
		requestLogger.Debug("acceptLocalRes: false: result is nil")
		return false
	}

	if res.Rcode != dns.RcodeSuccess {
		requestLogger.Debugf("acceptLocalRes: false: Rcode=%s", dns.RcodeToString[res.Rcode])
		return false
	}

	if isUnusualType(res) {
		if d.local.denyUnusualTypes {
			requestLogger.Debug("acceptLocalRes: false: unusual type")
			return false
		}

		requestLogger.Debug("acceptLocalRes: true: unusual type")
		return true
	}

	// check CNAME
	if d.local.domainPolicies != nil && d.local.checkCNAME == true {
		for i := range res.Answer {
			if cname, ok := res.Answer[i].(*dns.CNAME); ok {
				p := d.local.domainPolicies.check(cname.Target)
				switch p {
				case policyActionAccept, policyActionForce:
					requestLogger.Debug("acceptLocalRes: true: matched by CNAME")
					return true
				case policyActionDeny:
					requestLogger.Debug("acceptLocalRes: false: matched by CNAME")
					return false
				default: // policyMissing
					continue
				}
			}
		}
	}

	// check ip
	var hasIP bool
	if d.local.ipPolicies != nil {
		for i := range res.Answer {
			var ip netlist.IPv6
			var err error
			switch tmp := res.Answer[i].(type) {
			case *dns.A:
				ip, err = netlist.Conv(tmp.A)
			case *dns.AAAA:
				ip, err = netlist.Conv(tmp.AAAA)
			default:
				continue
			}

			hasIP = true

			if err != nil {
				requestLogger.Warnf("acceptLocalRes: internal err: netlist.Conv %v", err)
				continue
			}

			p := d.local.ipPolicies.check(ip)
			switch p {
			case policyActionAccept:
				requestLogger.Debug("acceptLocalRes: true: matched by ip")
				return true
			case policyActionDeny:
				requestLogger.Debug("acceptLocalRes: false: matched by ip")
				return false
			default: // policyMissing
				continue
			}
		}
	}

	if d.local.denyResultWithoutIP && !hasIP {
		requestLogger.Debug("acceptLocalRes: false: no ip RR")
		return false
	}

	requestLogger.Debug("acceptLocalRes: true: default accpet")
	return true
}

// check if local result is ok to accept, res can be nil.
func (d *Dispatcher) acceptRawLocalRes(rRaw []byte, requestLogger *logrus.Entry) (ok bool) {
	res := getMsg()
	defer releaseMsg(res)
	err := res.Unpack(rRaw)
	if err != nil {
		requestLogger.Debugf("acceptRawLocalRes: false, Unpack: %v", err)
		return false
	}

	return d.acceptLocalRes(res, requestLogger)
}

func caPath2Pool(ca string) (*x509.CertPool, error) {
	pem, err := ioutil.ReadFile(ca)
	if err != nil {
		return nil, fmt.Errorf("ReadFile: %w", err)
	}

	rootCAs := x509.NewCertPool()
	if ok := rootCAs.AppendCertsFromPEM(pem); !ok {
		return nil, fmt.Errorf("AppendCertsFromPEM: no certificate was successfully parsed in %s", ca)
	}
	return rootCAs, nil
}

type policyAction uint8

const (
	policyActionForceStr   string = "force"
	policyActionAcceptStr  string = "accept"
	policyActionDenyStr    string = "deny"
	policyActionDenyAllStr string = "deny_all"

	policyActionForce policyAction = iota
	policyActionAccept
	policyActionDeny
	policyActionDenyAll
	policyActionMissing
)

var convIPPolicyActionStr = map[string]policyAction{
	policyActionAcceptStr:  policyActionAccept,
	policyActionDenyStr:    policyActionDeny,
	policyActionDenyAllStr: policyActionDenyAll,
}

var convDomainPolicyActionStr = map[string]policyAction{
	policyActionForceStr:   policyActionForce,
	policyActionAcceptStr:  policyActionAccept,
	policyActionDenyStr:    policyActionDeny,
	policyActionDenyAllStr: policyActionDenyAll,
}

type rawPolicy struct {
	action policyAction
	args   string
}

type ipPolicies struct {
	policies []ipPolicy
}

type ipPolicy struct {
	action policyAction
	list   *netlist.List
}

type domainPolicies struct {
	policies []domainPolicy
}

type domainPolicy struct {
	action policyAction
	list   *domainlist.List
}

func convPoliciesStr(s string, f map[string]policyAction) ([]rawPolicy, error) {
	ps := make([]rawPolicy, 0)

	policiesStr := strings.Split(s, "|")
	for i := range policiesStr {
		pStr := strings.SplitN(policiesStr[i], ":", 2)

		p := rawPolicy{}
		action, ok := f[pStr[0]]
		if !ok {
			return nil, fmt.Errorf("unknown action [%s]", pStr[0])
		}
		p.action = action

		if len(pStr) == 2 {
			p.args = pStr[1]
		}

		ps = append(ps, p)
	}

	return ps, nil
}

func newIPPolicies(psString string, entry *logrus.Entry) (*ipPolicies, error) {
	psArgs, err := convPoliciesStr(psString, convIPPolicyActionStr)
	if err != nil {
		return nil, fmt.Errorf("invalid ip policies string, %w", err)
	}
	ps := &ipPolicies{
		policies: make([]ipPolicy, 0),
	}

	for i := range psArgs {
		p := ipPolicy{}
		p.action = psArgs[i].action

		file := psArgs[i].args
		if len(file) != 0 {
			list, err := netlist.NewListFromFile(file)
			if err != nil {
				return nil, fmt.Errorf("failed to load ip file from %s, %w", file, err)
			}
			p.list = list
			entry.Infof("newIPPolicies: ip list %s loaded, length %d", file, list.Len())
		}

		ps.policies = append(ps.policies, p)
	}

	return ps, nil
}

// ps can not be nil
func (ps *ipPolicies) check(ip netlist.IPv6) policyAction {
	for p := range ps.policies {
		if ps.policies[p].action == policyActionDenyAll {
			return policyActionDeny
		}

		if ps.policies[p].list != nil && ps.policies[p].list.Contains(ip) {
			return ps.policies[p].action
		}
	}

	return policyActionMissing
}

func newDomainPolicies(psString string, entry *logrus.Entry) (*domainPolicies, error) {
	psArgs, err := convPoliciesStr(psString, convDomainPolicyActionStr)
	if err != nil {
		return nil, fmt.Errorf("invalid domain policies string, %w", err)
	}
	ps := &domainPolicies{
		policies: make([]domainPolicy, 0),
	}

	for i := range psArgs {
		p := domainPolicy{}
		p.action = psArgs[i].action

		file := psArgs[i].args
		if len(file) != 0 {
			list, err := domainlist.LoadFormFile(file)
			if err != nil {
				return nil, fmt.Errorf("failed to load domain file from %s, %w", file, err)
			}
			p.list = list
			entry.Infof("newDomainPolicies: domain list %s loaded, length %d", file, list.Len())
		}

		ps.policies = append(ps.policies, p)
	}

	return ps, nil
}

// check: ps can not be nil
func (ps *domainPolicies) check(fqdn string) policyAction {
	for p := range ps.policies {
		if ps.policies[p].action == policyActionDenyAll {
			return policyActionDeny
		}

		if ps.policies[p].list != nil && ps.policies[p].list.Has(fqdn) {
			return ps.policies[p].action
		}
	}

	return policyActionMissing
}
