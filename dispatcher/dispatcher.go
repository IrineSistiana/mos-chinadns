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
	"sync"
	"time"

	"github.com/IrineSistiana/mos-chinadns/dispatcher/cache"
	"github.com/IrineSistiana/mos-chinadns/dispatcher/notification"
	"github.com/IrineSistiana/mos-chinadns/dispatcher/utils"

	"github.com/IrineSistiana/mos-chinadns/dispatcher/pool"

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

	cache struct {
		*cache.Cache
		minTTL uint32
	}

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
		local          *dns.EDNS0_SUBNET
		remote         *dns.EDNS0_SUBNET
		forceOverwrite bool
	}
}

// InitDispatcher inits a dispatcher from configuration
func InitDispatcher(conf *Config, entry *logrus.Entry) (*Dispatcher, error) {
	d := new(Dispatcher)
	d.entry = entry
	if conf.Dispatcher.MaxConcurrentQueries <= 0 {
		d.maxConcurrentQueries = 150
	} else {
		d.maxConcurrentQueries = conf.Dispatcher.MaxConcurrentQueries
	}

	if conf.Dispatcher.Cache.Size > 0 {
		d.cache.Cache = cache.New(conf.Dispatcher.Cache.Size)
		d.cache.minTTL = conf.Dispatcher.Cache.MinTTL
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
		subnet, err := newEDNS0SubnetFromStr(conf.ECS.Local)
		if err != nil {
			return nil, fmt.Errorf("parsing local ECS subnet, %w", err)
		}
		d.ecs.local = subnet
		d.entry.Info("initDispatcher: local server ECS enabled")
	}

	if len(conf.ECS.Remote) != 0 {
		subnet, err := newEDNS0SubnetFromStr(conf.ECS.Remote)
		if err != nil {
			return nil, fmt.Errorf("parsing remote ECS subnet, %w", err)
		}
		d.ecs.remote = subnet
		d.entry.Info("initDispatcher: remote server ECS enabled")
	}

	d.ecs.forceOverwrite = conf.ECS.ForceOverwrite

	return d, nil
}

func isUnusualType(q *dns.Msg) bool {
	return q.Opcode != dns.OpcodeQuery || len(q.Question) != 1 || q.Question[0].Qclass != dns.ClassINET || (q.Question[0].Qtype != dns.TypeA && q.Question[0].Qtype != dns.TypeAAAA)
}

// ServeDNS sends q to upstreams and return first valid result.
// Note: q will be unsafe to modify even after ServeDNS is returned.
// (Some goroutine may still be running even after ServeDNS is returned)
func (d *Dispatcher) ServeDNS(ctx context.Context, q *dns.Msg) (r *dns.Msg, err error) {
	requestLogger := pool.GetRequestLogger(d.entry.Logger, q)
	defer pool.ReleaseRequestLogger(requestLogger)

	hasECS := isMsgHasECS(q) // don't use cache for msg with ECS

	if !hasECS {
		if r = d.tryGetFromCache(q); r != nil {
			requestLogger.Debug("cache hit")
			return r, nil
		}
	}

	r, err = d.exchangeDNS(ctx, q)
	if err != nil {
		return nil, err
	}

	if !hasECS {
		d.tryAddToCache(r)
	}
	return r, nil
}

func (d *Dispatcher) tryGetFromCache(q *dns.Msg) (r *dns.Msg) {
	if d.cache.Cache != nil && len(q.Question) == 1 { // must have only one question
		r := d.cache.Get(q.Question[0])
		if r != nil {
			r.Id = q.Id
			return r
		}
		return nil
	}
	return nil
}

// tryAddToCache adds r to cache and modifies its ttl
func (d *Dispatcher) tryAddToCache(r *dns.Msg) {
	// must only have one question and Rcode must be success
	if d.cache.Cache != nil && len(r.Question) == 1 && r.Rcode == dns.RcodeSuccess {
		ttl := utils.GetAnswerMinTTL(r)
		if ttl < d.cache.minTTL {
			ttl = d.cache.minTTL
		}
		expireAt := time.Now().Add(time.Duration(ttl) * time.Second)
		d.cache.Add(r.Question[0], r, expireAt)

		utils.SetAnswerTTL(r, ttl) // if r is added to cache, modify its ttl as well.
	}
}

func (d *Dispatcher) exchangeDNS(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	requestLogger := pool.GetRequestLogger(d.entry.Logger, q)
	resChan := pool.GetResChan()
	upstreamFailedNotificationChan := pool.GetNotificationChan()

	serveDNSWG := sync.WaitGroup{}
	serveDNSWG.Add(1)
	defer serveDNSWG.Done()

	doLocal, doRemote := d.selectUpstreams(q)
	requestLogger.Debugf("exchangeDNS: selectUpstreams: local: %v, remote: %v", doLocal, doRemote)

	upstreamWG := sync.WaitGroup{}
	var localNotificationChan chan notification.Signal

	// local
	if doLocal {
		localNotificationChan = pool.GetNotificationChan()
		upstreamWG.Add(1)
		go func() {
			defer upstreamWG.Done()

			var qToLocal *dns.Msg
			qToLocal = q
			if d.ecs.local != nil {
				qWithLocalECS := appendECS(q, d.ecs.local, d.ecs.forceOverwrite, true)
				if qWithLocalECS != nil { // ecs appended
					qToLocal = qWithLocalECS
				}
			}

			queryStart := time.Now()
			r, err := d.local.client.Exchange(ctx, qToLocal)
			rtt := time.Since(queryStart).Milliseconds()
			if err != nil {
				if err != context.Canceled && err != context.DeadlineExceeded {
					requestLogger.Warnf("exchangeDNS: local server failed after %dms: %v", rtt, err)
				}
				notification.NoBlockNotify(localNotificationChan, notification.Failed)
				return
			}

			// Only fliter local result when both local and remote servers are queried.
			if doLocal && doRemote {
				if d.checkLocalRes(r, requestLogger) == false {
					pool.ReleaseMsg(r)
					requestLogger.Debugf("exchangeDNS: local result denied, rtt: %dms", rtt)
					notification.NoBlockNotify(localNotificationChan, notification.Failed)
					return
				}
			}

			requestLogger.Debugf("exchangeDNS: local result accepted, rtt: %dms", rtt)
			select {
			case resChan <- r:
			default:
			}
			notification.NoBlockNotify(localNotificationChan, notification.Succeed)
		}()
	}

	// remote and cleaner
	go func() {
		// remote
		if doRemote {
			if doLocal && d.remote.delayStart > 0 {
				delayTimer := pool.GetTimer(d.remote.delayStart)
				defer pool.ReleaseTimer(delayTimer)
				select {
				case n := <-localNotificationChan:
					if n == notification.Succeed {
						goto skipRemote
					}
				case <-delayTimer.C:
				}
			}

			var qToRemote *dns.Msg
			qToRemote = q
			if d.ecs.remote != nil {
				qWithRemoteECS := appendECS(q, d.ecs.remote, d.ecs.forceOverwrite, true)
				if qWithRemoteECS != nil { // ecs appended
					qToRemote = qWithRemoteECS
				}
			}

			queryStart := time.Now()
			r, err := d.remote.client.Exchange(ctx, qToRemote)
			rtt := time.Since(queryStart).Milliseconds()
			if err != nil {
				if err != context.Canceled && err != context.DeadlineExceeded {
					requestLogger.Warnf("exchangeDNS: remote server failed after %dms: %v", rtt, err)
				}
				goto skipRemote
			}

			requestLogger.Debugf("exchangeDNS: get reply from remote, rtt: %dms", rtt)
			select {
			case resChan <- r:
			default:
			}
		}
	skipRemote:

		// local and remote upstreams are returned
		upstreamWG.Wait()
		// avoid below select{} choose upstreamFailedNotificationChan
		// if both resChan and upstreamFailedNotificationChan are selectable
		if len(resChan) == 0 {
			notification.NoBlockNotify(upstreamFailedNotificationChan, notification.Failed)
		}

		// exchangeDNS is done
		serveDNSWG.Wait()

		// time to finial cleanup
		pool.ReleaseRequestLogger(requestLogger)
		pool.ReleaseResChan(resChan)
		pool.ReleaseNotificationChan(upstreamFailedNotificationChan)
		if localNotificationChan != nil {
			pool.ReleaseNotificationChan(localNotificationChan)
		}
	}()

	select {
	case m := <-resChan:
		return m, nil
	case <-upstreamFailedNotificationChan:
		return nil, ErrServerFailed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (d *Dispatcher) selectUpstreams(q *dns.Msg) (doLocal, doRemote bool) {
	var localOnly bool = false

	if d.local.client != nil {
		switch {
		case isUnusualType(q) && d.local.denyUnusualTypes == true: // drop unusual type
			doLocal = false
		case d.local.domainPolicies != nil: // match domain policies
			p := d.local.domainPolicies.check(q.Question[0].Name)
			switch p {
			case policyActionForce:
				doLocal = true
				localOnly = true
			case policyActionAccept:
				doLocal = true
			case policyActionDeny:
				doLocal = false
			}
		}
	}

	if d.remote.client != nil && !localOnly {
		doRemote = true
	}
	return
}

func (d *Dispatcher) checkLocalRes(res *dns.Msg, requestLogger *logrus.Entry) (ok bool) {
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

	if d.local.denyResultWithoutIP && !answerHasIP(res.Answer) {
		requestLogger.Debug("acceptLocalRes: false: no ip RR")
		return false
	}

	requestLogger.Debug("acceptLocalRes: true: default accept")
	return true
}

func answerHasIP(rr []dns.RR) bool {
	for i := range rr {
		switch rr[i].(type) {
		case *dns.A, *dns.AAAA:
			return true
		default:
			continue
		}
	}
	return false
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
