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
	"container/list"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/IrineSistiana/mos-chinadns/dispatcher/netlist"
	"golang.org/x/sync/singleflight"

	"golang.org/x/net/http2"

	"github.com/IrineSistiana/mos-chinadns/dispatcher/pool"
	"github.com/miekg/dns"
	"golang.org/x/net/proxy"
)

const (
	tlsHandshakeTimeout = time.Second * 5
	dialTCPTimeout      = time.Second * 5
	dialUDPTimeout      = time.Second * 5
	generalWriteTimeout = time.Second * 1
	generalReadTimeout  = time.Second * 5
	dohIOTimeout        = time.Second * 10

	connPoolCleanerInterval = time.Second * 2
)

// Upstream represents a dns upstream
type Upstream interface {
	Exchange(ctx context.Context, q *dns.Msg) (r *dns.Msg, err error)
}

// upstream represents mos-chinadns upstream.
type upstream struct {
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

	bk                *bucket
	singleFlightGroup singleflight.Group
	basicUpstream     Upstream
}

func isUnhandlableType(q *dns.Msg) bool {
	return q.Opcode != dns.OpcodeQuery || len(q.Question) != 1 || q.Question[0].Qclass != dns.ClassINET || (q.Question[0].Qtype != dns.TypeA && q.Question[0].Qtype != dns.TypeAAAA)
}

var (
	errTooManyConcurrentQueries = errors.New("too many concurrent queries")
)

func (u *upstream) Exchange(ctx context.Context, q *dns.Msg) (r *dns.Msg, err error) {
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
			r = rUnsafe.Copy()
			r.Id = q.Id
			return r, nil
		}

		return rUnsafe, nil
	}

	return u.exchange(ctx, q)
}

func (u *upstream) exchange(ctx context.Context, q *dns.Msg) (r *dns.Msg, err error) {
	// get token
	if u.bk != nil {
		if u.bk.acquire() == false {
			return nil, errTooManyConcurrentQueries
		}
		defer u.bk.release()
	}

	// check msg type
	var msgIsUnhandlableType bool
	if msgIsUnhandlableType = isUnhandlableType(q); msgIsUnhandlableType {
		if u.policies.denyUnhandlableTypes {
			return nil, nil
		} else {
			return u.basicUpstream.Exchange(ctx, q)
		}
	}

	// check domain
	var domainPolicyAction = policyFinalActionOnHold
	if u.policies.domain != nil {
		domainPolicyAction = u.policies.domain.check(q.Question[0].Name)
		if domainPolicyAction == policyFinalActionDeny {
			return nil, nil
		}
	}

	// append edns0 client subnet
	if u.edns0.clientSubnet != nil {
		if checkMsgHasECS(q) == false || (checkMsgHasECS(q) == true && u.edns0.overwriteECS) {
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
	if domainPolicyAction == policyFinalActionAccept || msgIsUnhandlableType {
		return r, nil
	}

	// check Rcode
	if u.policies.denyErrorRcode && r.Rcode != dns.RcodeSuccess {
		return nil, nil
	}

	// check CNAME
	if u.policies.domain != nil && u.policies.checkCNAME == true {
		switch checkMsgCNAME(u.policies.domain, r) {
		case policyFinalActionDeny:
			return nil, nil
		case policyFinalActionAccept:
			return r, nil
		}
	}

	// check ip
	if u.policies.denyEmptyIPReply && checkMsgHasValidIP(r) == false {
		return nil, nil
	}
	if u.policies.ip != nil && checkMsgIP(u.policies.ip, r) == policyFinalActionDeny {
		return nil, nil
	}

	return r, err
}

func getMsgKey(m *dns.Msg) (string, error) {
	buf := pool.AcquirePackBuf()
	defer pool.ReleasePackBuf(buf)

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
func NewUpstream(sc *BasicServerConfig, rootCAs *x509.CertPool) (Upstream, error) {
	if sc == nil {
		return nil, errors.New("no server config")
	}

	u := new(upstream)

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
		dialUDP := func() (net.Conn, error) {
			return net.DialTimeout("udp", sc.Addr, dialUDPTimeout)
		}
		u.basicUpstream = &upstreamCommon{
			dialNewConn: dialUDP,
			readMsg:     readMsgFromUDP,
			writeMsg:    writeMsgToUDP,
			cp:          newConnPool(0xffff, time.Second*10, connPoolCleanerInterval),
		}
	case "tcp":
		dialTCP, err := getUpstreamDialTCPFunc("tcp", sc.Addr, sc.Socks5, dialTCPTimeout)
		if err != nil {
			return nil, fmt.Errorf("failed to init dialer: %v", err)
		}

		uc := &upstreamCommon{
			dialNewConn: dialTCP,
			readMsg:     readMsgFromTCP,
			writeMsg:    writeMsgToTCP,
		}

		if sc.TCP.IdleTimeout > 0 {
			idleTimeout := time.Duration(sc.TCP.IdleTimeout) * time.Second
			uc.cp = newConnPool(0xffff, idleTimeout, connPoolCleanerInterval)
		}

		u.basicUpstream = uc
	case "dot":
		if len(sc.DoT.ServerName) == 0 {
			return nil, fmt.Errorf("protocol [%s] needs additional argument: server_name", sc.Protocol)
		}

		dialTCP, err := getUpstreamDialTCPFunc("tcp", sc.Addr, sc.Socks5, dialTCPTimeout)
		if err != nil {
			return nil, fmt.Errorf("failed to init dialer: %v", err)
		}

		tlsConf := &tls.Config{
			ServerName:         sc.DoT.ServerName,
			RootCAs:            rootCAs,
			ClientSessionCache: tls.NewLRUClientSessionCache(64),

			// for test only
			InsecureSkipVerify: sc.InsecureSkipVerify,
		}
		dialTLS := func() (net.Conn, error) {
			c, err := dialTCP()
			if err != nil {
				return nil, fmt.Errorf("failed to dial tcp connection: %v", err)
			}
			tlsConn := tls.Client(c, tlsConf)
			tlsConn.SetDeadline(time.Now().Add(tlsHandshakeTimeout))
			// try handshake first
			if err := tlsConn.Handshake(); err != nil {
				c.Close()
				return nil, fmt.Errorf("failed to tls handshake: %v", err)
			}
			return tlsConn, nil
		}
		uc := &upstreamCommon{
			dialNewConn: dialTLS,
			readMsg:     readMsgFromTCP,
			writeMsg:    writeMsgToTCP,
		}

		if sc.DoT.IdleTimeout > 0 {
			idleTimeout := time.Duration(sc.DoT.IdleTimeout) * time.Second
			uc.cp = newConnPool(0xffff, idleTimeout, connPoolCleanerInterval)
		}

		u.basicUpstream = uc
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

		u.basicUpstream, err = newDoHUpstream(sc.DoH.URL, dialContext, tlsConf)
		if err != nil {
			return nil, fmt.Errorf("failed to init DoH: %v", err)
		}
	default:
		return nil, fmt.Errorf("unsupport protocol: %s", sc.Protocol)
	}

	return u, nil
}

// upstreamCommon represents a udp/tcp/tls upstream
type upstreamCommon struct {
	dialNewConn func() (net.Conn, error)
	writeMsg    func(c io.Writer, m *dns.Msg) (int, error)
	readMsg     func(c io.Reader) (m *dns.Msg, n int, err error)

	cp *connPool
}

func (u *upstreamCommon) Exchange(ctx context.Context, q *dns.Msg) (r *dns.Msg, err error) {
	return u.exchange(ctx, q)
}

func (u *upstreamCommon) exchange(ctx context.Context, q *dns.Msg) (r *dns.Msg, err error) {
	if contextIsDone(ctx) == true {
		return nil, ctx.Err()
	}

	if c := u.getConnFromPool(); c != nil {
		r, err := u.exchangeViaConn(q, c)
		if err != nil {
			c.Close()
			if contextIsDone(ctx) == true {
				return nil, fmt.Errorf("reused connection err: %v, can't retry: %v", err, ctx.Err())
			} else {
				goto exchangeViaNewConn // we might have time to retry this query on a new connection
			}
		}
		u.putConnToPool(c)
		return r, nil
	}

exchangeViaNewConn:
	c, err := u.dialNewConn()
	if err != nil {
		return nil, fmt.Errorf("failed to dial new conntion: %v", err)
	}

	// dialNewConn might take some time, check if ctx is done
	if contextIsDone(ctx) == true {
		u.putConnToPool(c)
		return nil, ctx.Err()
	}

	r, err = u.exchangeViaConn(q, c)
	if err != nil {
		c.Close()
		return nil, err
	}

	u.putConnToPool(c)
	return r, nil
}

func (u *upstreamCommon) exchangeViaConn(q *dns.Msg, c net.Conn) (r *dns.Msg, err error) {
	// write first
	c.SetWriteDeadline(time.Now().Add(generalWriteTimeout)) // give write enough time to complete, avoid broken write.
	_, err = u.writeMsg(c, q)
	if err != nil { // write err typically is a fatal err
		c.Close()
		return nil, fmt.Errorf("failed to write msg: %v", err)
	}

	c.SetReadDeadline(time.Now().Add(generalReadTimeout))
	r, _, err = u.readMsg(c)
	if err != nil {
		return nil, fmt.Errorf("failed to read msg: %v", err)
	}
	return r, nil
}

func (u *upstreamCommon) getConnFromPool() net.Conn {
	if u.cp != nil {
		return u.cp.get()
	}
	return nil
}

func (u *upstreamCommon) putConnToPool(c net.Conn) {
	if u.cp != nil {
		u.cp.put(c)
	}
}

type connPool struct {
	maxSize         int
	ttl             time.Duration
	cleanerInterval time.Duration

	cleanerStatus int32
	sync.Mutex
	pool *list.List
}

type poolElem struct {
	c           net.Conn
	expiredTime time.Time
}

const (
	cleanerOffline int32 = iota
	cleanerOnline
)

func newConnPool(size int, ttl, cleanerInterval time.Duration) *connPool {
	if size <= 0 || ttl <= 0 || cleanerInterval <= 0 {
		panic("invalid arguments in newConnPool")
	}

	return &connPool{
		maxSize:         size,
		ttl:             ttl,
		cleanerInterval: cleanerInterval,
		pool:            list.New(),
		cleanerStatus:   cleanerOffline,
	}
}

func (p *connPool) tryStartCleanerGoroutine() {
	if atomic.CompareAndSwapInt32(&p.cleanerStatus, cleanerOffline, cleanerOnline) {
		go func() {
			p.startCleaner()
			atomic.StoreInt32(&p.cleanerStatus, cleanerOffline)
		}()
	}
}

func (p *connPool) startCleaner() {
	ticker := time.NewTicker(p.cleanerInterval)
	defer ticker.Stop()
	for {
		<-ticker.C
		p.Lock()
		_, connRemain := p.clean()
		if connRemain == 0 { // no connection in pool, stop the cleaner
			p.Unlock()
			return
		}
		p.Unlock()
	}
}

// clean cleans old connections. Must be called after connPool is locked.
func (p *connPool) clean() (connRemoved, connRemain int) {
	// remove expired connections
	var next *list.Element // temporarily store e.Next(), which will not available after list.Remove().
	for e := p.pool.Front(); e != nil; e = next {
		next = e.Next()
		pe := e.Value.(*poolElem)
		if time.Now().After(pe.expiredTime) { // expired, release the resources
			connRemoved++
			pe.c.Close()
			p.pool.Remove(e)
		}
	}

	return connRemoved, p.pool.Len()
}

func (p *connPool) put(c net.Conn) {
	var poppedPoolElem *poolElem
	p.Lock()
	if p.pool.Len() >= p.maxSize { // if pool is full, pop it's first(oldest) element.
		e := p.pool.Front()
		poppedPoolElem = e.Value.(*poolElem)
		p.pool.Remove(e)
	}
	pe := &poolElem{c: c, expiredTime: time.Now().Add(p.ttl)}
	p.pool.PushBack(pe)
	p.Unlock()

	if poppedPoolElem != nil {
		poppedPoolElem.c.Close() // release the old connection
	}

	p.tryStartCleanerGoroutine()
}

func (p *connPool) get() (c net.Conn) {
	var pe *poolElem
	p.Lock()
	e := p.pool.Back()
	if e != nil {
		pe = e.Value.(*poolElem)
		p.pool.Remove(e)
	}
	p.Unlock()

	if pe != nil {
		if time.Now().After(pe.expiredTime) {
			pe.c.Close() // expired
			return nil
		}
		return pe.c
	}

	return nil // no available connection in pool
}

func (p *connPool) connRemain() int {
	p.Lock()
	defer p.Unlock()

	return p.pool.Len()
}

type upstreamDoH struct {
	urlPrefix string
	client    *http.Client
}

func newDoHUpstream(urlPrefix string, dialContext func(ctx context.Context, network, address string) (net.Conn, error), tlsConfig *tls.Config) (*upstreamDoH, error) {
	// check urlPrefix
	u, err := url.ParseRequestURI(urlPrefix)
	if err != nil {
		return nil, fmt.Errorf("invalid url: %w", err)
	}

	if u.Scheme != "https" {
		return nil, fmt.Errorf("invalid url scheme [%s]", u.Scheme)
	}

	u.ForceQuery = true // make sure we have a '?' at somewhere
	urlPrefix = u.String()
	if strings.HasSuffix(urlPrefix, "?") {
		urlPrefix = urlPrefix + "dns=" // the only one and the first arg
	} else {
		urlPrefix = urlPrefix + "&dns=" // the last arg
	}

	transport := &http.Transport{
		DialContext:           dialContext,
		TLSClientConfig:       tlsConfig,
		TLSHandshakeTimeout:   tlsHandshakeTimeout,
		IdleConnTimeout:       90 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     true,
	}

	http2.ConfigureTransport(transport) // enable http2

	c := new(upstreamDoH)
	c.urlPrefix = urlPrefix
	c.client = &http.Client{
		Transport: transport,
	}

	return c, nil
}

//Exchange: dot upstream has its own context to control timeout, it will not follow the ctx.
func (u *upstreamDoH) Exchange(_ context.Context, q *dns.Msg) (r *dns.Msg, err error) {

	ctx, cancel := context.WithTimeout(context.Background(), dohIOTimeout)
	defer cancel()

	// In order to maximize HTTP cache friendliness, DoH clients using media
	// formats that include the ID field from the DNS message header, such
	// as "application/dns-message", SHOULD use a DNS ID of 0 in every DNS
	// request.
	// https://tools.ietf.org/html/rfc8484 4.1
	qWithNewID := pool.GetMsg()
	defer pool.ReleaseMsg(qWithNewID)
	*qWithNewID = *q // shadow copy, we just want to change its ID
	qWithNewID.Id = 0

	buf := pool.AcquirePackBuf()
	defer pool.ReleasePackBuf(buf)

	rRaw, err := qWithNewID.PackBuffer(buf)
	if err != nil {
		return nil, fmt.Errorf("invalid msg q: %v", err)
	}

	// Padding characters for base64url MUST NOT be included.
	// See: https://tools.ietf.org/html/rfc8484 6
	// That's why we use base64.RawURLEncoding
	urlBuilder := acquireDoHURLBuilder()
	defer releaseDoHURLBuilder(urlBuilder)
	urlBuilder.WriteString(u.urlPrefix)
	encoder := base64.NewEncoder(base64.RawURLEncoding, urlBuilder)
	encoder.Write(rRaw)
	encoder.Close()

	r, err = u.doHTTP(ctx, urlBuilder.String())
	if err != nil {
		return nil, fmt.Errorf("doHTTP: %w", err)
	}

	if r.Id != 0 { // check msg id
		return nil, dns.ErrId
	}
	// change the id back
	r.Id = q.Id
	return r, nil
}

func (u *upstreamDoH) doHTTP(ctx context.Context, url string) (*dns.Msg, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("interal err: NewRequestWithContext: %w", err)
	}

	req.Header["Accept"] = []string{"application/dns-message"}

	resp, err := u.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http request failed: %w", err)
	}
	defer resp.Body.Close()

	// check status code
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad http status codes %d", resp.StatusCode)
	}

	var buf []byte
	// read body
	switch {
	case resp.ContentLength > dns.MaxMsgSize:
		return nil, fmt.Errorf("content-length %d is bigger than dns.MaxMsgSize %d", resp.ContentLength, dns.MaxMsgSize)
	case resp.ContentLength > 12:
		buf = pool.GetMsgBuf(int(resp.ContentLength))
		defer pool.ReleaseMsgBuf(buf)
		_, err = io.ReadFull(resp.Body, buf)
		if err != nil {
			return nil, fmt.Errorf("unexpected err when read http resp body: %v", err)
		}
	case resp.ContentLength >= 0:
		return nil, fmt.Errorf("content-length %d is smaller than dns header size 12", resp.ContentLength)
	case resp.ContentLength == -1: // unknown length
		bb := acquireDoHReadBuf()
		defer releaseDoHReadBuf(bb)
		n, err := bb.ReadFrom(io.LimitReader(resp.Body, dns.MaxMsgSize+1))
		if err != nil {
			return nil, fmt.Errorf("unexpected err when read http resp body: %v", err)
		}

		if n > dns.MaxMsgSize || n < 12 {
			return nil, fmt.Errorf("invalid body length: %d", n)
		}

		buf = bb.Bytes()
	default:
		return nil, fmt.Errorf("invalid body length: %d", resp.ContentLength)
	}

	r := new(dns.Msg)
	if err := r.Unpack(buf); err != nil {
		return nil, fmt.Errorf("invalid reply: %v", err)
	}
	return r, nil
}

var (
	dohReadBytesBufPool = sync.Pool{
		New: func() interface{} {
			return new(bytes.Buffer)
		},
	}
)

func acquireDoHReadBuf() *bytes.Buffer {
	return dohReadBytesBufPool.Get().(*bytes.Buffer)
}

func releaseDoHReadBuf(buf *bytes.Buffer) {
	buf.Reset()
	dohReadBytesBufPool.Put(buf)
}

var (
	dohURLStringBuilderPool = sync.Pool{
		New: func() interface{} {
			return new(strings.Builder)
		},
	}
)

func acquireDoHURLBuilder() *strings.Builder {
	return dohURLStringBuilderPool.Get().(*strings.Builder)
}

func releaseDoHURLBuilder(builder *strings.Builder) {
	builder.Reset()
	dohURLStringBuilderPool.Put(builder)
}

func getUpstreamDialContextFunc(network, dstAddress, sock5Address string) (func(ctx context.Context, _, _ string) (net.Conn, error), error) {
	if len(sock5Address) != 0 { // proxy through sock5
		d, err := proxy.SOCKS5(network, sock5Address, nil, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to init socks5 dialer: %v", err)
		}
		contextDialer, ok := d.(proxy.ContextDialer)
		if !ok {
			return nil, errors.New("internel err: socks5 dialer is not a proxy.ContextDialer")
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

func getUpstreamDialTCPFunc(network, dstAddress, sock5Address string, timeout time.Duration) (func() (net.Conn, error), error) {
	d, err := getUpstreamDialContextFunc(network, dstAddress, sock5Address)
	if err != nil {
		return nil, fmt.Errorf("failed to get upstream dialTCP func: %v", err)
	}
	return func() (net.Conn, error) {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		return d(ctx, "", "")
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

func contextIsDone(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}
