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
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
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
	generalReadTimeout  = time.Second * 3
	dohIOTimeout        = time.Second * 10
)

// Upstream represents a dns upstream
type Upstream interface {
	Exchange(ctx context.Context, q *dns.Msg) (r *dns.Msg, err error)
}

// upstream represents mos-chinadns upstream.
type upstream struct {
	bk    *bucket
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

	singleFlightGroup singleflight.Group
	u                 Upstream
}

func isUnhandlableType(q *dns.Msg) bool {
	return q.Opcode != dns.OpcodeQuery || len(q.Question) != 1 || q.Question[0].Qclass != dns.ClassINET || (q.Question[0].Qtype != dns.TypeA && q.Question[0].Qtype != dns.TypeAAAA)
}

var (
	errTooManyConcurrentQueries = errors.New("too many concurrent queries")
	errInternalTypeMismatch     = errors.New("internal err: interface type mismatched")
)

func (u *upstream) Exchange(ctx context.Context, q *dns.Msg) (r *dns.Msg, err error) {
	// deduplicate
	if u.deduplicate {
		key, err := getMsgKey(q)
		if err != nil {
			return nil, fmt.Errorf("failed to caculate msg key, %v", err)
		}

		v, err, _ := u.singleFlightGroup.Do(key, func() (interface{}, error) {
			defer u.singleFlightGroup.Forget(key)
			return u.exchange(ctx, q)
		})

		if err != nil {
			return nil, err
		}
		r, ok := v.(*dns.Msg)
		if !ok {
			return nil, errInternalTypeMismatch
		}
		return r, nil
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
			return u.u.Exchange(ctx, q)
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
		qWithECS := appendECS(q, u.edns0.clientSubnet, u.edns0.overwriteECS, true)
		if qWithECS != nil {
			return u.u.Exchange(ctx, qWithECS)
		}
	}

	// send to upstream
	r, err = u.u.Exchange(ctx, q)
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
	if u.policies.ip != nil && checkMsgIP(u.policies.ip, r) == policyFinalActionDeny {
		return nil, nil
	}
	if u.policies.denyEmptyIPReply && checkMsgHasValidIP(r) == false {
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

	var basicUpstream Upstream

	switch sc.Protocol {
	case "udp", "":
		dialUDP := func() (net.Conn, error) {
			return net.DialTimeout("udp", sc.Addr, dialUDPTimeout)
		}
		basicUpstream = &upstreamCommon{
			dialNewConn: dialUDP,
			readMsg:     readMsgFromUDP,
			writeMsg:    writeMsgToUDP,
			cp:          newConnPool(0xffff, time.Second*10, time.Second*5),
		}
	case "tcp":
		dialTCP, err := getUpstreamDialTCPFunc("tcp", sc.Addr, sc.Socks5, dialTCPTimeout)
		if err != nil {
			return nil, fmt.Errorf("failed to init dialer: %v", err)
		}

		idleTimeout := time.Duration(sc.TCP.IdleTimeout) * time.Second
		basicUpstream = &upstreamCommon{
			dialNewConn: dialTCP,
			readMsg:     readMsgFromTCP,
			writeMsg:    writeMsgToTCP,
			cp:          newConnPool(0xffff, idleTimeout, idleTimeout>>1),
		}
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
		idleTimeout := time.Duration(sc.DoT.IdleTimeout) * time.Second
		basicUpstream = &upstreamCommon{
			dialNewConn: dialTLS,
			readMsg:     readMsgFromTCP,
			writeMsg:    writeMsgToTCP,
			cp:          newConnPool(0xffff, idleTimeout, idleTimeout>>1),
		}
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

		basicUpstream, err = newDoHUpstream(sc.DoH.URL, dialContext, tlsConf)
		if err != nil {
			return nil, fmt.Errorf("failed to init DoH: %v", err)
		}
	default:
		return nil, fmt.Errorf("unsupport protocol: %s", sc.Protocol)
	}

	u := &upstream{u: basicUpstream}

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

	return u, nil
}

// upstreamCommon represents a udp/tcp/tls upstream
type upstreamCommon struct {
	dialNewConn func() (net.Conn, error)
	writeMsg    func(c io.Writer, m *dns.Msg) (int, error)
	readMsg     func(c io.Reader) (m *dns.Msg, brokenDataLeft int, n int, err error)

	cp *connPool
}

func (u *upstreamCommon) Exchange(ctx context.Context, q *dns.Msg) (r *dns.Msg, err error) {
	return u.exchange(ctx, q, false)
}

func (u *upstreamCommon) exchange(ctx context.Context, q *dns.Msg, forceNewConn bool) (r *dns.Msg, err error) {
	if err = ctx.Err(); err != nil {
		return nil, err
	}

	var isNewConn bool
	var dc *dnsConn
	if !forceNewConn { // we want a new connection
		dc = u.cp.get()
	}

	// if we need a new conn
	if dc == nil {
		c, err := u.dialNewConn()
		if err != nil {
			return nil, fmt.Errorf("failed to dial new conntion: %v", err)
		}
		dc = newDNSConn(c, time.Now())
		isNewConn = true
		// dialNewConn might take some time, check if ctx is done
		if err = ctx.Err(); err != nil {
			u.cp.put(dc)
			return nil, err
		}
	} else {
		dc.msgIDCounter++
	}

	qWithNewID := pool.GetMsg()
	defer pool.ReleaseMsg(qWithNewID)
	*qWithNewID = *q // shadow copy, we just want to change its ID
	qWithNewID.Id = dc.msgIDCounter

	// write first
	dc.SetWriteDeadline(time.Now().Add(generalWriteTimeout)) // give write enough time to complete, avoid broken write.
	_, err = u.writeMsg(dc.Conn, qWithNewID)
	if err != nil { // write err typically is fatal err
		dc.Close()
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, err
		}
		// ctx is not done yet, open a new conn and try again.
		return u.exchange(ctx, q, true)
	}

	var n int
	dc.SetReadDeadline(time.Now().Add(generalReadTimeout))
	// if we need to empty the conn (some data of previous reply)
	if dc.frameLeft > 0 {
		buf := pool.GetMsgBuf(dc.frameLeft)
		n, err = io.ReadFull(dc, buf)
		pool.ReleaseMsgBuf(buf)
		if n > 0 {
			dc.peerLastActiveTime = time.Now()
			dc.frameLeft = dc.frameLeft - n
		}
		if err != nil {
			goto readErr
		}
	}

read:
	r, dc.frameLeft, n, err = u.readMsg(dc.Conn)
	if n > 0 {
		dc.peerLastActiveTime = time.Now()
	}
	if err != nil {
		goto readErr
	}

	if r.Id != dc.msgIDCounter {
		if !isNewConn {
			// this connection is reused, data might be the reply
			// of a previous qRaw, not this qRaw.
			// try to read again
			goto read
		} else {
			// new connection should not receive a mismatched id, this is an error
			dc.Close()
			err = dns.ErrId
			goto readErr
		}
	}

	u.cp.put(dc)
	r.Id = q.Id // change the ID back
	return r, nil

readErr:
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		if dc.frameLeft == unknownBrokenDataSize {
			dc.Close()
			return nil, fmt.Errorf("conn is broken, %v", err)
		}
		u.cp.put(dc)
		return nil, err
	}

	if isNewConn { // new connection shouldn't have any other type of err
		dc.Close()
		return nil, fmt.Errorf("new conn io err, %v", err)
	}

	// reused connection got an unexpected err
	dc.Close()
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, err
	}
	// ctx is not done yet, open a new conn and try again.
	return u.exchange(ctx, q, true)
}

type connPool struct {
	maxSize         int
	ttl             time.Duration
	cleanerInterval time.Duration

	sync.Mutex
	pool      []*dnsConn
	lastClean time.Time
}

type dnsConn struct {
	net.Conn
	frameLeft          int
	msgIDCounter       uint16
	peerLastActiveTime time.Time
}

func newDNSConn(c net.Conn, lastRead time.Time) *dnsConn {
	return &dnsConn{
		Conn:               c,
		frameLeft:          0,
		msgIDCounter:       dns.Id(),
		peerLastActiveTime: lastRead,
	}
}

func newConnPool(size int, ttl, gcInterval time.Duration) *connPool {
	return &connPool{
		maxSize:         size,
		ttl:             ttl,
		cleanerInterval: gcInterval,
		pool:            make([]*dnsConn, 0),
	}

}

// runCleaner must run under lock
func (p *connPool) runCleaner(force bool) {
	if p.disabled() || len(p.pool) == 0 {
		return
	}

	//scheduled or forced
	if force || time.Since(p.lastClean) > p.cleanerInterval {
		p.lastClean = time.Now()
		res := p.pool[:0]
		for i := range p.pool {
			// remove expired conns
			if time.Since(p.pool[i].peerLastActiveTime) < p.ttl {
				res = append(res, p.pool[i])
			} else { // expired, release the resources
				p.pool[i].Conn.Close()
				p.pool[i] = nil
			}
		}
		p.pool = res
	}

	//when the pool is full
	if len(p.pool) >= p.maxSize {
		res := p.pool[:0]
		mid := len(p.pool) >> 1
		for i := range p.pool {
			// remove half of the connections first
			if i < mid {
				p.pool[i].Conn.Close()
				p.pool[i] = nil
				continue
			}

			// then remove expired connections
			if time.Since(p.pool[i].peerLastActiveTime) < p.ttl {
				res = append(res, p.pool[i])
			} else {
				p.pool[i].Conn.Close()
				p.pool[i] = nil
			}
		}
		p.pool = res
	}
}

func (p *connPool) put(dc *dnsConn) {
	if dc == nil || dc.Conn == nil {
		return
	}

	if p.disabled() || dc.frameLeft == unknownBrokenDataSize {
		dc.Conn.Close()
		return
	}

	p.Lock()
	defer p.Unlock()

	p.runCleaner(false)

	if len(p.pool) >= p.maxSize {
		dc.Conn.Close() // pool is full, drop it
	} else {
		p.pool = append(p.pool, dc)
	}
}

func (p *connPool) get() (dc *dnsConn) {
	if p.disabled() {
		return nil
	}

	p.Lock()
	defer p.Unlock()

	p.runCleaner(false)

	if len(p.pool) > 0 {
		dc := p.pool[len(p.pool)-1]
		p.pool[len(p.pool)-1] = nil
		p.pool = p.pool[:len(p.pool)-1]

		if time.Since(dc.peerLastActiveTime) > p.ttl {
			dc.Conn.Close() // expired
			// the last elem is expired, means all elems are expired
			// remove them asap
			p.runCleaner(true)
			return nil
		}
		return dc
	}
	return nil
}

func (p *connPool) disabled() bool {
	return p == nil || p.maxSize <= 0 || p.ttl <= 0
}

type upstreamDoH struct {
	preparedURL []byte
	client      *http.Client
}

func newDoHUpstream(urlStr string, dialContext func(ctx context.Context, network, address string) (net.Conn, error), tlsConfig *tls.Config) (*upstreamDoH, error) {
	// check urlStr
	u, err := url.ParseRequestURI(urlStr)
	if err != nil {
		return nil, fmt.Errorf("invalid url: %w", err)
	}

	if u.Scheme != "https" {
		return nil, fmt.Errorf("invalid url scheme [%s]", u.Scheme)
	}

	u.ForceQuery = true // make sure we have a '?' at somewhere
	urlStr = u.String()
	if strings.HasSuffix(urlStr, "?") {
		urlStr = urlStr + "dns=" // the only one and the first arg
	} else {
		urlStr = urlStr + "&dns=" // the last arg
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
	c.preparedURL = []byte(urlStr)
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
	urlBuilder := pool.AcquireStringBuilder()
	defer pool.ReleaseStringBuilder(urlBuilder)
	urlBuilder.Write(u.preparedURL)
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

	// check Content-Length
	if resp.ContentLength > dns.MaxMsgSize {
		return nil, fmt.Errorf("content-length %d is bigger than dns.MaxMsgSize %d", resp.ContentLength, dns.MaxMsgSize)
	}

	if resp.ContentLength >= 0 && resp.ContentLength < 12 {
		return nil, fmt.Errorf("content-length %d is smaller than dns header size 12", resp.ContentLength)
	}

	var buf []byte
	if resp.ContentLength > 12 {
		buf = pool.GetMsgBuf(int(resp.ContentLength))
		defer pool.ReleaseMsgBuf(buf)
		_, err = io.ReadFull(resp.Body, buf)
		if err != nil {
			return nil, fmt.Errorf("unexpected err when read http resp body: %v", err)
		}
	} else { // resp.ContentLength = -1, unknown length
		bb := pool.AcquireBytesBuf()
		defer pool.ReleaseBytesBuf(bb)
		n, err := bb.ReadFrom(io.LimitReader(resp.Body, dns.MaxMsgSize+1))
		if n > dns.MaxMsgSize {
			return nil, fmt.Errorf("response body is too large, first 1kb data: %s", string(bb.Bytes()[:1024]))
		}
		if err != nil {
			return nil, fmt.Errorf("unexpected err when read http resp body: %v", err)
		}
		if bb.Len() < 12 {
			return nil, dns.ErrShortRead
		}
		buf = bb.Bytes()
	}

	r := new(dns.Msg)
	if err := r.Unpack(buf); err != nil {
		return nil, fmt.Errorf("invalid reply: %v", err)
	}
	return r, nil
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
