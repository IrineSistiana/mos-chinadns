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

	"golang.org/x/net/http2"

	"github.com/IrineSistiana/mos-chinadns/dispatcher/bufpool"
	"github.com/IrineSistiana/mos-chinadns/dispatcher/utils"
	"github.com/miekg/dns"
	"golang.org/x/net/proxy"
)

const (
	tlsHandshakeTimeout = time.Second * 5
	dialTCPTimeout      = time.Second * 5
	dialUDPTimeout      = time.Second * 5
	generalIOTimeout    = time.Second * 1
	dohIOTimeout        = time.Second * 10
)

// Upstream reprenses a dns upsteam
type Upstream interface {
	// Exchange sends qRaw to upstream and return its reply. For better preformence, release the rRaw.
	Exchange(ctx context.Context, qRaw []byte) (rRaw *bufpool.MsgBuf, err error)
}

// upstreamCommon represents a udp/tcp/tls server
type upstreamCommon struct {
	dialNewConn func() (net.Conn, error)
	writeMsg    func(c io.Writer, msg []byte) (int, error)
	readMsg     func(c io.Reader) (msg *bufpool.MsgBuf, brokenDataLeft int, n int, err error)

	cp *connPool
}

// upstreamWithLimit represents server but has a concurrent limitation
type upstreamWithLimit struct {
	bk *bucket
	u  Upstream
}

// NewUpstream inits a upstream instance base on the config.
// maxConcurrentQueries limits the max concurrent queries for this upstream. 0 means disable the limit.
// rootCAs will be used in dot/doh upstream in tls server verification.
func NewUpstream(sc *BasicServerConfig, maxConcurrentQueries int, rootCAs *x509.CertPool) (Upstream, error) {
	if sc == nil {
		return nil, errors.New("no server config")
	}

	var upstream Upstream
	switch sc.Protocol {
	case "udp", "":
		dialUDP := func() (net.Conn, error) {
			return net.DialTimeout("udp", sc.Addr, dialUDPTimeout)
		}
		upstream = &upstreamCommon{
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
		upstream = &upstreamCommon{
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
		upstream = &upstreamCommon{
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

		upstream, err = newDoHUpstream(sc.DoH.URL, dialContext, tlsConf)
		if err != nil {
			return nil, fmt.Errorf("failed to init DoH upstream: %v", err)
		}
	default:
		return nil, fmt.Errorf("unsupport protocol: %s", sc.Protocol)
	}
	if maxConcurrentQueries > 0 {
		limitedUpstream := &upstreamWithLimit{bk: newBucket(maxConcurrentQueries), u: upstream}
		return limitedUpstream, nil
	}
	return upstream, nil
}

var (
	errTooManyConcurrentQueries = errors.New("too many concurrent queries")
)

func (u *upstreamWithLimit) Exchange(ctx context.Context, qRaw []byte) (rRaw *bufpool.MsgBuf, err error) {
	if u.bk.aquire() == false {
		return nil, errTooManyConcurrentQueries
	}
	defer u.bk.release()
	return u.u.Exchange(ctx, qRaw)
}

func (u *upstreamCommon) Exchange(ctx context.Context, qRaw []byte) (rRaw *bufpool.MsgBuf, err error) {
	return u.exchange(ctx, qRaw, false)
}

func (u *upstreamCommon) exchange(ctx context.Context, qRaw []byte, forceNewConn bool) (rRaw *bufpool.MsgBuf, err error) {
	if err = ctx.Err(); err != nil {
		return nil, err
	}

	if len(qRaw) < 12 {
		return nil, dns.ErrShortRead
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
		dc.msgID++
	}

	var queryCtx context.Context
	var cancel func()
	// this once is to make sure that the following
	// dc.Conn.SetDeadline wouldn't be called after dc is put into connPool
	once := sync.Once{}
	qRawCopy := bufpool.AcquireMsgBufAndCopy(qRaw)
	defer bufpool.ReleaseMsgBuf(qRawCopy)
	originalID := utils.ExchangeMsgID(dc.msgID, qRawCopy.Bytes())

	// write first
	dc.SetDeadline(time.Now().Add(generalIOTimeout)) // give write enough time to complete, avoid broken write.
	n, err := u.writeMsg(dc.Conn, qRawCopy.Bytes())
	if n > 0 {
		dc.lastIO = time.Now()
	}
	if n != qRawCopy.Size() {
		err = fmt.Errorf("writeMsg: broken write: %v", err)
	}
	if err != nil {
		goto ioErr
	}

	dc.SetDeadline(time.Time{}) // overwrite ddl, this ddl should be handled by queryCtx
	queryCtx, cancel = context.WithCancel(ctx)
	defer cancel()
	go func() {
		select {
		case <-queryCtx.Done():
			once.Do(func() { dc.SetDeadline(time.Now()) })
		}
	}()

	// if we need to empty the conn (some data of previous reply)
	if dc.frameleft > 0 {
		buf := bufpool.AcquireMsgBuf(dc.frameleft)
		n, err = io.ReadFull(dc, buf.Bytes())
		bufpool.ReleaseMsgBuf(buf)
		if n > 0 {
			dc.lastIO = time.Now()
			dc.frameleft = dc.frameleft - n
		}
		if err != nil {
			goto ioErr
		}
	}

read:
	rRaw, dc.frameleft, n, err = u.readMsg(dc.Conn)
	if n > 0 {
		dc.lastIO = time.Now()
	}
	if err != nil {
		goto ioErr
	}

	if utils.GetMsgID(rRaw.Bytes()) != dc.msgID {
		bufpool.ReleaseMsgBuf(rRaw)
		if !isNewConn {
			// this connection is reused, data might be the reply
			// of a previous qRaw, not this qRaw.
			// try to read again
			goto read
		} else {
			// new connection should not receive a mismatched id, this is an error
			dc.Close()
			err = dns.ErrId
			goto ioErr
		}
	}

	once.Do(func() {}) // do nothing, just fire the once
	u.cp.put(dc)

	utils.SetMsgID(originalID, rRaw.Bytes())
	return rRaw, nil

ioErr:
	ctxErr := queryCtx.Err()
	// err caused by cancelled ctx, it's ok to reuse the connection
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		if dc.frameleft == unknownBrokenDataSize {
			dc.Close()
			return nil, fmt.Errorf("conn is broken, %v", err)
		}
		once.Do(func() {}) // do nothing, just fire the once
		u.cp.put(dc)
		if ctxErr != nil {
			return nil, ctxErr
		}
		return nil, err
	}

	if isNewConn { // new connection shouldn't have any other type of err
		dc.Close()
		return nil, fmt.Errorf("new conn io err, %v", err)
	}

	// reused connection got an unexpected err
	dc.Close()
	if ctxErr != nil {
		return nil, err // return the true err instead ctx's err
	}
	// but ctx isn't done yet, open a new conn and try again
	return u.exchange(ctx, qRaw, true)
}

type connPool struct {
	sync.Mutex
	maxSize          int
	ttl              time.Duration
	cleannerInterval time.Duration

	pool      []*dnsConn
	lastClean time.Time
}

type dnsConn struct {
	net.Conn
	frameleft int
	msgID     uint16
	lastIO    time.Time
}

func newDNSConn(c net.Conn, lastIO time.Time) *dnsConn {
	return &dnsConn{
		Conn:      c,
		frameleft: 0,
		msgID:     dns.Id(),
		lastIO:    lastIO,
	}
}

func newConnPool(size int, ttl, gcInterval time.Duration) *connPool {
	return &connPool{
		maxSize:          size,
		ttl:              ttl,
		cleannerInterval: gcInterval,
		pool:             make([]*dnsConn, 0),
	}

}

// runCleanner must run under lock
func (p *connPool) runCleanner(force bool) {
	if p.disabled() || len(p.pool) == 0 {
		return
	}

	//scheduled or forced
	if force || time.Since(p.lastClean) > p.cleannerInterval {
		p.lastClean = time.Now()
		res := p.pool[:0]
		for i := range p.pool {
			// remove expired conns
			if time.Since(p.pool[i].lastIO) < p.ttl {
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
			// forcely remove half conns first
			if i < mid {
				p.pool[i].Conn.Close()
				p.pool[i] = nil
				continue
			}

			//then remove expired conns
			if time.Since(p.pool[i].lastIO) < p.ttl {
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

	if p.disabled() || dc.frameleft == unknownBrokenDataSize {
		dc.Conn.Close()
		return
	}

	p.Lock()
	defer p.Unlock()

	p.runCleanner(false)

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

	p.runCleanner(false)

	if len(p.pool) > 0 {
		dc := p.pool[len(p.pool)-1]
		p.pool[len(p.pool)-1] = nil
		p.pool = p.pool[:len(p.pool)-1]

		if time.Since(dc.lastIO) > p.ttl {
			dc.Conn.Close() // expired
			// the last elem is expired, means all elems are expired
			// remove them asap
			p.runCleanner(true)
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
func (u *upstreamDoH) Exchange(_ context.Context, qRaw []byte) (rRaw *bufpool.MsgBuf, err error) {
	if len(qRaw) < 12 {
		return nil, dns.ErrShortRead // avoid panic when access msg id in m[0] and m[1]
	}

	ctx, cancel := context.WithTimeout(context.Background(), dohIOTimeout)
	defer cancel()
	qRawWithNewID := bufpool.AcquireMsgBufAndCopy(qRaw)
	defer bufpool.ReleaseMsgBuf(qRawWithNewID)

	// In order to maximize HTTP cache friendliness, DoH clients using media
	// formats that include the ID field from the DNS message header, such
	// as "application/dns-message", SHOULD use a DNS ID of 0 in every DNS
	// request.
	// https://tools.ietf.org/html/rfc8484 4.1
	oldID := utils.ExchangeMsgID(0, qRawWithNewID.Bytes())

	// Padding characters for base64url MUST NOT be included.
	// See: https://tools.ietf.org/html/rfc8484 6
	// That's why we use base64.RawURLEncoding
	urlBuilder := bufpool.AcquireStringBuilder()
	defer bufpool.ReleaseStringBuilder(urlBuilder)
	urlBuilder.Write(u.preparedURL)
	encoder := base64.NewEncoder(base64.RawURLEncoding, urlBuilder)
	encoder.Write(qRawWithNewID.Bytes())
	encoder.Close()

	rRaw, err = u.doHTTP(ctx, urlBuilder.String())
	if err != nil {
		return nil, fmt.Errorf("doHTTP: %w", err)
	}

	// change the id back
	if utils.GetMsgID(rRaw.Bytes()) != 0 { // check msg id
		bufpool.ReleaseMsgBuf(rRaw)
		return nil, dns.ErrId
	}
	utils.SetMsgID(oldID, rRaw.Bytes())
	return rRaw, nil
}

func (u *upstreamDoH) doHTTP(ctx context.Context, url string) (*bufpool.MsgBuf, error) {

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

	// check statu code
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

	var msgBuf *bufpool.MsgBuf
	if resp.ContentLength > 12 {
		msgBuf = bufpool.AcquireMsgBuf(int(resp.ContentLength))
		_, err = io.ReadFull(resp.Body, msgBuf.Bytes())
		if err != nil {
			bufpool.ReleaseMsgBuf(msgBuf)
			return nil, fmt.Errorf("unexpected err when read http resp body: %v", err)
		}
	} else { // resp.ContentLength = -1, unknown length
		buf := bufpool.AcquireBytesBuf()
		defer bufpool.ReleaseBytesBuf(buf)
		_, err = buf.ReadFrom(io.LimitReader(resp.Body, dns.MaxMsgSize))
		if err != nil {
			if err == io.EOF {
				return nil, fmt.Errorf("response body is too large: buf.ReadFrom(): %w", err)
			}
			return nil, fmt.Errorf("unexpected err when read http resp body: %v", err)
		}
		if buf.Len() < 12 {
			return nil, dns.ErrShortRead
		}
		msgBuf = bufpool.AcquireMsgBufAndCopy(buf.Bytes())
	}

	return msgBuf, nil
}

func getSocks5ContextDailer(network, sock5Address string) (proxy.ContextDialer, error) {
	d, err := proxy.SOCKS5(network, sock5Address, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to init socks5 dialer: %v", err)
	}
	contextDialer, ok := d.(proxy.ContextDialer)
	if !ok {
		return nil, errors.New("internel err: socks5 dialer is not a proxy.ContextDialer")
	}
	return contextDialer, nil
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

func (b *bucket) aquire() bool {
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
