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

package upstream

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/IrineSistiana/mos-chinadns/dispatcher/bufpool"
	"github.com/miekg/dns"
	"golang.org/x/net/http2"
)

type upstreamDoH struct {
	urlTemplate string
	client      *http.Client
}

func NewDoHUpstream(urlEndpoint string, dialContext func(ctx context.Context, network, address string) (net.Conn, error), tlsConfig *tls.Config) (Upstream, error) {
	// check urlTemplate
	u, err := url.ParseRequestURI(urlEndpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid url: %w", err)
	}

	if u.Scheme != "https" {
		return nil, fmt.Errorf("invalid url scheme [%s]", u.Scheme)
	}

	u.ForceQuery = true // make sure we have a '?' at somewhere
	urlEndpoint = u.String()
	if strings.HasSuffix(urlEndpoint, "?") {
		urlEndpoint = urlEndpoint + "dns=" // the only one and the first arg
	} else {
		urlEndpoint = urlEndpoint + "&dns=" // the last arg
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
	c.urlTemplate = urlEndpoint
	c.client = &http.Client{
		Transport: transport,
	}

	return c, nil
}

//Exchange: DoH upstream has its own context to control timeout, it will not follow the ctx.
func (u *upstreamDoH) Exchange(_ context.Context, q *dns.Msg) (r *dns.Msg, err error) {

	ctx, cancel := context.WithTimeout(context.Background(), dohIOTimeout)
	defer cancel()

	buf, err := bufpool.GetMsgBufFor(q)
	if err != nil {
		return nil, fmt.Errorf("invalid msg q: %w", err)
	}

	rRaw, err := q.PackBuffer(buf)
	if err != nil {
		return nil, fmt.Errorf("invalid msg q: %w", err)
	}

	// In order to maximize HTTP cache friendliness, DoH clients using media
	// formats that include the ID field from the DNS message header, such
	// as "application/dns-message", SHOULD use a DNS ID of 0 in every DNS
	// request.
	// https://tools.ietf.org/html/rfc8484 4.1
	rRaw[0] = 0
	rRaw[1] = 0

	urlBuilder := acquireDoHURLBuilder()
	defer releaseDoHURLBuilder(urlBuilder)

	// Padding characters for base64url MUST NOT be included.
	// See: https://tools.ietf.org/html/rfc8484 6
	// That's why we use base64.RawURLEncoding
	urlBuilder.Grow(len(u.urlTemplate) + base64.RawURLEncoding.EncodedLen(len(rRaw)))
	urlBuilder.WriteString(u.urlTemplate)
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
		buf = bufpool.GetMsgBuf(int(resp.ContentLength))
		defer bufpool.ReleaseMsgBuf(buf)
		_, err = io.ReadFull(resp.Body, buf)
		if err != nil {
			return nil, fmt.Errorf("unexpected err when read http resp body: %w", err)
		}
	case resp.ContentLength >= 0:
		return nil, fmt.Errorf("content-length %d is smaller than dns header size 12", resp.ContentLength)
	case resp.ContentLength == -1: // unknown length
		bb := acquireDoHReadBuf()
		defer releaseDoHReadBuf(bb)
		n, err := bb.ReadFrom(io.LimitReader(resp.Body, dns.MaxMsgSize+1))
		if err != nil {
			return nil, fmt.Errorf("unexpected err when read http resp body: %w", err)
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
		return nil, fmt.Errorf("invalid reply: %w", err)
	}
	return r, nil
}

var (
	dohReadBytesBufPool = sync.Pool{
		New: func() interface{} {
			return new(bytes.Buffer)
		},
	}

	dohURLStringBuilderPool = sync.Pool{
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

func acquireDoHURLBuilder() *bytes.Buffer {
	return dohURLStringBuilderPool.Get().(*bytes.Buffer)
}

func releaseDoHURLBuilder(builder *bytes.Buffer) {
	builder.Reset()
	dohURLStringBuilderPool.Put(builder)
}
