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
	"github.com/IrineSistiana/mos-chinadns/dispatcher/config"
	"github.com/IrineSistiana/mos-chinadns/dispatcher/upstream"
	"io/ioutil"
	"sync"
	"time"

	"github.com/IrineSistiana/mos-chinadns/dispatcher/logger"

	"github.com/miekg/dns"
)

// Dispatcher represents a dns query dispatcher
type Dispatcher struct {
	config *config.Config

	servers         map[string]upstream.Upstream
	upstreamEntries map[string]*upstreamEntry

	// for faster range operation
	entriesSlice []*upstreamEntry

	ipsetHandler *ipsetHandler
}

// InitDispatcher inits a dispatcher from configuration
func InitDispatcher(c *config.Config) (*Dispatcher, error) {
	d := new(Dispatcher)
	d.config = c

	var rootCAs *x509.CertPool
	var err error
	if len(c.CA.Path) != 0 {
		rootCAs, err = caPath2Pool(c.CA.Path)
		if err != nil {
			return nil, fmt.Errorf("caPath2Pool: %w", err)
		}
		logger.GetStd().Info("initDispatcher: CA cert loaded")
	}

	// load server first
	if len(c.Server) == 0 {
		return nil, fmt.Errorf("no server")
	}
	d.servers = make(map[string]upstream.Upstream)
	for tag, serverConfig := range c.Server {
		server, err := upstream.NewUpstreamServer(serverConfig, rootCAs)
		if err != nil {
			return nil, fmt.Errorf("failed to init sever %s: %w", tag, err)
		}
		d.servers[tag] = server
	}

	if len(c.Upstream) == 0 {
		return nil, fmt.Errorf("no upstream")
	}
	d.entriesSlice = make([]*upstreamEntry, 0, len(c.Upstream))
	for name := range c.Upstream {
		u, err := d.newEntry(name, c.Upstream[name])
		if err != nil {
			return nil, fmt.Errorf("failed to init upstream %s: %w", name, err)
		}
		d.entriesSlice = append(d.entriesSlice, u)
	}

	handler, err := newIPSetHandler(c)
	if err != nil {
		return nil, fmt.Errorf("failed to init ipset handler: %w", err)
	}
	d.ipsetHandler = handler

	return d, nil
}

// ServeDNS sends q to upstreams and return first valid result.
func (d *Dispatcher) ServeDNS(ctx context.Context, q *dns.Msg) (r *dns.Msg, err error) {
	r, err = d.dispatch(ctx, q)
	if err != nil {
		return nil, err
	}
	if d.ipsetHandler != nil {
		err := d.ipsetHandler.applyIPSet(q, r)
		if err != nil {
			logger.GetStd().Warnf("dispatch: [%v %d]: ipset handler: %v", q.Question, q.Id, err)
		}
	}
	return r, nil
}

var (
	// ErrUpstreamsFailed all upstreams are failed or not respond in time.
	ErrUpstreamsFailed = errors.New("all upstreams failed or not respond in time")
)

func (d *Dispatcher) dispatch(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	resChan := make(chan *dns.Msg, 1)
	upstreamWG := sync.WaitGroup{}
	for i := range d.entriesSlice {
		entry := d.entriesSlice[i]

		upstreamWG.Add(1)
		go func() {
			defer upstreamWG.Done()

			queryStart := time.Now()
			r, err := entry.Exchange(ctx, q)
			rtt := time.Since(queryStart).Milliseconds()
			if err != nil {
				if err != context.Canceled && err != context.DeadlineExceeded {
					logger.GetStd().Warnf("dispatch: [%v %d]: upstream %s err after %dms: %v,", q.Question, q.Id, entry.name, rtt, err)
				}
				return
			}

			if r != nil {
				logger.GetStd().Debugf("dispatch: [%v %d]: reply from upstream %s accepted, rtt: %dms", q.Question, q.Id, entry.name, rtt)
				select {
				case resChan <- r:
				default:
				}
			}
		}()
	}
	upstreamFailedNotificationChan := make(chan struct{}, 0)

	// this go routine notifies the dispatch if all upstreams are failed
	go func() {
		// all upstreams are returned
		upstreamWG.Wait()
		// avoid below select{} choose upstreamFailedNotificationChan
		// if both resChan and upstreamFailedNotificationChan are selectable
		if len(resChan) == 0 {
			close(upstreamFailedNotificationChan)
		}
	}()

	select {
	case m := <-resChan:
		return m, nil
	case <-upstreamFailedNotificationChan:
		return nil, ErrUpstreamsFailed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func caPath2Pool(cas []string) (*x509.CertPool, error) {
	rootCAs := x509.NewCertPool()

	for _, ca := range cas {
		pem, err := ioutil.ReadFile(ca)
		if err != nil {
			return nil, fmt.Errorf("ReadFile: %w", err)
		}

		if ok := rootCAs.AppendCertsFromPEM(pem); !ok {
			return nil, fmt.Errorf("AppendCertsFromPEM: no certificate was successfully parsed in %s", ca)
		}
	}
	return rootCAs, nil
}
