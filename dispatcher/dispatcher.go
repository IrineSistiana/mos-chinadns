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

	"github.com/IrineSistiana/mos-chinadns/dispatcher/notification"
	"github.com/IrineSistiana/mos-chinadns/dispatcher/pool"

	"github.com/miekg/dns"
)

const (
	// MaxUDPSize max udp packet size
	MaxUDPSize = 1480

	queryTimeout = time.Second * 5
)

// Dispatcher represents a dns query dispatcher
type Dispatcher struct {
	config *Config

	upstreams map[string]Upstream
}

// InitDispatcher inits a dispatcher from configuration
func InitDispatcher(conf *Config) (*Dispatcher, error) {
	d := new(Dispatcher)
	d.config = conf

	var rootCAs *x509.CertPool
	var err error
	if len(conf.CA.Path) != 0 {
		rootCAs, err = caPath2Pool(conf.CA.Path)
		if err != nil {
			return nil, fmt.Errorf("caPath2Pool: %w", err)
		}
		logger.Info("initDispatcher: CA cert loaded")
	}

	if len(conf.Upstream) == 0 {
		return nil, fmt.Errorf("no upstream")
	}
	d.upstreams = make(map[string]Upstream)
	for name := range conf.Upstream {
		u, err := NewUpstream(conf.Upstream[name], rootCAs)
		if err != nil {
			return nil, fmt.Errorf("failed to init upstream %s: %w", name, err)
		}
		d.upstreams[name] = u
	}

	return d, nil
}

// ServeDNS sends q to upstreams and return first valid result.
func (d *Dispatcher) ServeDNS(ctx context.Context, q *dns.Msg) (r *dns.Msg, err error) {
	return d.dispatch(ctx, q)
}

var (
	// ErrUpstreamsFailed all upstreams are failed or not respond in time.
	ErrUpstreamsFailed = errors.New("all upstreams failed or not respond in time")
)

func (d *Dispatcher) dispatch(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	requestLogger := getRequestLogger(q)
	resChan := pool.GetResChan()

	exchangeDNSWG := sync.WaitGroup{}
	exchangeDNSWG.Add(1)
	defer exchangeDNSWG.Done()

	upstreamWG := sync.WaitGroup{}

	for name, u := range d.upstreams {
		name := name
		u := u

		upstreamWG.Add(1)
		go func() {
			defer upstreamWG.Done()

			queryStart := time.Now()
			r, err := u.Exchange(ctx, q)
			rtt := time.Since(queryStart).Milliseconds()
			if err != nil {
				if err != context.Canceled && err != context.DeadlineExceeded {
					requestLogger.Warnf("dispatch: upstream %s err after %dms: %v,", name, rtt, err)
				}
				return
			}

			if r != nil {
				requestLogger.Debugf("dispatch: reply from upstream %s accepted, rtt: %dms", name, rtt)
				select {
				case resChan <- r:
				default:
				}
			}
		}()
	}
	upstreamFailedNotificationChan := pool.GetNotificationChan()

	// this go routine notifies the dispatch if all upstreams are failed
	// and release some resources.
	go func() {
		// all upstreams are returned
		upstreamWG.Wait()
		// avoid below select{} choose upstreamFailedNotificationChan
		// if both resChan and upstreamFailedNotificationChan are selectable
		if len(resChan) == 0 {
			notification.NoBlockNotify(upstreamFailedNotificationChan, notification.Failed)
		}

		// dispatch is returned
		exchangeDNSWG.Wait()

		// time to finial cleanup
		releaseRequestLogger(requestLogger)
		pool.ReleaseResChan(resChan)
		pool.ReleaseNotificationChan(upstreamFailedNotificationChan)
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
