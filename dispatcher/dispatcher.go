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

	"github.com/IrineSistiana/mos-chinadns/dispatcher/logger"

	"github.com/miekg/dns"
)

// Dispatcher represents a dns query dispatcher
type Dispatcher struct {
	config *Config

	upstreams []upstreamWithName
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
		logger.GetStd().Info("initDispatcher: CA cert loaded")
	}

	if len(conf.Upstream) == 0 {
		return nil, fmt.Errorf("no upstream")
	}
	d.upstreams = make([]upstreamWithName, 0, len(conf.Upstream))
	for name := range conf.Upstream {
		u, err := NewUpstream(name, conf.Upstream[name], rootCAs)
		if err != nil {
			return nil, fmt.Errorf("failed to init upstream %s: %w", name, err)
		}
		d.upstreams = append(d.upstreams, u)
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
	resChan := make(chan *dns.Msg, 1)
	upstreamWG := sync.WaitGroup{}
	for i := range d.upstreams {
		u := d.upstreams[i]

		upstreamWG.Add(1)
		go func() {
			defer upstreamWG.Done()

			queryStart := time.Now()
			r, err := u.Exchange(ctx, q)
			rtt := time.Since(queryStart).Milliseconds()
			if err != nil {
				if err != context.Canceled && err != context.DeadlineExceeded {
					logger.GetStd().Warnf("dispatch: [%v %d]: upstream %s err after %dms: %v,", q.Question, q.Id, u.getName(), rtt, err)
				}
				return
			}

			if r != nil {
				logger.GetStd().Debugf("dispatch: [%v %d]: reply from upstream %s accepted, rtt: %dms", q.Question, q.Id, u.getName(), rtt)
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
