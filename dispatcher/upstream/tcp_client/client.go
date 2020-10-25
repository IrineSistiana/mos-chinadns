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

package tcpClient

import (
	"context"
	"errors"
	"github.com/IrineSistiana/mos-chinadns/dispatcher/logger"
	"github.com/IrineSistiana/mos-chinadns/dispatcher/utils"
	"github.com/miekg/dns"
	"net"
	"sync/atomic"
	"time"
)

type Client struct {
	ctx          context.Context
	dial         func() (net.Conn, error)
	readTimeout  time.Duration
	writeTimeout time.Duration
	idleTimeout  time.Duration

	sender chan *query
}

type query struct {
	ctx      context.Context
	m        *dns.Msg
	receiver chan *result
}

type result struct {
	m   *dns.Msg
	err error
}

type worker struct {
	pool *Client
	conn net.Conn

	er                atomic.Value // read err
	readLoopEventChan chan *dns.Msg
}

func New(ctx context.Context, dial func() (net.Conn, error), readTimeout, writeTimeout, idleTimeout time.Duration) *Client {
	return &Client{
		ctx:          ctx,
		dial:         dial,
		readTimeout:  readTimeout,
		writeTimeout: writeTimeout,
		idleTimeout:  idleTimeout,
		sender:       make(chan *query),
	}
}

func (p *Client) Query(ctx context.Context, q *dns.Msg) (r *dns.Msg, err error) {
	if p.idleTimeout == 0 {
		return p.handleQueryNoCR(ctx, q)
	}
	return p.handleQuery(ctx, q)
}

// handle query without connection reuse
func (p *Client) handleQueryNoCR(_ context.Context, q *dns.Msg) (r *dns.Msg, err error) {
	c, err := p.dial()
	if err != nil {
		return nil, err
	}
	defer c.Close()

	c.SetWriteDeadline(time.Now().Add(p.writeTimeout))
	_, err = utils.WriteMsgToTCP(c, q)
	if err != nil {
		return nil, err
	}
	c.SetReadDeadline(time.Now().Add(p.readTimeout))
	r, _, err = utils.ReadMsgFromTCP(c)
	return r, err
}

// handle query with connection reuse
func (p *Client) handleQuery(ctx context.Context, q *dns.Msg) (r *dns.Msg, err error) {
	receiver := make(chan *result, 1)
	query := &query{ctx: ctx, m: q, receiver: receiver}
	select {
	case p.sender <- query:
	default:
		w, err := p.newWorker()
		if err != nil {
			return nil, err
		}
		go w.run(query)
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case result := <-receiver:
		return result.m, result.err
	}
}

func (p *Client) newWorker() (*worker, error) {
	conn, err := p.dial()
	if err != nil {
		return nil, err
	}

	return &worker{
		pool:              p,
		conn:              conn,
		readLoopEventChan: make(chan *dns.Msg),
	}, nil
}

func (w *worker) run(firstQuery *query) {
	defer w.conn.Close()
	logger.GetStd().Debugf("conn worker %p: %s -> %s is started", w, w.conn.LocalAddr(), w.conn.RemoteAddr())

	// read loop
	go func() {
		err := w.readLoop()
		if err != nil {
			logger.GetStd().Debugf("conn worker %p: read loop exited, %v", w, err)
		}
	}()

	// handle first query
	if err := w.handleQuery(firstQuery); err != nil {
		logger.GetStd().Debugf("conn worker %p: exited, %v", w, err)
		return
	}

	// write loop
	err := w.writeLoop()
	if err != nil {
		logger.GetStd().Debugf("conn worker %p: exited, %v", w, err)
	}
}

func (w *worker) readLoop() error {
	for {
		r, _, err := utils.ReadMsgFromTCP(w.conn)
		if err != nil {
			w.er.Store(err)
			close(w.readLoopEventChan)
			return err
		}

		select {
		case w.readLoopEventChan <- r:
		default:
		}
	}
}

func (w *worker) writeLoop() error {
	idleTimer := utils.GetTimer(w.pool.idleTimeout)
	defer utils.ReleaseTimer(idleTimer)

	for {
		select {
		case <-w.pool.ctx.Done():
			return w.pool.ctx.Err()
		case <-idleTimer.C:
			return errors.New("idle timeout")
		case _, ok := <-w.readLoopEventChan: // idle read, ignore the msg
			if !ok { // read loop is exited
				e := w.er.Load()
				err, _ := e.(error) // read the read err
				return err
			}

		case q := <-w.pool.sender: // received a msg from pool
			if err := w.handleQuery(q); err != nil {
				return err
			}
			utils.ResetAndDrainTimer(idleTimer, w.pool.idleTimeout)
		}
	}
}

func (w *worker) handleQuery(q *query) error {
	w.conn.SetWriteDeadline(time.Now().Add(w.pool.writeTimeout))
	_, err := utils.WriteMsgToTCP(w.conn, q.m)
	if err != nil {
		select {
		case q.receiver <- &result{m: nil, err: err}:
		default:
		}
		return err
	}

	readTimeoutTimer := utils.GetTimer(w.pool.readTimeout)
	defer utils.ReleaseTimer(readTimeoutTimer)

	select {
	case <-w.pool.ctx.Done(): // ctx is done
		return err
	case <-readTimeoutTimer.C:
		return errors.New("read timeout")
	case r, ok := <-w.readLoopEventChan: // read loop event
		if !ok { // read loop is exited
			e := w.er.Load()
			err, _ := e.(error) // read the read err
			select {
			case q.receiver <- &result{m: nil, err: err}:
			default:
			}
			return err
		}
		// got a reply
		select {
		case q.receiver <- &result{m: r, err: nil}:
		default:
		}
	}
	return nil
}
