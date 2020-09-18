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
	"errors"
	"fmt"
	"github.com/IrineSistiana/mos-chinadns/dispatcher/config"
	"github.com/IrineSistiana/mos-chinadns/dispatcher/logger"
	"github.com/IrineSistiana/mos-chinadns/dispatcher/netlist"
	"github.com/IrineSistiana/mos-chinadns/dispatcher/upstream"
	"github.com/miekg/dns"
	"net"
)

// upstreamEntry represents a mos-chinadns upstream.
type upstreamEntry struct {
	name string

	policies struct {
		query struct {
			unhandlableTypes *action
			Domain           *domainPolicies
		}
		reply struct {
			errorRcode *action
			cname      *domainPolicies
			withoutIP  *action
			ip         *ipPolicies
		}
	}

	backend upstream.Upstream
}

// newEntry inits a upstream instance.
func (d *Dispatcher) newEntry(name string, uc *config.UpstreamEntryConfig) (*upstreamEntry, error) {
	if uc == nil {
		return nil, errors.New("no server config")
	}

	entry := new(upstreamEntry)
	entry.name = name

	backend, ok := d.servers[uc.ServerTag]
	if !ok {
		return nil, fmt.Errorf("can not find server with tag [%s]", uc.ServerTag)
	}
	entry.backend = backend

	// load policies
	if len(uc.Policies.Query.UnhandlableTypes) != 0 {
		action, err := d.newAction(uc.Policies.Query.UnhandlableTypes)
		if err != nil {
			return nil, fmt.Errorf("invalid unhandlable types action [%s]: %v", uc.Policies.Query.UnhandlableTypes, err)
		}
		entry.policies.query.unhandlableTypes = action
	}

	if len(uc.Policies.Query.Domain) != 0 {
		p, err := d.newDomainPolicies(uc.Policies.Query.Domain, false)
		if err != nil {
			return nil, fmt.Errorf("failed to load domain policies, %w", err)
		}
		entry.policies.query.Domain = p
	}

	if len(uc.Policies.Reply.ErrorRcode) != 0 {
		action, err := d.newAction(uc.Policies.Reply.ErrorRcode)
		if err != nil {
			return nil, fmt.Errorf("invalid err rcode action [%s]: %v", uc.Policies.Reply.ErrorRcode, err)
		}
		entry.policies.reply.errorRcode = action
	}

	if len(uc.Policies.Reply.CNAME) != 0 {
		p, err := d.newDomainPolicies(uc.Policies.Reply.CNAME, true)
		if err != nil {
			return nil, fmt.Errorf("failed to load cname policies, %v", err)
		}
		entry.policies.reply.cname = p
	}

	if len(uc.Policies.Reply.WithoutIP) != 0 {
		action, err := d.newAction(uc.Policies.Reply.WithoutIP)
		if err != nil {
			return nil, fmt.Errorf("invalid without ip action [%s]: %v", uc.Policies.Reply.WithoutIP, err)
		}
		entry.policies.reply.withoutIP = action
	}

	if len(uc.Policies.Reply.IP) != 0 {
		p, err := d.newIPPolicies(uc.Policies.Reply.IP)
		if err != nil {
			return nil, fmt.Errorf("failed to load ip policies, %v", err)
		}
		entry.policies.reply.ip = p
	}

	return entry, nil
}

func isUnhandlableType(q *dns.Msg) bool {
	return q.Opcode != dns.OpcodeQuery || len(q.Question) != 1 || q.Question[0].Qclass != dns.ClassINET || (q.Question[0].Qtype != dns.TypeA && q.Question[0].Qtype != dns.TypeAAAA)
}

func (u *upstreamEntry) Exchange(ctx context.Context, q *dns.Msg) (r *dns.Msg, err error) {
	return u.exchange(ctx, q)
}

func (u *upstreamEntry) exchange(ctx context.Context, q *dns.Msg) (r *dns.Msg, err error) {

	// check query
	// check msg type
	if isUnhandlableType(q) {
		if action := u.policies.query.unhandlableTypes; action != nil {
			logger.GetStd().Debugf("upstream %s: [%v %d]: query is unhandlable type, action [%s]", u.name, q.Question, q.Id, action.mode)
			switch action.mode {
			case policyActionAccept:
				return u.backend.Exchange(ctx, q)
			case policyActionDeny:
				return nil, nil
			case policyActionRedirect:
				return action.redirect.Exchange(ctx, q)
			default:
				return nil, fmt.Errorf("unexpected unhandlableTypes action [%s]", action.mode)
			}
		}
	}

	// check domain
	if u.policies.query.Domain != nil {
		if action := u.policies.query.Domain.check(q.Question[0].Name); action != nil {
			logger.GetStd().Debugf("upstream %s: [%v %d]: query is matched by domain, action [%s]", u.name, q.Question, q.Id, action.mode)
			switch action.mode {
			case policyActionAccept:
				return u.backend.Exchange(ctx, q)
			case policyActionDeny:
				return nil, nil
			default:
				return nil, fmt.Errorf("unexpected domain action [%s]", action.mode)
			}
		}
	}

	// send to upstream
	r, err = u.backend.Exchange(ctx, q)
	if err != nil {
		return nil, err
	}

	// check reply
	// check Rcode
	if r.Rcode != dns.RcodeSuccess {
		if action := u.policies.reply.errorRcode; action != nil {
			logger.GetStd().Debugf("upstream %s: [%v %d]: reply has a error rcode, action [%s]", u.name, q.Question, q.Id, action.mode)
			switch action.mode {
			case policyActionAccept:
				return r, nil
			case policyActionDeny:
				return nil, nil
			case policyActionRedirect:
				return action.redirect.Exchange(ctx, q)
			default:
				return nil, fmt.Errorf("unexpected errorRcode action [%s]", action.mode)
			}
		}
	}

	// check CNAME
	if u.policies.reply.cname != nil {
		if action := checkMsgCNAME(u.policies.reply.cname, r); action != nil {
			logger.GetStd().Debugf("upstream %s: [%v %d]: reply cname matched, action [%s]", u.name, q.Question, q.Id, action.mode)
			switch action.mode {
			case policyActionAccept:
				return r, nil
			case policyActionDeny:
				return nil, nil
			case policyActionRedirect:
				return action.redirect.Exchange(ctx, q)
			default:
				return nil, fmt.Errorf("unexpected cname action [%s]", action.mode)
			}
		}
	}

	// check ip
	if checkMsgHasValidIP(r) == false {
		if action := u.policies.reply.withoutIP; action != nil {
			logger.GetStd().Debugf("upstream %s: [%v %d]: reply don not has any valid ip, action [%s]", u.name, q.Question, q.Id, action.mode)
			switch action.mode {
			case policyActionAccept:
				return r, nil
			case policyActionDeny:
				return nil, nil
			case policyActionRedirect:
				return action.redirect.Exchange(ctx, q)
			default:
				return nil, fmt.Errorf("unexpected cname action [%s]", action.mode)
			}
		}
	}

	if u.policies.reply.ip != nil {
		if action := checkMsgIP(u.policies.reply.ip, r); action != nil {
			logger.GetStd().Debugf("upstream %s: [%v %d]: reply ip matched, action [%s]", u.name, q.Question, q.Id, action.mode)
			switch action.mode {
			case policyActionAccept:
				return r, nil
			case policyActionDeny:
				return nil, nil
			case policyActionRedirect:
				return action.redirect.Exchange(ctx, q)
			default:
				return nil, fmt.Errorf("unexpected ip action [%s]", action.mode)
			}
		}
	}

	// default accept
	return r, nil
}

// checkMsgIP checks m's ip RR in answer section. If ip is a
func checkMsgIP(p *ipPolicies, m *dns.Msg) *action {
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
			logger.GetStd().Warnf("checkMsgIP: internal err: failed to convert ip %v to ipv6", ip)
			continue
		} else {
			ip = ipv6
		}

		action := p.check(netlist.Conv(ip))
		return action
	}
	return nil
}

func checkMsgCNAME(p *domainPolicies, m *dns.Msg) *action {
	for i := range m.Answer {
		if cname, ok := m.Answer[i].(*dns.CNAME); ok {
			a := p.check(cname.Target)
			if a != nil {
				return a
			}
		}
	}
	return nil
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
