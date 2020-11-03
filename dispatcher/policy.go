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
	"fmt"
	"github.com/IrineSistiana/mos-chinadns/dispatcher/matcher"
	"github.com/IrineSistiana/mos-chinadns/dispatcher/matcher/domain"
	"github.com/IrineSistiana/mos-chinadns/dispatcher/matcher/netlist"
	"github.com/IrineSistiana/mos-chinadns/dispatcher/upstream"
	"net"
	"strings"
)

type actionMode uint8

const (
	policyActionAcceptStr      string = "accept"
	policyActionDenyStr        string = "deny"
	policyActionRedirectPrefix string = "redirect"

	policyActionAccept actionMode = iota
	policyActionDeny
	policyActionRedirect
)

var actionModeToStr = map[actionMode]string{
	policyActionAccept:   policyActionAcceptStr,
	policyActionDeny:     policyActionDenyStr,
	policyActionRedirect: policyActionRedirectPrefix,
}

func (m actionMode) String() string {
	s, ok := actionModeToStr[m]
	if ok {
		return s
	}
	return fmt.Sprintf("unknown action mode %d", m)
}

type action struct {
	mode     actionMode
	redirect upstream.Upstream
}

// newAction accepts policyActionAcceptStr, policyActionDenyStr
// and string with prefix policyActionRedirectStr.
func newAction(s string, servers map[string]upstream.Upstream) (*action, error) {
	var mode actionMode
	var redirect upstream.Upstream
	var ok bool
	switch {
	case s == policyActionAcceptStr:
		mode = policyActionAccept
	case s == policyActionDenyStr:
		mode = policyActionDeny
	case strings.HasPrefix(s, policyActionRedirectPrefix):
		mode = policyActionRedirect
		serverTag := strings.TrimLeft(s, policyActionRedirectPrefix+"_")
		redirect, ok = servers[serverTag]
		if !ok {
			return nil, fmt.Errorf("unable to redirect, can not find server with tag [%s]", serverTag)
		}
	default:
		return nil, fmt.Errorf("invalid action [%s]", s)
	}

	return &action{mode: mode, redirect: redirect}, nil
}

type ipPolicies struct {
	policies      []*ipPolicy
	defaultAction *action
}

type ipPolicy struct {
	matcher netlist.Matcher
	action  *action
}

type domainPolicies struct {
	policies      []*domainPolicy
	defaultAction *action
}

type domainPolicy struct {
	matcher domain.Matcher
	action  *action
}

func newIPPolicies(s string, servers map[string]upstream.Upstream) (*ipPolicies, error) {
	ipps := new(ipPolicies)
	ipps.policies = make([]*ipPolicy, 0)

	ss := strings.Split(s, "|")
	for i := range ss {
		ipp := new(ipPolicy)

		tmp := strings.SplitN(ss[i], ":", 2)

		actionStr := tmp[0]
		action, err := newAction(actionStr, servers)
		if err != nil {
			return nil, fmt.Errorf("invalid ip policy at index %d: %w", i, err)
		}
		ipp.action = action

		if len(tmp) == 2 {
			file := tmp[1]
			if len(file) != 0 {
				m, err := matcher.NewIPMatcherFromFile(file)
				if err != nil {
					return nil, fmt.Errorf("failed to load ip file from %s, %w", file, err)
				}
				ipp.matcher = m
			}
		}

		ipps.policies = append(ipps.policies, ipp)
	}

	return ipps, nil
}

func (ps *ipPolicies) check(ip net.IP) *action {
	for i := range ps.policies {
		if ps.policies[i].matcher == nil { // nil matcher means match-all
			return ps.policies[i].action
		}

		if ps.policies[i].matcher.Match(ip) {
			return ps.policies[i].action
		}
	}

	return nil
}

func newDomainPolicies(s string, servers map[string]upstream.Upstream, allowRedirect bool) (*domainPolicies, error) {
	dps := new(domainPolicies)
	dps.policies = make([]*domainPolicy, 0)

	ss := strings.Split(s, "|")
	for i := range ss {
		dp := new(domainPolicy)

		tmp := strings.SplitN(ss[i], ":", 2)

		actionStr := tmp[0]
		action, err := newAction(actionStr, servers)
		if err != nil {
			return nil, fmt.Errorf("invalid domain policy at index %d: %w", i, err)
		}
		if !allowRedirect && action.mode == policyActionRedirect {
			return nil, fmt.Errorf("invalid domain policy at index %d: redirect mode is not allowed here", i)
		}

		dp.action = action

		if len(tmp) == 2 {
			file := tmp[1]
			if len(file) != 0 {
				m, err := matcher.NewDomainMatcherFormFile(file)
				if err != nil {
					return nil, fmt.Errorf("failed to load domain file from %s, %w", file, err)
				}
				dp.matcher = m
			}
		}

		dps.policies = append(dps.policies, dp)
	}

	return dps, nil
}

func (ps *domainPolicies) check(fqdn string) *action {
	for i := range ps.policies {
		if ps.policies[i].matcher == nil {
			return ps.policies[i].action
		}

		if ps.policies[i].matcher != nil && ps.policies[i].matcher.Match(fqdn) {
			return ps.policies[i].action
		}
	}

	return nil
}
