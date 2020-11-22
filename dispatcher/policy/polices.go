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

package policy

import (
	"fmt"
	"github.com/IrineSistiana/mos-chinadns/dispatcher/matcher/domain"
	"github.com/IrineSistiana/mos-chinadns/dispatcher/matcher/netlist"
	"github.com/IrineSistiana/mos-chinadns/dispatcher/upstream"
	"net"
	"strings"
)

type IPPolicies struct {
	policies []*ipPolicy
}

type ipPolicy struct {
	matcher netlist.Matcher
	action  *Action
}

type DomainPolicies struct {
	policies []*domainPolicy
}

type domainPolicy struct {
	matcher domain.Matcher
	action  *Action
}

func NewIPPolicies(s string, servers map[string]upstream.Upstream) (*IPPolicies, error) {
	ipps := new(IPPolicies)
	ipps.policies = make([]*ipPolicy, 0)

	ss := strings.Split(s, "|")
	for i := range ss {
		ipp := new(ipPolicy)

		tmp := strings.SplitN(ss[i], ":", 2)

		actionStr := tmp[0]
		action, err := NewAction(actionStr, servers)
		if err != nil {
			return nil, fmt.Errorf("invalid ip policy at index %d: %w", i, err)
		}
		ipp.action = action

		if len(tmp) == 2 {
			file := tmp[1]
			if len(file) != 0 {
				m, err := netlist.NewIPMatcherFromFile(file)
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

func (ps *IPPolicies) Match(ip net.IP) *Action {
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

func NewDomainPolicies(s string, servers map[string]upstream.Upstream) (*DomainPolicies, error) {
	dps := new(DomainPolicies)
	dps.policies = make([]*domainPolicy, 0)

	ss := strings.Split(s, "|")
	for i := range ss {
		dp := new(domainPolicy)

		tmp := strings.SplitN(ss[i], ":", 2)

		actionStr := tmp[0]
		action, err := NewAction(actionStr, servers)
		if err != nil {
			return nil, fmt.Errorf("invalid domain policy at index %d: %w", i, err)
		}

		dp.action = action

		if len(tmp) == 2 {
			file := tmp[1]
			if len(file) != 0 {
				m, err := domain.NewDomainMatcherFormFile(file)
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

func (ps *DomainPolicies) Match(fqdn string) *Action {
	for i := range ps.policies {
		if ps.policies[i].matcher == nil { // a policy without a matcher is a default policy
			return ps.policies[i].action // return its action
		}

		if ps.policies[i].matcher != nil && ps.policies[i].matcher.Match(fqdn) {
			return ps.policies[i].action
		}
	}

	return nil
}
