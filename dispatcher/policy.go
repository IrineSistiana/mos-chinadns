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
	"strings"
	"sync"

	"github.com/IrineSistiana/mos-chinadns/dispatcher/domainlist"
	"github.com/IrineSistiana/mos-chinadns/dispatcher/netlist"
	"github.com/sirupsen/logrus"
)

type policyAction uint8
type policyFinalAction uint8

const (
	policyActionAcceptStr  string = "accept"
	policyActionDenyStr    string = "deny"
	policyActionDenyAllStr string = "deny_all"

	policyActionAccept policyAction = iota
	policyActionDeny
	policyActionDenyAll

	policyFinalActionAccept policyFinalAction = iota
	policyFinalActionDeny
	policyFinalActionOnHold
)

func (pa policyAction) ToPFA() policyFinalAction {
	switch pa {
	case policyActionAccept:
		return policyFinalActionAccept
	case policyActionDeny, policyActionDenyAll:
		return policyFinalActionDeny
	default:
		panic("unknown policyAction")
	}
}

var convPolicyStringToAction = map[string]policyAction{
	policyActionAcceptStr:  policyActionAccept,
	policyActionDenyStr:    policyActionDeny,
	policyActionDenyAllStr: policyActionDenyAll,
}

type rawPolicies struct {
	policies []rawPolicy
}

type rawPolicy struct {
	action policyAction
	args   string
}

type ipPolicies struct {
	policies []ipPolicy
}

type ipPolicy struct {
	action policyAction
	list   *netlist.List
}

type domainPolicies struct {
	policies []domainPolicy
}

type domainPolicy struct {
	action policyAction
	list   *domainlist.List
}

func convPoliciesStr(s string) (*rawPolicies, error) {
	rps := new(rawPolicies)
	rps.policies = make([]rawPolicy, 0)

	policiesStr := strings.Split(s, "|")
	for i := range policiesStr {
		pStr := strings.SplitN(policiesStr[i], ":", 2)

		p := rawPolicy{}
		action, ok := convPolicyStringToAction[pStr[0]]
		if !ok {
			return nil, fmt.Errorf("unknown action [%s]", pStr[0])
		}
		p.action = action

		if len(pStr) == 2 {
			p.args = pStr[1]
		} else {
			p.args = ""
		}

		rps.policies = append(rps.policies, p)
	}

	return rps, nil
}

func newIPPolicies(s string) (*ipPolicies, error) {
	rps, err := convPoliciesStr(s)
	if err != nil {
		return nil, fmt.Errorf("invalid ip policies string, %w", err)
	}
	ps := &ipPolicies{
		policies: make([]ipPolicy, 0),
	}

	for i := range rps.policies {
		p := ipPolicy{}
		p.action = rps.policies[i].action

		file := rps.policies[i].args
		if len(file) != 0 {
			list, err := loadIPPolicy(file)
			if err != nil {
				return nil, fmt.Errorf("failed to load ip file from %s, %w", file, err)
			}
			p.list = list
		}

		ps.policies = append(ps.policies, p)
	}

	return ps, nil
}

func (ps *ipPolicies) check(ip netlist.IPv6) policyFinalAction {
	for p := range ps.policies {
		if ps.policies[p].action == policyActionDenyAll {
			return policyFinalActionDeny
		}

		if ps.policies[p].list != nil && ps.policies[p].list.Contains(ip) {
			return ps.policies[p].action.ToPFA()
		}
	}

	return policyFinalActionOnHold
}

func newDomainPolicies(s string) (*domainPolicies, error) {
	rps, err := convPoliciesStr(s)
	if err != nil {
		return nil, fmt.Errorf("invalid domain policies string, %w", err)
	}
	ps := &domainPolicies{
		policies: make([]domainPolicy, 0),
	}

	for i := range rps.policies {
		p := domainPolicy{}
		p.action = rps.policies[i].action

		file := rps.policies[i].args
		if len(file) != 0 {
			list, err := loadDomainPolicy(file)
			if err != nil {
				return nil, fmt.Errorf("failed to load domain file from %s, %w", file, err)
			}
			p.list = list
		}

		ps.policies = append(ps.policies, p)
	}

	return ps, nil
}

func (ps *domainPolicies) check(fqdn string) policyFinalAction {
	for p := range ps.policies {
		if ps.policies[p].action == policyActionDenyAll {
			return policyFinalActionDeny
		}

		if ps.policies[p].list != nil && ps.policies[p].list.Has(fqdn) {
			return ps.policies[p].action.ToPFA()
		}
	}

	return policyFinalActionOnHold
}

type policyCache struct {
	l     sync.Mutex
	cache map[string]interface{}
}

var globePolicyCache = policyCache{cache: make(map[string]interface{})}

func loadDomainPolicy(f string) (*domainlist.List, error) {
	globePolicyCache.l.Lock()
	defer globePolicyCache.l.Unlock()

	if e, ok := globePolicyCache.cache[f]; ok { // cache hit
		if list, ok := e.(*domainlist.List); ok {
			return list, nil // load from cache
		} else {
			return nil, fmt.Errorf("%s is loaded but not a domain list", f)
		}
	}

	// load from file
	list, err := domainlist.LoadFormFile(f, true)
	if err != nil {
		return nil, err
	}

	logrus.Infof("loadDomainPolicy: domain list %s loaded, length %d", f, list.Len())
	globePolicyCache.cache[f] = list // cache the list
	return list, nil
}

func loadIPPolicy(f string) (*netlist.List, error) {
	globePolicyCache.l.Lock()
	defer globePolicyCache.l.Unlock()

	if e, ok := globePolicyCache.cache[f]; ok { // cache hit
		if list, ok := e.(*netlist.List); ok {
			return list, nil // load from cache
		} else {
			return nil, fmt.Errorf("%s is loaded but not a ip list", f)
		}
	}

	// load from file
	list, err := netlist.NewListFromFile(f, true)
	if err != nil {
		return nil, err
	}

	logrus.Infof("loadIPPolicy: ip list %s loaded, length %d", f, list.Len())
	globePolicyCache.cache[f] = list // cache the list
	return list, nil
}
