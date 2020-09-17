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
	"github.com/IrineSistiana/mos-chinadns/dispatcher/upstream"
	"strings"
	"sync"

	"github.com/IrineSistiana/mos-chinadns/dispatcher/domainlist"
	"github.com/IrineSistiana/mos-chinadns/dispatcher/netlist"
	"github.com/sirupsen/logrus"
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
func (d *Dispatcher) newAction(s string) (*action, error) {
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
		redirect, ok = d.servers[serverTag]
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
	list   *netlist.List
	action *action
}

type domainPolicies struct {
	policies      []*domainPolicy
	defaultAction *action
}

type domainPolicy struct {
	list   *domainlist.List
	action *action
}

func (d *Dispatcher) newIPPolicies(s string) (*ipPolicies, error) {
	ipps := new(ipPolicies)
	ipps.policies = make([]*ipPolicy, 0)

	ss := strings.Split(s, "|")
	for i := range ss {
		ipp := new(ipPolicy)

		tmp := strings.SplitN(ss[i], ":", 2)

		actionStr := tmp[0]
		action, err := d.newAction(actionStr)
		if err != nil {
			return nil, fmt.Errorf("invalid ip policy at index %d: %v", i, err)
		}
		ipp.action = action

		if len(tmp) == 2 {
			file := tmp[1]
			if len(file) != 0 {
				list, err := loadIPPolicy(file)
				if err != nil {
					return nil, fmt.Errorf("failed to load ip file from %s, %w", file, err)
				}
				ipp.list = list
			}
		}

		ipps.policies = append(ipps.policies, ipp)
	}

	return ipps, nil
}

func (ps *ipPolicies) check(ip netlist.IPv6) *action {
	for i := range ps.policies {
		if ps.policies[i].list == nil { // nil list means match-all
			return ps.policies[i].action
		}

		if ps.policies[i].list.Contains(ip) {
			return ps.policies[i].action
		}
	}

	return nil
}

func (d *Dispatcher) newDomainPolicies(s string, allowRedirect bool) (*domainPolicies, error) {
	dps := new(domainPolicies)
	dps.policies = make([]*domainPolicy, 0)

	ss := strings.Split(s, "|")
	for i := range ss {
		dp := new(domainPolicy)

		tmp := strings.SplitN(ss[i], ":", 2)

		actionStr := tmp[0]
		action, err := d.newAction(actionStr)
		if err != nil {
			return nil, fmt.Errorf("invalid domain policy at index %d: %v", i, err)
		}
		if !allowRedirect && action.mode == policyActionRedirect {
			return nil, fmt.Errorf("invalid domain policy at index %d: redirect mode is not allowed here", i)
		}

		dp.action = action

		if len(tmp) == 2 {
			file := tmp[1]
			if len(file) != 0 {
				list, err := loadDomainPolicy(file)
				if err != nil {
					return nil, fmt.Errorf("failed to load domain file from %s, %w", file, err)
				}
				dp.list = list
			}
		}

		dps.policies = append(dps.policies, dp)
	}

	return dps, nil
}

func (ps *domainPolicies) check(fqdn string) *action {
	for i := range ps.policies {
		if ps.policies[i].list == nil {
			return ps.policies[i].action
		}

		if ps.policies[i].list != nil && ps.policies[i].list.Has(fqdn) {
			return ps.policies[i].action
		}
	}

	return nil
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
	list, err := domainlist.NewListFormFile(f, true)
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
