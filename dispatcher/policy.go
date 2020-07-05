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
	"github.com/IrineSistiana/mos-chinadns/dispatcher/domainlist"
	netlist "github.com/IrineSistiana/net-list"
	"github.com/sirupsen/logrus"
	"strings"
)

type policyAction uint8

const (
	policyActionForceStr   string = "force"
	policyActionAcceptStr  string = "accept"
	policyActionDenyStr    string = "deny"
	policyActionDenyAllStr string = "deny_all"

	policyActionForce policyAction = iota
	policyActionAccept
	policyActionDeny
	policyActionDenyAll
	policyActionMissing
)

var convIPPolicyActionStr = map[string]policyAction{
	policyActionAcceptStr:  policyActionAccept,
	policyActionDenyStr:    policyActionDeny,
	policyActionDenyAllStr: policyActionDenyAll,
}

var convDomainPolicyActionStr = map[string]policyAction{
	policyActionForceStr:   policyActionForce,
	policyActionAcceptStr:  policyActionAccept,
	policyActionDenyStr:    policyActionDeny,
	policyActionDenyAllStr: policyActionDenyAll,
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

func convPoliciesStr(s string, f map[string]policyAction) ([]rawPolicy, error) {
	ps := make([]rawPolicy, 0)

	policiesStr := strings.Split(s, "|")
	for i := range policiesStr {
		pStr := strings.SplitN(policiesStr[i], ":", 2)

		p := rawPolicy{}
		action, ok := f[pStr[0]]
		if !ok {
			return nil, fmt.Errorf("unknown action [%s]", pStr[0])
		}
		p.action = action

		if len(pStr) == 2 {
			p.args = pStr[1]
		}

		ps = append(ps, p)
	}

	return ps, nil
}

func newIPPolicies(psString string, entry *logrus.Entry) (*ipPolicies, error) {
	psArgs, err := convPoliciesStr(psString, convIPPolicyActionStr)
	if err != nil {
		return nil, fmt.Errorf("invalid ip policies string, %w", err)
	}
	ps := &ipPolicies{
		policies: make([]ipPolicy, 0),
	}

	for i := range psArgs {
		p := ipPolicy{}
		p.action = psArgs[i].action

		file := psArgs[i].args
		if len(file) != 0 {
			list, err := netlist.NewListFromFile(file)
			if err != nil {
				return nil, fmt.Errorf("failed to load ip file from %s, %w", file, err)
			}
			p.list = list
			entry.Infof("newIPPolicies: ip list %s loaded, length %d", file, list.Len())
		}

		ps.policies = append(ps.policies, p)
	}

	return ps, nil
}

// ps can not be nil
func (ps *ipPolicies) check(ip netlist.IPv6) policyAction {
	for p := range ps.policies {
		if ps.policies[p].action == policyActionDenyAll {
			return policyActionDeny
		}

		if ps.policies[p].list != nil && ps.policies[p].list.Contains(ip) {
			return ps.policies[p].action
		}
	}

	return policyActionMissing
}

func newDomainPolicies(psString string, entry *logrus.Entry) (*domainPolicies, error) {
	psArgs, err := convPoliciesStr(psString, convDomainPolicyActionStr)
	if err != nil {
		return nil, fmt.Errorf("invalid domain policies string, %w", err)
	}
	ps := &domainPolicies{
		policies: make([]domainPolicy, 0),
	}

	for i := range psArgs {
		p := domainPolicy{}
		p.action = psArgs[i].action

		file := psArgs[i].args
		if len(file) != 0 {
			list, err := domainlist.LoadFormFile(file)
			if err != nil {
				return nil, fmt.Errorf("failed to load domain file from %s, %w", file, err)
			}
			p.list = list
			entry.Infof("newDomainPolicies: domain list %s loaded, length %d", file, list.Len())
		}

		ps.policies = append(ps.policies, p)
	}

	return ps, nil
}

// check: ps can not be nil
func (ps *domainPolicies) check(fqdn string) policyAction {
	for p := range ps.policies {
		if ps.policies[p].action == policyActionDenyAll {
			return policyActionDeny
		}

		if ps.policies[p].list != nil && ps.policies[p].list.Has(fqdn) {
			return ps.policies[p].action
		}
	}

	return policyActionMissing
}
