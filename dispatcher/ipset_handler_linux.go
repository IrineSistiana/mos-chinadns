// +build linux

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
	"github.com/IrineSistiana/mos-chinadns/dispatcher/config"
	"github.com/IrineSistiana/mos-chinadns/dispatcher/ipset"
	"github.com/IrineSistiana/mos-chinadns/dispatcher/logger"
	"github.com/miekg/dns"
	"net"
)

func newIPSetHandler(c *config.Config) (*ipsetHandler, error) {
	h := new(ipsetHandler)
	h.checkCAME = c.IPSet.CheckCNAME
	h.mask4 = c.IPSet.Mask4
	h.mask6 = c.IPSet.Mask6

	// default
	if h.mask4 == 0 {
		h.mask4 = 24
	}
	if h.mask6 == 0 {
		h.mask6 = 32
	}

	for _, ipsetConfig := range c.IPSet.Rule {
		if len(ipsetConfig.SetName4) == 0 && len(ipsetConfig.SetName6) == 0 {
			continue
		}

		dps, err := newDomainPolicies(ipsetConfig.Domain, nil, false)
		if err != nil {
			return nil, fmt.Errorf("failed to init ipset domain policies %s: %w", ipsetConfig.Domain, err)
		}
		rule := &ipsetRule{
			setName4:       ipsetConfig.SetName4,
			setName6:       ipsetConfig.SetName6,
			domainPolicies: dps,
		}

		h.rules = append(h.rules, rule)
	}
	return h, nil
}

func (h *ipsetHandler) applyIPSet(q, r *dns.Msg) error {
	for _, rule := range h.rules {
		domainMatched := false

		for i := range q.Question { // match question first
			if action := rule.domainPolicies.check(q.Question[i].Name); action != nil && action.mode == policyActionAccept {
				domainMatched = true
				break
			}
		}
		if !domainMatched && h.checkCAME { // match cname
			for i := range r.Answer {
				if cname, ok := r.Answer[i].(*dns.CNAME); ok {
					if action := rule.domainPolicies.check(cname.Target); action != nil && action.mode == policyActionAccept {
						domainMatched = true
						break
					}
				}
			}
		}

		if domainMatched {
			for i := range r.Answer {
				var ip net.IP
				var setName string
				var mask uint8
				var isNET6 bool

				switch rr := r.Answer[i].(type) {
				case *dns.A:
					ip = rr.A
					setName = rule.setName4
					mask = h.mask4
					isNET6 = false
				case *dns.AAAA:
					ip = rr.AAAA
					setName = rule.setName6
					mask = h.mask6
					isNET6 = true
				default:
					continue
				}

				if len(setName) == 0 {
					continue
				}

				logger.GetStd().Debugf("applyIPSet: [%v %d]: add %s/%d to set %s", q.Question, q.Id, ip, mask, setName)
				err := ipset.AddCIDR(setName, ip, mask, isNET6)
				if err != nil {
					return fmt.Errorf("failed to add ip %s to set %s: %w", ip, setName, err)
				}
			}
		}
	}

	return nil
}
