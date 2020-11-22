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
	"errors"
	"fmt"
	"github.com/IrineSistiana/mos-chinadns/dispatcher/upstream"
	"strings"
)

type ActionMode uint8

const (
	PolicyActionAcceptStr      string = "accept"
	PolicyActionDenyStr        string = "deny"
	PolicyActionRedirectPrefix string = "Redirect"

	PolicyActionAccept ActionMode = iota
	PolicyActionDeny
	PolicyActionRedirect
)

var ActionModeToStr = map[ActionMode]string{
	PolicyActionAccept:   PolicyActionAcceptStr,
	PolicyActionDeny:     PolicyActionDenyStr,
	PolicyActionRedirect: PolicyActionRedirectPrefix,
}

func (m ActionMode) String() string {
	s, ok := ActionModeToStr[m]
	if ok {
		return s
	}
	return fmt.Sprintf("unknown action Mode %d", m)
}

type Action struct {
	Mode     ActionMode
	Redirect upstream.Upstream
}

// NewAction accepts PolicyActionAcceptStr, PolicyActionDenyStr
// and string with prefix policyActionRedirectStr.
func NewAction(s string, servers map[string]upstream.Upstream) (*Action, error) {
	var mode ActionMode
	var redirect upstream.Upstream
	var ok bool
	switch {
	case s == PolicyActionAcceptStr:
		mode = PolicyActionAccept
	case s == PolicyActionDenyStr:
		mode = PolicyActionDeny
	case strings.HasPrefix(s, PolicyActionRedirectPrefix):
		if servers == nil {
			return nil, errors.New("redirect is not allowed")
		}

		mode = PolicyActionRedirect
		serverTag := strings.TrimLeft(s, PolicyActionRedirectPrefix+"_")
		redirect, ok = servers[serverTag]
		if !ok {
			return nil, fmt.Errorf("unable to Redirect, can not find server with tag [%s]", serverTag)
		}
	default:
		return nil, fmt.Errorf("invalid action [%s]", s)
	}

	return &Action{Mode: mode, Redirect: redirect}, nil
}
