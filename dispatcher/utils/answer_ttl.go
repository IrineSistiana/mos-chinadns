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

package utils

import "github.com/miekg/dns"

func SetAnswerTTL(m *dns.Msg, ttl uint32) {
	for i := range m.Answer {
		m.Answer[i].Header().Ttl = ttl
	}
}

func GetAnswerMinTTL(m *dns.Msg) uint32 {
	var minTTL uint32 = ^uint32(0)
	for i := range m.Answer {
		ttl := m.Answer[i].Header().Ttl
		if ttl < minTTL {
			minTTL = ttl
		}
	}
	return minTTL
}
