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

package domainlist

import (
	"testing"
)

func Test_DomainList(t *testing.T) {
	l := New()
	l.Add("cn.")
	l.Add("a.com.")
	l.Add("b.com.")
	l.Add("abc.com.")
	l.Add("123456789012345678901234567890.com.")

	assertTrue(l.Has("a.cn."))
	assertTrue(l.Has("a.b.cn."))

	assertTrue(l.Has("a.com."))
	assertTrue(l.Has("b.com."))
	assertTrue(!l.Has("c.com."))
	assertTrue(!l.Has("a.c.com."))
	assertTrue(l.Has("123456789012345678901234567890.com."))

	assertTrue(l.Has("abc.abc.com."))
}

func assertTrue(b bool) {
	if !b {
		panic("assert failed")
	}
}
