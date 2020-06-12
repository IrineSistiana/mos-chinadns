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

import "encoding/binary"

func GetMsgID(m []byte) uint16 {
	return binary.BigEndian.Uint16(m)
}

func SetMsgID(id uint16, m []byte) {
	binary.BigEndian.PutUint16(m, id)
}

func ExchangeMsgID(newID uint16, m []byte) (oldID uint16) {
	oldID = GetMsgID(m)
	SetMsgID(newID, m)
	return
}
