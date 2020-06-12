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

import "testing"

func Test_bucket_aquire(t *testing.T) {
	maxSize := 150
	bk := newBucket(maxSize)

	// aquire & release
	for i := 1; i <= maxSize; i++ {
		if bk.aquire() != true {
			t.Fatal("failed to aquire token from bucket")
		}
	}
	if bk.aquire() != false {
		t.Fatal("get a token from an empty bucket")
	}

	for i := 1; i <= maxSize; i++ {
		bk.release()
	}
	if bk.i != 0 {
		t.Fatal("bucket isn't full after all tokens are released")
	}
}
