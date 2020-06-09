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

package main

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"

	"github.com/miekg/dns"
)

func Test_readMsgFromUDP(t *testing.T) {
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)

	rawData, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	getData := func() []byte {
		b := make([]byte, 0)
		b = append(b, rawData...)
		return b
	}

	type args struct {
		c io.Reader
	}
	tests := []struct {
		name               string
		args               args
		wantM              []byte
		wantBrokenDataLeft int
		wantN              int
		wantErr            bool
	}{
		{"normal", args{bytes.NewBuffer(getData())}, rawData, 0, len(rawData), false},
		{"header short read", args{bytes.NewBuffer(getData()[:11])}, nil, 0, 11, true},
		{"msg short read", args{bytes.NewBuffer(getData()[:13])}, nil, 0, 13, false},
		{"no data", args{bytes.NewBuffer(nil)}, nil, 0, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotM, gotBrokenDataLeft, gotN, err := readMsgFromUDP(tt.args.c)
			if (err != nil) != tt.wantErr {
				t.Errorf("readMsgFromUDP() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotM != nil && tt.wantM != nil && !bytes.Equal(gotM.B, tt.wantM) {
				t.Errorf("readMsgFromUDP() gotM = %v, want %v", gotM, tt.wantM)
			}
			if gotBrokenDataLeft != tt.wantBrokenDataLeft {
				t.Errorf("readMsgFromUDP() gotBrokenDataLeft = %v, want %v", gotBrokenDataLeft, tt.wantBrokenDataLeft)
			}
			if gotN != tt.wantN {
				t.Errorf("readMsgFromUDP() gotN = %v, want %v", gotN, tt.wantN)
			}
		})
	}
}

func Test_readMsgFromTCP(t *testing.T) {
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)

	rawData, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	getData := func() []byte {
		b := make([]byte, 2)
		binary.BigEndian.PutUint16(b, uint16(len(rawData)))
		b = append(b, rawData...)
		return b
	}

	type args struct {
		c io.Reader
	}
	tests := []struct {
		name               string
		args               args
		wantMRaw           []byte
		wantBrokenDataLeft int
		wantN              int
		wantErr            bool
	}{
		{"normal", args{bytes.NewBuffer(getData())}, rawData, 0, len(rawData) + 2, false},
		{"header short read", args{bytes.NewBuffer(getData()[:11])}, nil, len(rawData) - 9, 11, true},
		{"msg short read", args{bytes.NewBuffer(getData()[:13])}, nil, len(rawData) - 11, 13, true},
		{"no data", args{bytes.NewBuffer(nil)}, nil, 0, 0, true},
		{"invalid length", args{bytes.NewBuffer([]byte{0, 1, 0})}, nil, unknownBrokenDataSize, 2, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotMRaw, gotBrokenDataLeft, gotN, err := readMsgFromTCP(tt.args.c)
			if (err != nil) != tt.wantErr {
				t.Errorf("readMsgFromTCP() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotMRaw != nil && tt.wantMRaw != nil && !bytes.Equal(gotMRaw.B, tt.wantMRaw) {
				t.Errorf("readMsgFromTCP() gotMRaw = %v, want %v", gotMRaw, tt.wantMRaw)
			}
			if gotBrokenDataLeft != tt.wantBrokenDataLeft {
				t.Errorf("readMsgFromTCP() gotBrokenDataLeft = %v, want %v", gotBrokenDataLeft, tt.wantBrokenDataLeft)
			}
			if gotN != tt.wantN {
				t.Errorf("readMsgFromTCP() gotN = %v, want %v", gotN, tt.wantN)
			}
		})
	}
}
