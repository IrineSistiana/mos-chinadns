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

package netlist

import (
	"bufio"
	"fmt"
	"github.com/IrineSistiana/mos-chinadns/dispatcher/logger"
	"io"
	"os"
	"strings"
)

//NewListFromFile read IP list from a file, if no valid IP addr was found,
//it will return a empty NetList, NOT nil. NetList will be a sorted list.
func NewListFromFile(file string, continueOnInvalidString bool) (*List, error) {

	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return NewListFromReader(f, continueOnInvalidString)
}

//NewListFromReader read IP list from a reader, if no valid IP addr was found,
//it will return a empty NetList, NOT nil. NetList will be a sorted list.
func NewListFromReader(reader io.Reader, continueOnInvalidString bool) (*List, error) {

	ipNetList := NewNetList()
	s := bufio.NewScanner(reader)

	//count how many lines we have read.
	lineCounter := 0

	for s.Scan() {
		lineCounter++
		line := strings.TrimSpace(s.Text())

		//ignore lines begin with # and empty lines
		if len(line) == 0 || strings.HasPrefix(line, "#") {
			continue
		}

		ipNet, err := ParseCIDR(line)
		if err != nil {
			if continueOnInvalidString {
				logger.GetStd().Warnf("NewListFromReader: invalid CIDR format %s in line %d", line, lineCounter)
				continue
			} else {
				return nil, fmt.Errorf("invalid CIDR format %s in line %d", line, lineCounter)
			}
		}

		ipNetList.Append(ipNet)
	}

	ipNetList.Sort()
	return ipNetList, nil
}
