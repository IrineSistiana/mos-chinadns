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

package matcher

import (
	"bytes"
	"fmt"
	"github.com/IrineSistiana/mos-chinadns/dispatcher/matcher/netlist"
	"github.com/golang/protobuf/proto"
	"strings"
	"v2ray.com/core/app/router"
)

// NewIPMatcherFromFile loads a netlist file a list or geoip file.
// if file contains a ':' and has format like 'geoip:cn', file must be a geoip file.
func NewIPMatcherFromFile(file string) (netlist.Matcher, error) {
	e, ok := loadFromCache(file)
	if ok {
		if m, ok := e.(netlist.Matcher); ok {
			return m, nil
		}
	}

	var m netlist.Matcher
	var err error
	if strings.Contains(file, ":") {
		tmp := strings.SplitN(file, ":", 2)
		m, err = NewNetListFromDAT(tmp[0], tmp[1]) // file and tag
	} else {
		m, err = NewListFromListFile(file, true)
	}

	if err != nil {
		return nil, err
	}

	cacheData(file, m)
	return m, nil
}

// NewListFromFile read IP list from a file, the returned NetList is already been sorted.
func NewListFromListFile(file string, continueOnInvalidString bool) (netlist.Matcher, error) {
	data, raw, err := loadFromCacheOrRawDisk(file)
	if err != nil {
		return nil, err
	}

	// load from cache
	if nl, ok := data.(*netlist.List); ok {
		return nl, nil
	}
	// load from disk
	return netlist.NewListFromReader(bytes.NewBuffer(raw), continueOnInvalidString)
}

func NewNetListFromDAT(file, tag string) (netlist.Matcher, error) {
	cidrList, err := loadV2CIDRListFromDAT(file, tag)
	if err != nil {
		return nil, err
	}

	return netlist.NewV2Matcher(cidrList)
}

func loadV2CIDRListFromDAT(file, tag string) ([]*router.CIDR, error) {
	geoIP, err := loadGeoIPFromDAT(file, tag)
	if err != nil {
		return nil, err
	}
	return geoIP.GetCidr(), nil
}

func loadGeoIPFromDAT(file, tag string) (*router.GeoIP, error) {
	geoIPList, err := loadGeoIPListFromDAT(file)
	if err != nil {
		return nil, err
	}

	entry := geoIPList.GetEntry()
	for i := range entry {
		if strings.ToUpper(entry[i].CountryCode) == strings.ToUpper(tag) {
			return entry[i], nil
		}
	}

	return nil, fmt.Errorf("can not find tag %s in %s", tag, file)
}

func loadGeoIPListFromDAT(file string) (*router.GeoIPList, error) {
	data, raw, err := loadFromCacheOrRawDisk(file)
	if err != nil {
		return nil, err
	}
	// load from cache
	if geoIPList, ok := data.(*router.GeoIPList); ok {
		return geoIPList, nil
	}

	// load from disk
	geoIPList := new(router.GeoIPList)
	if err := proto.Unmarshal(raw, geoIPList); err != nil {
		return nil, err
	}

	// cache the file
	cacheData(file, geoIPList)
	return geoIPList, nil
}
