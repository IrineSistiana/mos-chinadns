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
	"gopkg.in/yaml.v3"
	"io/ioutil"
	"os"
)

// Config is config
type Config struct {
	Dispatcher struct {
		Bind  []string `yaml:"bind"`
		Cache struct {
			Size int `yaml:"size"`
		} `yaml:"cache"`
		MinTTL uint32 `yaml:"min_ttl"`
	} `yaml:"dispatcher"`

	Upstream map[string]*BasicServerConfig `yaml:"upstream"`

	CA struct {
		Path []string `yaml:"path"`
	} `yaml:"ca"`
}

// BasicServerConfig is a basic config for a upstream dns server.
type BasicServerConfig struct {
	Addr     string `yaml:"addr"`
	Protocol string `yaml:"protocol"`
	Socks5   string `yaml:"socks5"`

	TCP struct {
		IdleTimeout uint `yaml:"idle_timeout"`
	} `yaml:"tcp"`

	DoT struct {
		ServerName  string `yaml:"server_name"`
		IdleTimeout uint   `yaml:"idle_timeout"`
	} `yaml:"dot"`

	DoH struct {
		URL string `yaml:"url"`
	} `yaml:"doh"`

	// for test and experts only, we add `omitempty`
	InsecureSkipVerify bool `yaml:"insecure_skip_verify,omitempty"`

	Deduplicate          bool `yaml:"deduplicate"`
	MaxConcurrentQueries int  `yaml:"max_concurrent_queries"`

	EDNS0 struct {
		ClientSubnet string `yaml:"client_subnet"`
		OverwriteECS bool   `yaml:"overwrite_ecs"`
	} `yaml:"edns0"`
	Policies struct {
		Domain     string `yaml:"domain"`
		IP         string `yaml:"ip"`
		CheckCNAME bool   `yaml:"check_cname"`

		DenyErrorRcode       bool `yaml:"deny_error_rcode"`
		DenyUnhandlableTypes bool `yaml:"deny_unhandlable_types"`
		DenyEmptyIPReply     bool `yaml:"deny_empty_ip_reply"`
	}
}

// LoadConfig loads a yaml config from path p.
func LoadConfig(p string) (*Config, error) {
	c := new(Config)
	b, err := ioutil.ReadFile(p)
	if err != nil {
		return nil, err
	}

	if err := yaml.Unmarshal(b, c); err != nil {
		return nil, err
	}

	return c, nil
}

// GenConfig generates a template config to path p.
func GenConfig(p string) error {
	c := new(Config)
	c.Upstream = make(map[string]*BasicServerConfig)
	c.Upstream["local"] = new(BasicServerConfig)
	c.Upstream["remote"] = new(BasicServerConfig)

	f, err := os.Create(p)
	if err != nil {
		return err
	}
	defer f.Close()

	b, err := yaml.Marshal(c)
	if err != nil {
		return err
	}

	_, err = f.Write(b)

	return err
}
