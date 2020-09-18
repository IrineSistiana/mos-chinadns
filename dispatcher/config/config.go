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

package config

import (
	"gopkg.in/yaml.v3"
	"io/ioutil"
	"os"
)

// Config is config
type Config struct {
	Dispatcher struct {
		Bind       []string `yaml:"bind"`
		MaxUDPSize int      `yaml:"max_udp_size"`
	} `yaml:"dispatcher"`

	Upstream map[string]*UpstreamEntryConfig `yaml:"upstream"`
	Server   map[string]*BasicUpstreamConfig `yaml:"server"`

	CA struct {
		Path []string `yaml:"path"`
	} `yaml:"ca"`
}

// UpstreamEntryConfig is a dns upstream.
type UpstreamEntryConfig struct {
	ServerTag string `yaml:"server"`
	Policies  struct {
		Query struct {
			UnhandlableTypes string `yaml:"unhandlable_types"`
			Domain           string `yaml:"domain"`
		} `yaml:"query"`
		Reply struct {
			ErrorRcode string `yaml:"error_rcode"`
			CNAME      string `yaml:"cname"`
			WithoutIP  string `yaml:"without_ip"`
			IP         string `yaml:"ip"`
		} `yaml:"reply"`
	} `yaml:"policies"`
}

// BasicUpstreamConfig is a basic config for a dns upstream.
type BasicUpstreamConfig struct {
	Addr        string `yaml:"addr"`
	Protocol    string `yaml:"protocol"`
	Socks5      string `yaml:"socks5"`
	Deduplicate bool   `yaml:"deduplicate"`

	EDNS0 struct {
		ClientSubnet string `yaml:"client_subnet"`
		OverwriteECS bool   `yaml:"overwrite_ecs"`
	} `yaml:"edns0"`

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
	c.Upstream = make(map[string]*UpstreamEntryConfig)
	c.Upstream["upstream1"] = new(UpstreamEntryConfig)
	c.Upstream["upstream2"] = new(UpstreamEntryConfig)

	c.Server = make(map[string]*BasicUpstreamConfig)
	c.Server["server1"] = new(BasicUpstreamConfig)
	c.Server["server2"] = new(BasicUpstreamConfig)
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
