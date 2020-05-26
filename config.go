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
	"io/ioutil"
	"os"

	"gopkg.in/yaml.v3"
)

// Config is config
type Config struct {
	Bind struct {
		Addr     string `yaml:"addr"`
		Protocol string `yaml:"protocol"`
	} `yaml:"bind"`

	Dispatcher struct {
		MaxConcurrentQueries int `yaml:"max_concurrent_queries"`
	} `yaml:"dispatcher"`

	Server struct {
		Local struct {
			BasicServerConfig `yaml:"basic,inline"`

			DenyUnusualTypes     bool `yaml:"deny_unusual_types"`
			DenyResultsWithoutIP bool `yaml:"deny_results_without_ip"`
			CheckCNAME           bool `yaml:"check_cname"`

			IPPolicies     string `yaml:"ip_policies"`
			DomainPolicies string `yaml:"domain_policies"`
		} `yaml:"local"`

		Remote struct {
			BasicServerConfig `yaml:"basic,inline"`
			DelayStart        int `yaml:"delay_start"`
		} `yaml:"remote"`
	} `yaml:"server"`

	ECS struct {
		Local  string `yaml:"local"`
		Remote string `yaml:"remote"`
	} `yaml:"ecs"`

	CA struct {
		Path string `yaml:"path"`
	} `yaml:"ca"`
}

type BasicServerConfig struct {
	Addr     string `yaml:"addr"`
	Protocol string `yaml:"protocol"`
	DoH      struct {
		URL      string `yaml:"url"`
		FastHTTP bool   `yaml:"fasthttp"`
	} `yaml:"doh"`

	DoT struct {
		ServerName  string `yaml:"server_name"`
		IdleTimeout uint   `yaml:"idle_timeout"`
	} `yaml:"dot"`
}

func loadConfig(configFile string) (*Config, error) {
	c := new(Config)
	b, err := ioutil.ReadFile(configFile)
	if err != nil {
		return nil, err
	}

	if err := yaml.Unmarshal(b, c); err != nil {
		return nil, err
	}

	return c, nil
}

func genConfig(configFile string) error {
	c := new(Config)

	f, err := os.Create(configFile)
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
