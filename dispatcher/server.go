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
	"fmt"
	"github.com/IrineSistiana/mos-chinadns/dispatcher/logger"
	"github.com/IrineSistiana/mos-chinadns/dispatcher/server"
	"net"
	"strings"
)

// StartServer starts mos-chinadns. Will always return a non-nil err.
func (d *Dispatcher) StartServer() error {

	if len(d.config.Dispatcher.Bind) == 0 {
		return fmt.Errorf("no address to bind")
	}

	errChan := make(chan error, 1) // must be a buffered chan to catch at least one err.

	for _, s := range d.config.Dispatcher.Bind {
		ss := strings.Split(s, "://")
		if len(ss) != 2 {
			return fmt.Errorf("invalid bind address: %s", s)
		}
		network := ss[0]
		addr := ss[1]

		var s server.Server
		switch network {
		case "tcp", "tcp4", "tcp6":
			l, err := net.Listen(network, addr)
			if err != nil {
				return err
			}
			defer l.Close()
			logger.GetStd().Infof("StartServer: tcp server started at %s", l.Addr())

			s = server.NewTCPServer(l, d)

		case "udp", "udp4", "udp6":
			l, err := net.ListenPacket(network, addr)
			if err != nil {
				return err
			}
			defer l.Close()
			logger.GetStd().Infof("StartServer: udp server started at %s", l.LocalAddr())

			s = server.NewUDPServer(l, d, d.config.Dispatcher.MaxUDPSize)
		default:
			return fmt.Errorf("invalid bind protocol: %s", network)
		}

		go func() {
			err := s.ListenAndServe()
			select {
			case errChan <- err:
			default:
			}
		}()
	}

	listenerErr := <-errChan

	return fmt.Errorf("server listener failed and exited: %w", listenerErr)
}
