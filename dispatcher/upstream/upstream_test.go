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

package upstream

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

var (
	dummyIP     = net.IPv4(1, 2, 3, 4)
	dummyServer = &vServer{ip: dummyIP, latency: 0}
)

func Test_udp_upstream(t *testing.T) {
	udpConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := udpConn.LocalAddr().String()
	rs := dns.Server{Net: "udp", PacketConn: udpConn, Handler: dummyServer}
	go rs.ActivateAndServe()
	defer rs.Shutdown()

	u := NewUDPUpstream(addr)
	if err := testUpstream(u); err != nil {
		t.Fatal(err)
	}
}
func Test_tcp_upstream(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	rs := dns.Server{Net: "udp", Listener: l, Handler: dummyServer}
	go rs.ActivateAndServe()
	defer rs.Shutdown()

	u := NewTCPUpstream(addr, "", time.Second)
	if err := testUpstream(u); err != nil {
		t.Fatal(err)
	}
}
func Test_dot_upstream(t *testing.T) {
	cert, err := generateCertificate()
	tlsConfig := new(tls.Config)
	tlsConfig.Certificates = []tls.Certificate{cert}
	tlsListener, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatal(err)
	}
	addr := tlsListener.Addr().String()
	rs := dns.Server{Net: "tcp-tls", Listener: tlsListener, TLSConfig: tlsConfig, Handler: dummyServer}
	go rs.ActivateAndServe()
	defer rs.Shutdown()

	u := NewDoTUpstream(addr, "", time.Second, &tls.Config{InsecureSkipVerify: true})
	if err := testUpstream(u); err != nil {
		t.Fatal(err)
	}
}

// TODO: add test for doh
//func Test_doh_upstream(t *testing.T) {
//
//}

func testUpstream(u Upstream) error {
	wg := sync.WaitGroup{}
	errs := make([]error, 0)
	errsLock := sync.Mutex{}
	logErr := func(err error) {
		errsLock.Lock()
		errs = append(errs, err)
		errsLock.Unlock()
	}
	errsToString := func() string {
		s := fmt.Sprintf("%d err(s) occured during the test: ", len(errs))
		for i := range errs {
			s = s + errs[i].Error() + "|"
		}
		return s
	}

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			q := new(dns.Msg)
			q.SetQuestion("example.com.", dns.TypeA)

			ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
			defer cancel()
			r, err := u.Exchange(ctx, q)
			if err != nil {
				logErr(err)
				return
			}
			if !r.Answer[0].(*dns.A).A.Equal(dummyIP) {
				logErr(errors.New("data corrupted"))
				return
			}
		}()
	}
	wg.Wait()
	if len(errs) != 0 {
		return errors.New(errsToString())
	}
	return nil
}

func generateCertificate() (cert tls.Certificate, err error) {
	//priv key
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return
	}

	//serial number
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		err = fmt.Errorf("generate serial number: %w", err)
		return
	}

	dnsName := "example.com"

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: dnsName},
		DNSNames:     []string{dnsName},

		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(10, 0, 0),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return
	}
	b, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	return tls.X509KeyPair(certPEM, keyPEM)
}

type vServer struct {
	latency    time.Duration
	shutdowned bool
	ip         net.IP
}

func (s *vServer) ServeDNS(w dns.ResponseWriter, q *dns.Msg) {
	if s.shutdowned {
		return
	}

	name := q.Question[0].Name
	r := new(dns.Msg)
	r.SetReply(q)
	var rr dns.RR
	hdr := dns.RR_Header{
		Name:     name,
		Class:    dns.ClassINET,
		Ttl:      300,
		Rdlength: 0,
	}

	hdr.Rrtype = dns.TypeA

	rr = &dns.A{Hdr: hdr, A: s.ip}
	r.Answer = append(r.Answer, rr)

	time.Sleep(s.latency)
	w.WriteMsg(r)
}
