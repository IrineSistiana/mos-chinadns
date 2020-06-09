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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/IrineSistiana/mos-chinadns/bufpool"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

func Test_upstream(t *testing.T) {

	testUpstream := func(name string, u upstream) {
		wg := sync.WaitGroup{}
		errs := make([]error, 0)
		errsLock := sync.Mutex{}
		logErr := func(err error) {
			errsLock.Lock()
			errs = append(errs, err)
			errsLock.Unlock()
		}
		errsToString := func() string {
			s := fmt.Sprintf("%s has %d err: ", name, len(errs))
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
				qRaw, err := q.Pack()
				if err != nil {
					logErr(err)
					return
				}
				ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
				defer cancel()
				rRaw, err := u.Exchange(ctx, qRaw, logrus.NewEntry(logrus.StandardLogger()))
				if err != nil {
					logErr(err)
					return
				}
				defer bufpool.ReleaseMsgBuf(rRaw)
				r := new(dns.Msg)
				err = r.Unpack(rRaw.B)
				if err != nil {
					logErr(err)
					return
				}
			}()
		}
		wg.Wait()
		if len(errs) != 0 {
			t.Fatal(errsToString())
		}
	}

	testUpstreamTimeout := func(name string, u upstream) {
		q := new(dns.Msg)
		q.SetQuestion("example.com.", dns.TypeA)
		qRaw, err := q.Pack()
		if err != nil {
			t.Fatal(err)
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*50)
		defer cancel()
		rRaw, err := u.Exchange(ctx, qRaw, logrus.NewEntry(logrus.StandardLogger()))
		if err != nil {
			return
		}
		t.Fatalf("%s: err here, got %v", name, rRaw)
	}

	testServer := &vServer{ip: net.IPv4(1, 2, 3, 4), latency: 0}

	// test udp
	func() {
		udpConn, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := udpConn.LocalAddr().String()
		rs := dns.Server{Net: "udp", PacketConn: udpConn, Handler: testServer}
		go rs.ActivateAndServe()
		defer rs.Shutdown()

		sc := &BasicServerConfig{
			Addr:     addr,
			Protocol: "udp",
		}
		upstreamUDP, err := newUpstream(sc, 100, nil)
		if err != nil {
			t.Fatal(err)
		}
		testUpstream("udp", upstreamUDP)
		testServer.shutdowned = true
		testUpstreamTimeout("udp timeout", upstreamUDP)
		testServer.shutdowned = false
	}()

	// test tcp
	func() {
		tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := tcpListener.Addr().String()
		rs := dns.Server{Net: "tcp", Listener: tcpListener, Handler: testServer}
		go rs.ActivateAndServe()
		defer rs.Shutdown()
		sc := &BasicServerConfig{
			Addr:     addr,
			Protocol: "tcp",
		}
		sc.TCP.IdleTimeout = 8
		upstreamTCP, err := newUpstream(sc, 100, nil)
		if err != nil {
			t.Fatal(err)
		}
		testUpstream("tcp", upstreamTCP)
		testServer.shutdowned = true
		testUpstreamTimeout("tcp timeout", upstreamTCP)
		testServer.shutdowned = false
	}()

	// test dot
	func() {
		cert, err := generateCertificate()
		if err != nil {
			t.Fatal(err)
		}
		tlsConfig := new(tls.Config)
		tlsConfig.Certificates = []tls.Certificate{cert}
		tlsListener, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
		if err != nil {
			t.Fatal(err)
		}
		addr := tlsListener.Addr().String()
		rs := dns.Server{Net: "tcp-tls", Listener: tlsListener, TLSConfig: tlsConfig, Handler: testServer}
		go rs.ActivateAndServe()
		defer rs.Shutdown()
		sc := &BasicServerConfig{
			Addr:               addr,
			Protocol:           "dot",
			insecureSkipVerify: true,
		}
		sc.DoT.IdleTimeout = 10
		upstreamDot, err := newUpstream(sc, 100, nil)
		if err != nil {
			t.Fatal(err)
		}
		testUpstream("dot", upstreamDot)
		testServer.shutdowned = true
		testUpstreamTimeout("dot timeout", upstreamDot)
		testServer.shutdowned = false
	}()

	// TODO add tests for DoH
}

func Test_connPool(t *testing.T) {
	conn, _ := net.Pipe()

	// nil
	var cp *connPool
	cp.put(newDNSConn(conn, time.Now())) // do nothing
	if c := cp.get(); c != nil {
		t.Fatal("cp should be empty")
	}
	// zero size
	cp = newConnPool(0, time.Second, time.Second)
	cp.put(newDNSConn(conn, time.Now())) // do nothing
	if len(cp.pool) != 0 {
		t.Fatal("cp should be empty")
	}
	if c := cp.get(); c != nil {
		t.Fatal("cp should be empty")
	}

	cp = newConnPool(8, time.Millisecond*250, time.Second*30) // dont run cleaner in schedule
	for i := 0; i < 8; i++ {
		cp.put(newDNSConn(conn, time.Now()))
	}
	if len(cp.pool) != 8 {
		t.Fatal("cp should have 8 elems")
	}
	cp.put(newDNSConn(conn, time.Now())) // if cp is full, it will remove half of its elems and add this
	if len(cp.pool) != 5 {
		t.Fatalf("cp should have 5 elems, but got %d", len(cp.pool))
	}
	if c := cp.get(); c == nil {
		t.Fatal("cp should return a old conn")
	}
	if len(cp.pool) != 4 {
		t.Fatalf("cp should have 4 elems, but got %d", len(cp.pool))
	}
	time.Sleep(time.Millisecond * 500) // all elems are expired now.
	if c := cp.get(); c != nil {       // remove all expired elems
		t.Fatal("cp should be emtpy")
	}
	if len(cp.pool) != 0 { // all expired elems are removed
		t.Fatalf("cp should have 0 elems, but got %d", len(cp.pool))
	}
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
		err = fmt.Errorf("generate serial number: %v", err)
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
