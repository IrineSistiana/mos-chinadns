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
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func Test_basicUpstream(t *testing.T) {
	testUpstream := func(name string, u Upstream) {
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

				ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
				defer cancel()
				_, err := u.Exchange(ctx, q)
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

	testUpstreamTimeout := func(name string, u Upstream) {
		q := new(dns.Msg)
		q.SetQuestion("example.com.", dns.TypeA)

		ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*50)
		defer cancel()
		r, err := u.Exchange(ctx, q)
		if err != nil {
			return
		}
		t.Fatalf("%s: err here, got %v", name, r)
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
		upstreamUDP, err := NewUpstream(sc, nil)
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
		upstreamTCP, err := NewUpstream(sc, nil)
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
			InsecureSkipVerify: true,
		}
		sc.DoT.IdleTimeout = 10
		sc.DoT.ServerName = "example.com"
		upstreamDot, err := NewUpstream(sc, nil)
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

// This test tests if proxy.SOCKS5 still return a proxy.ContextDialer
func Test_getUpstreamDialContextFunc(t *testing.T) {
	_, err := getUpstreamDialContextFunc("tcp", "127.0.0.1:1081", "127.0.0.1:1080")
	if err != nil {
		t.Fatal(err)
	}
}

func Test_connPool(t *testing.T) {
	conn, _ := net.Pipe()

	var cp *connPool
	cp = newConnPool(8, time.Millisecond*500, time.Millisecond*250)
	if c := cp.get(); c != nil {
		t.Fatal("cp should be empty")
	}

	for i := 0; i < 8; i++ {
		cp.put(conn)
	}
	if cp.pool.Len() != 8 {
		t.Fatal("cp should have 8 elems")
	}
	if atomic.LoadInt32(&cp.cleanerStatus) != cleanerOnline {
		t.Fatal("cp cleaner should be online")
	}
	cp.put(conn) // if cp is full.
	if cp.pool.Len() != 8 {
		t.Fatalf("cp should have 8 elems, but got %d", cp.pool.Len())
	}
	if c := cp.get(); c == nil {
		t.Fatal("cp should return a conn")
	}
	if cp.pool.Len() != 7 {
		t.Fatalf("cp should have 7 elems, but got %d", cp.pool.Len())
	}

	time.Sleep(time.Millisecond * 1000) // all elems are expired now.
	if cp.pool.Len() != 0 {             // all expired elems are removed
		t.Fatalf("cp should have 0 elems, but got %d", cp.pool.Len())
	}
	if atomic.LoadInt32(&cp.cleanerStatus) != cleanerOffline { // if no elem in pool, cleaner should exit.
		t.Fatal("cp cleaner should be offline")
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
