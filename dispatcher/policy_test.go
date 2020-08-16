package dispatcher

import (
	"github.com/IrineSistiana/mos-chinadns/dispatcher/netlist"
	"github.com/miekg/dns"
	"net"
	"testing"
)

func Test_ipPolicies(t *testing.T) {

	// new policies
	p1, err := newIPPolicies("accept:./testdata/ip.list|deny_all")
	if err != nil {
		t.Fatal(err)
	}
	p2, err := newIPPolicies("deny:./testdata/ip.list")
	if err != nil {
		t.Fatal(err)
	}

	ipInTestList := []string{"1.0.0.1", "1.0.0.2", "2.0.0.255", "3.0.128.85"}
	ipNotInTestList := []string{"1.0.128.1", "2.0.128.2", "12.0.0.255", "13.0.128.85"}

	for _, ip := range ipInTestList {
		if p1.check(netlist.Conv(net.ParseIP(ip).To16())) != policyFinalActionAccept {
			t.Fatalf("ip %s should be accepted", ip)
		}

		if p2.check(netlist.Conv(net.ParseIP(ip).To16())) != policyFinalActionDeny {
			t.Fatalf("ip %s should be denied", ip)
		}
	}

	for _, ip := range ipNotInTestList {
		if p1.check(netlist.Conv(net.ParseIP(ip).To16())) != policyFinalActionDeny {
			t.Fatalf("ip %s should be denied", ip)
		}

		if p2.check(netlist.Conv(net.ParseIP(ip).To16())) != policyFinalActionOnHold {
			t.Fatalf("ip %s should be onhold", ip)
		}
	}
}

func Test_domainPolicies(t *testing.T) {

	// new policies
	p1, err := newDomainPolicies("accept:./testdata/domain.list|deny_all")
	if err != nil {
		t.Fatal(err)
	}
	p2, err := newDomainPolicies("deny:./testdata/domain.list")
	if err != nil {
		t.Fatal(err)
	}

	domainInTestList := []string{"a.com", "a.a.com", "b.b.com", "c.com", "d.d.e.com"}
	domainNotInTestList := []string{"zz.com", "zz.zz.com", "c.e.com", "cn"}

	for _, domain := range domainInTestList {
		if p1.check(dns.Fqdn(domain)) != policyFinalActionAccept {
			t.Fatalf("domain %s should be accepted", domain)
		}

		if p2.check(dns.Fqdn(domain)) != policyFinalActionDeny {
			t.Fatalf("domain %s should be denied", domain)
		}
	}

	for _, domain := range domainNotInTestList {
		if p1.check(dns.Fqdn(domain)) != policyFinalActionDeny {
			t.Fatalf("domain %s should be denied", domain)
		}

		if p2.check(dns.Fqdn(domain)) != policyFinalActionOnHold {
			t.Fatalf("domain %s should be onhold", domain)
		}
	}
}
