package dispatcher

import (
	"github.com/miekg/dns"
	"net"
	"testing"
)

func Test_ipPolicies(t *testing.T) {

	d := new(Dispatcher)
	// new policies
	p1, err := d.newIPPolicies("accept:./testdata/ip.list|deny")
	if err != nil {
		t.Fatal(err)
	}
	p2, err := d.newIPPolicies("deny:./testdata/ip.list|accept")
	if err != nil {
		t.Fatal(err)
	}

	ipInTestList := []string{"1.0.0.1", "1.0.0.2", "2.0.0.255", "3.0.128.85"}
	ipNotInTestList := []string{"1.0.128.1", "2.0.128.2", "12.0.0.255", "13.0.128.85"}

	for _, ip := range ipInTestList {
		if action := p1.check(net.ParseIP(ip).To16()); action == nil || action.mode != policyActionAccept {
			t.Fatalf("ip %s should be accepted", ip)
		}

		if action := p2.check(net.ParseIP(ip).To16()); action == nil || action.mode != policyActionDeny {
			t.Fatalf("ip %s should be denied", ip)
		}
	}

	for _, ip := range ipNotInTestList {
		if action := p1.check(net.ParseIP(ip).To16()); action == nil || action.mode != policyActionDeny {
			t.Fatalf("ip %s should be denied", ip)
		}

		if action := p2.check(net.ParseIP(ip).To16()); action == nil || action.mode != policyActionAccept {
			t.Fatalf("ip %s should be onhold", ip)
		}
	}
}

func Test_domainPolicies(t *testing.T) {

	d := new(Dispatcher)
	// new policies
	p1, err := d.newDomainPolicies("accept:./testdata/domain.list|deny", false)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := d.newDomainPolicies("deny:./testdata/domain.list|accept", false)
	if err != nil {
		t.Fatal(err)
	}

	domainInTestList := []string{"a.com", "a.a.com", "b.b.com", "c.com", "d.d.e.com"}
	domainNotInTestList := []string{"zz.com", "zz.zz.com", "c.e.com", "cn"}

	for _, domain := range domainInTestList {
		if action := p1.check(dns.Fqdn(domain)); action == nil || action.mode != policyActionAccept {
			t.Fatalf("domain %s should be accepted", domain)
		}

		if action := p2.check(dns.Fqdn(domain)); action == nil || action.mode != policyActionDeny {
			t.Fatalf("domain %s should be denied", domain)
		}
	}

	for _, domain := range domainNotInTestList {
		if action := p1.check(dns.Fqdn(domain)); action == nil || action.mode != policyActionDeny {
			t.Fatalf("domain %s should be denied", domain)
		}

		if action := p2.check(dns.Fqdn(domain)); action == nil || action.mode != policyActionAccept {
			t.Fatalf("domain %s should be onhold", domain)
		}
	}
}
