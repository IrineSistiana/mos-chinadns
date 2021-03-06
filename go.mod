module github.com/IrineSistiana/mos-chinadns

go 1.15

require (
	github.com/golang/protobuf v1.4.3
	github.com/miekg/dns v1.1.34
	github.com/sirupsen/logrus v1.6.0
	github.com/vishvananda/netlink v1.1.1-0.20201029203352-d40f9887b852
	golang.org/x/net v0.0.0-20201022231255-08b38378de70
	golang.org/x/sync v0.0.0-20201020160332-67f06af15bc9
	golang.org/x/sys v0.0.0-20201022201747-fb209a7c41cd
	gopkg.in/yaml.v3 v3.0.0-20200615113413-eeeca48fe776
	v2ray.com/core v4.19.1+incompatible
)

// this version isn't correct
replace v2ray.com/core => github.com/v2fly/v2ray-core v0.0.0-20201023173911-0dc17643a07c
