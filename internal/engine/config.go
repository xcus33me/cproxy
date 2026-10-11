// Package engine adapts sing-box; it does not implement another proxy stack.
package engine

import (
	"encoding/json"
	"errors"

	"cproxy/internal/config"
	"cproxy/internal/sshconn"
)

type outbound struct {
	Type       string   `json:"type"`
	Tag        string   `json:"tag"`
	Server     string   `json:"server,omitempty"`
	Port       int      `json:"server_port,omitempty"`
	User       string   `json:"user,omitempty"`
	Key        string   `json:"private_key_path,omitempty"`
	Pass       string   `json:"private_key_passphrase,omitempty"`
	HostKey    []string `json:"host_key,omitempty"`
	Algorithms []string `json:"host_key_algorithms,omitempty"`
	Resolver   string   `json:"domain_resolver"`
	Timeout    string   `json:"connect_timeout,omitempty"`
}
type rule struct {
	Network  string   `json:"network,omitempty"`
	Domains  []string `json:"domain_suffix,omitempty"`
	CIDRs    []string `json:"ip_cidr,omitempty"`
	Action   string   `json:"action"`
	Outbound string   `json:"outbound,omitempty"`
}

func Config(s config.Settings, pass []byte) ([]byte, error) {
	if s.HostKey == "" {
		return nil, errors.New("Не подтверждён ключ SSH-сервера")
	}
	key, e := sshconn.PublicKey(s.HostKey)
	if e != nil {
		return nil, e
	}
	for _, d := range s.Domains {
		if e := config.ValidateDomain(d); e != nil {
			return nil, e
		}
	}
	for _, cidr := range s.CIDRs {
		if e := config.ValidateCIDR(cidr); e != nil {
			return nil, e
		}
	}
	var c struct {
		Log struct {
			Level     string `json:"level"`
			Timestamp bool   `json:"timestamp"`
		} `json:"log"`
		DNS struct {
			Servers []map[string]string `json:"servers"`
		} `json:"dns"`
		Inbounds []struct {
			Type   string `json:"type"`
			Tag    string `json:"tag"`
			Listen string `json:"listen"`
			Port   int    `json:"listen_port"`
			System bool   `json:"set_system_proxy"`
		} `json:"inbounds"`
		Outbounds []outbound `json:"outbounds"`
		Route     struct {
			Rules []rule `json:"rules"`
			Final string `json:"final"`
		} `json:"route"`
	}
	c.Log.Level = "warn"
	c.Log.Timestamp = true
	c.DNS.Servers = []map[string]string{{"type": "local", "tag": "system"}}
	c.Inbounds = append(c.Inbounds, struct {
		Type   string `json:"type"`
		Tag    string `json:"tag"`
		Listen string `json:"listen"`
		Port   int    `json:"listen_port"`
		System bool   `json:"set_system_proxy"`
	}{"mixed", "local-proxy", "127.0.0.1", s.ProxyPort, false})
	c.Outbounds = []outbound{{Type: "ssh", Tag: "ssh-out", Server: s.Server, Port: s.SSHPort, User: s.User, Key: s.Key, Pass: string(pass), HostKey: []string{s.HostKey}, Algorithms: sshconn.Algorithms(key), Resolver: "system", Timeout: "10s"}, {Type: "direct", Tag: "direct", Resolver: "system"}}
	c.Route.Rules = []rule{{Network: "udp", Action: "reject"}, {Domains: config.ProtectedDomains, Action: "route", Outbound: "ssh-out"}}
	if len(s.CIDRs) > 0 {
		c.Route.Rules = append(c.Route.Rules, rule{CIDRs: s.CIDRs, Action: "route", Outbound: "direct"})
	}
	if len(s.Domains) > 0 {
		c.Route.Rules = append(c.Route.Rules, rule{Domains: s.Domains, Action: "route", Outbound: "direct"})
	}
	c.Route.Final = "ssh-out"
	return json.Marshal(c)
}
