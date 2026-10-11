{
  "log": {"level": "warn", "timestamp": true},
  "dns": {"servers": [{"type": "local", "tag": "system"}]},
  "inbounds": [{"type": "mixed", "tag": "local-proxy", "listen": "127.0.0.1", "listen_port": 2080, "set_system_proxy": false}],
  "outbounds": [
    {"type": "ssh", "tag": "ssh-out", "server": "", "server_port": 22, "user": "", "private_key_path": "", "host_key": [], "host_key_algorithms": [], "connect_timeout": "10s", "domain_resolver": "system"},
    {"type": "direct", "tag": "direct", "domain_resolver": "system"}
  ],
  "route": {
    "rules": [
      {"network": "udp", "action": "reject"},
      {"domain_suffix": ["anthropic.com", "claude.ai", "claude.com", "claudeusercontent.com", "claudemcpcontent.com"], "action": "route", "outbound": "ssh-out"},
      {"ip_cidr": ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "::1/128", "fc00::/7", "fe80::/10"], "action": "route", "outbound": "direct"},
      {"domain_suffix": ["local"], "action": "route", "outbound": "direct"}
    ],
    "final": "ssh-out"
  }
}
