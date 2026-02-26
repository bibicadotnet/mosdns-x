package coremain

import (
	"github.com/pmkol/mosdns-x/mlog"
	"github.com/pmkol/mosdns-x/pkg/data_provider"
	"github.com/pmkol/mosdns-x/pkg/utils"
)

type Config struct {
	Log           mlog.LogConfig                     `yaml:"log"`
	Include       []string                           `yaml:"include"`
	DataProviders []data_provider.DataProviderConfig `yaml:"data_providers"`
	Plugins       []PluginConfig                     `yaml:"plugins"`
	Servers       []ServerConfig                     `yaml:"servers"`
	API           APIConfig                          `yaml:"api"`

	// Experimental
	Security SecurityConfig `yaml:"security"`
}

// PluginConfig represents a plugin config
type PluginConfig struct {
	// Tag, required
	Tag string `yaml:"tag"`

	// Type, required
	Type string `yaml:"type"`

	// Args, might be required by some plugins.
	// The type of Args is depended on RegNewPluginFunc.
	// If it's a map[string]interface{}, it will be converted by mapstruct.
	Args interface{} `yaml:"args"`
}

type ServerConfig struct {
	Exec      string                  `yaml:"exec"`
	Timeout   uint                    `yaml:"timeout"` // (sec) query timeout.
	Listeners []*ServerListenerConfig `yaml:"listeners"`

	// Early blocking options
	BlockAAAA  bool `yaml:"block_aaaa"`
	BlockPTR   bool `yaml:"block_ptr"`
	BlockHTTPS bool `yaml:"block_https"`
	BlockNoDot bool `yaml:"block_no_dot"`
	StripEDNS0 bool `yaml:"strip_edns0"`
}

type ServerListenerConfig struct {
	// Protocol: server protocol, can be:
	// "", "udp" -> udp
	// "tcp" -> tcp
	// "dot", "tls" -> dns over tls
	// "doh", "https" -> dns over https (rfc 8844)
	// "http" -> dns over https (rfc 8844) but without tls
	// "doq", "quic" -> dns over quic (rfc 9250)
	// "doh3", "h3" -> dns over http3 (rfc 9114 && rfc 8844)
	Protocol string `yaml:"protocol"`

	// Addr: server "host:port" addr.
	// When uds enabled must be "path"
	// Addr cannot be empty.
	Addr string `yaml:"addr"`

	// UnixDomainSocket: server addr is uds.
	UnixDomainSocket bool `yaml:"uds"`

	Cert                string `yaml:"cert"`                    // certificate path, used by dot, doh, doq
	Key                 string `yaml:"key"`                     // certificate key path, used by dot, doh, doq
	KernelTX            bool   `yaml:"kernel_tx"`                // use kernel tls to send data
	KernelRX            bool   `yaml:"kernel_rx"`                // use kernel tls to receive data
	URLPath             string `yaml:"url_path"`                 // used by doh, http. If it's empty, any path will be handled.
	HealthPath          string `yaml:"health_path"`              // health check endpoint path
	RedirectURL         string `yaml:"redirect_url"`             // redirect URL for non-DNS paths
	GetUserIPFromHeader string `yaml:"get_user_ip_from_header"` // used by doh, http, except "True-Client-IP" "X-Real-IP" "X-Forwarded-For".
	ProxyProtocol       bool   `yaml:"proxy_protocol"`           // accepting the PROXYProtocol

	IdleTimeout uint `yaml:"idle_timeout"` // (sec) used by tcp, dot, doh as connection idle timeout.
	AllowedSNI  string `yaml:"allowed_sni"` // 只允许指定的SNI访问
}

type APIConfig struct {
	HTTP string `yaml:"http"`
}

type SecurityConfig struct {
	BadIPObserver BadIPObserverConfig `yaml:"bad_ip_observer"`
}

// BadIPObserverConfig is a copy of ip_observer.BadIPObserverOpts.
type BadIPObserverConfig struct {
	Threshold        int    `yaml:"threshold"` // Zero Threshold will disable the bad ip observer.
	Interval         int    `yaml:"interval"`  // (sec) Default is 10.
	TTL              int    `yaml:"ttl"`       // (sec) Default is 600 (10min).
	OnUpdateCallBack string `yaml:"on_update_callback"`
	// IP masks to aggregate an IP range.
	IPv4Mask int `yaml:"ipv4_mask"` // Default is 32.
	IPv6Mask int `yaml:"ipv6_mask"` // Default is 48.
}

func (c *BadIPObserverConfig) Init() {
	utils.SetDefaultNum(&c.Interval, 10)
	utils.SetDefaultNum(&c.TTL, 600)
	utils.SetDefaultNum(&c.IPv4Mask, 32)
	utils.SetDefaultNum(&c.IPv6Mask, 48)
}
