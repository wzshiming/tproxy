package tproxy

const (
	modeLocal  = "local"
	modeRouter = "router"
)

// https://en.wikipedia.org/wiki/Reserved_IP_addresses#Reserved_IPv4_addresses
var whitelistCIDR = []string{
	"0.0.0.0/8",
	"10.0.0.0/8",
	"100.64.0.0/10",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.0.2.0/24",
	"192.88.99.0/24",
	"192.168.0.0/16",
	"192.18.0.0/15",
	"192.51.100.0/24",
	"203.0.113.0/24",
	"224.0.0.0/4",
	"240.0.0.0/4",
	"255.255.255.255/32",
}

type TProxy interface {
	Router(snetPort int, dnsPort int) error
	Local(snetPort int, dnsPort int, dnsHost string) error
	Close() error
}

func NewTProxy(byPassRoutes []string) (TProxy, error) {
	return newTProxy(append(whitelistCIDR, byPassRoutes...))
}
