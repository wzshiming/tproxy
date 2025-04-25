package tproxy

import (
	"bytes"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

const (
	sentName       = "SNET"
	bypassSentName = "BYPASS_SNET"
)

type ipSet struct {
	name        string
	bypassCidrs []string
}

func (s *ipSet) Add(ip string) error {
	s.bypassCidrs = append(s.bypassCidrs, ip)
	cmd := exec.Command("ipset", "add", s.name, ip)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %v", string(out), err)
	}
	return nil
}

func (s *ipSet) init() error {
	_ = s.Close()
	result := make([]string, 0, len(s.bypassCidrs)+1)
	result = append(result, "create "+s.name+" hash:net family inet hashsize 1024 maxelem 65536")
	for _, route := range s.bypassCidrs {
		result = append(result, "add "+s.name+" "+route+" -exist")
	}
	cmd := exec.Command("ipset", "restore")
	cmd.Stdin = bytes.NewBufferString(strings.Join(result, "\n"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %v", string(out), err)
	}
	return nil
}

func (s *ipSet) Close() error {
	_ = exec.Command("ipset", "destroy", s.name).Run()
	return nil
}

type ipTables struct {
	ipset *ipSet
}

func (r *ipTables) Router(snetPort int, dnsPort int) error {
	r.cleanupRouter(dnsPort)
	port := strconv.Itoa(snetPort)

	cmd := exec.Command("iptables", "-t", "nat", "-N", sentName)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %v", string(out), err)
	}
	// by pass all tcp traffic for ips in BYPASS_SNET set
	cmd = exec.Command("iptables", "-t", "nat", "-A", sentName, "-p", "tcp", "-m", "set", "--match-set", r.ipset.name, "dst", "-j", "RETURN")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %v", string(out), err)
	}
	// redirect all tcp traffic in SNET chain to local proxy port
	cmd = exec.Command("iptables", "-t", "nat", "-A", sentName, "-p", "tcp", "-j", "REDIRECT", "--to-ports", port)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %v", string(out), err)
	}
	// send all output tcp traffic to SNET chain
	cmd = exec.Command("iptables", "-t", "nat", "-A", "OUTPUT", "-p", "tcp", "-j", sentName)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %v", string(out), err)
	}

	cmd = exec.Command("iptables", "-t", "nat", "-I", "PREROUTING", "-p", "tcp", "-j", sentName)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %v", string(out), err)
	}

	if dnsPort != 0 {
		dport := strconv.Itoa(dnsPort)
		cmd = exec.Command("iptables", "-t", "nat", "-I", "PREROUTING", "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-port", dport)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("%s: %v", string(out), err)
		}
	}
	return nil
}

func (r *ipTables) Local(snetPort int, dnsPort int, dnsHost string) error {
	r.cleanupLocal()
	var snetHost = "127.0.0.1"
	port := strconv.Itoa(snetPort)
	dport := strconv.Itoa(dnsPort)
	cmd := exec.Command("iptables", "-t", "nat", "-N", sentName)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %v", string(out), err)
	}
	// by pass all tcp traffic for ips in BYPASS_SNET set
	cmd = exec.Command("iptables", "-t", "nat", "-A", sentName, "-p", "tcp", "-m", "set", "--match-set", r.ipset.name, "dst", "-j", "RETURN")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %v", string(out), err)
	}
	// redirect all tcp traffic in SNET chain to local proxy port
	cmd = exec.Command("iptables", "-t", "nat", "-A", sentName, "-p", "tcp", "-j", "REDIRECT", "--to-ports", port)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %v", string(out), err)
	}
	// send all output tcp traffic to SNET chain
	cmd = exec.Command("iptables", "-t", "nat", "-A", "OUTPUT", "-p", "tcp", "-j", sentName)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %v", string(out), err)
	}

	if dnsHost != "" {
		// avoid outgoing cn dns query be redirected to snet, it's a loop!
		cmd = exec.Command("iptables", "-t", "nat", "-A", sentName, "-d", dnsHost, "-j", "RETURN")
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("%s: %v", string(out), err)
		}
		// redirect dns query in SNET chain to snet listen address
		cmd = exec.Command("iptables", "-t", "nat", "-A", sentName, "-p", "udp", "--dport", "53", "-j", "DNAT", "--to-destination", snetHost+":"+dport)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("%s: %v", string(out), err)
		}

		// redirect all outgoing dns query to SNET chain (except cn dns)
		cmd = exec.Command("iptables", "-t", "nat", "-A", "OUTPUT", "-p", "udp", "--dport", "53", "-j", sentName)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("%s: %v", string(out), err)
		}
	}
	return nil
}

func (r *ipTables) cleanupRouter(dnsPort int) error {
	cmd := exec.Command("iptables", "-t", "nat", "-D", "OUTPUT", "-p", "tcp", "-j", sentName)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %v", string(out), err)
	}

	cmd = exec.Command("iptables", "-t", "nat", "-D", "PREROUTING", "-p", "tcp", "-j", sentName)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %v", string(out), err)
	}

	if dnsPort != 0 {
		dport := strconv.Itoa(dnsPort)
		cmd = exec.Command("iptables", "-t", "nat", "-D", "PREROUTING", "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-port", dport)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("%s: %v", string(out), err)
		}
	}
	return nil
}

func (r *ipTables) cleanupLocal() error {
	cmd := exec.Command("iptables", "-t", "nat", "-D", "OUTPUT", "-p", "tcp", "-j", sentName)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %v", string(out), err)
	}

	cmd = exec.Command("iptables", "-t", "nat", "-D", "OUTPUT", "-p", "udp", "--dport", "53", "-j", sentName)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %v", string(out), err)
	}
	cmd = exec.Command("iptables", "-t", "nat", "-F", sentName)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %v", string(out), err)
	}
	cmd = exec.Command("iptables", "-t", "nat", "-X", sentName)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %v", string(out), err)
	}
	return nil
}

func (r *ipTables) Close() error {
	return r.ipset.Close()
}

func newTProxy(byPassRoutes []string) (TProxy, error) {
	ipset := &ipSet{name: bypassSentName, bypassCidrs: byPassRoutes}
	err := ipset.init()
	if err != nil {
		return nil, err
	}
	return &ipTables{ipset}, nil
}
