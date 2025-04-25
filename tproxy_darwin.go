package tproxy

import (
	"bytes"
	"fmt"
	exec "os/exec"
	"strings"
)

const (
	bypassSentName = "BYPASS_SNET"
)

type pfTable struct {
	Name        string
	bypassCidrs []string
}

func (t *pfTable) String() string {
	return strings.Join(t.bypassCidrs, " ")
}

type packetFilter struct {
	bypassTable *pfTable
	eni         string
}

func (pf *packetFilter) Router(snetPort int, dnsPort int) error {
	return fmt.Errorf("unsupported yet")
}

func (pf *packetFilter) Local(snetPort int, dnsPort int, dnsHost string) error {
	_ = pf.Close()

	var snetHost = "127.0.0.1"
	var tableBuilder strings.Builder
	tableBuilder.WriteString(fmt.Sprintf("table <%s> { %s }\n", pf.bypassTable.Name, pf.bypassTable.String()))
	tableBuilder.WriteString("lo=\"lo0\"\n")
	tableBuilder.WriteString(fmt.Sprintf("dev=\"%s\"\n", pf.eni))

	// let proxy handle tcp
	tableBuilder.WriteString(fmt.Sprintf("rdr on $lo proto tcp from $dev to any port 1:65535 -> %s port %d\n", snetHost, snetPort))

	if dnsPort != 0 {
		// let proxy handle dns query
		tableBuilder.WriteString(fmt.Sprintf("rdr on $lo proto udp from $dev to any port 53 -> %s port %d\n", snetHost, dnsPort))
	}

	// re-route outgoing tcp
	tableBuilder.WriteString("pass out on $dev route-to $lo proto tcp from $dev to any port 1:65535\n")

	if dnsHost != "" {
		// re-route outgoing udp
		tableBuilder.WriteString("pass out on $dev route-to $lo proto udp from $dev to any port 53\n")

		tableBuilder.WriteString(fmt.Sprintf("pass out proto udp from any to %s\n", dnsHost))
	}

	tableBuilder.WriteString(fmt.Sprintf("pass out proto tcp from any to <%s>\n", pf.bypassTable.Name))

	shCmd := exec.Command("pfctl", "-ef", "-")
	shCmd.Stdin = bytes.NewBufferString(tableBuilder.String())
	if out, err := shCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s\n%s\n%w", tableBuilder.String(), string(out), err)
	}
	return nil
}

func (pf *packetFilter) Close() error {
	cmd := exec.Command("pfctl", "-d")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %v", string(out), err)
	}
	return nil
}

func newTProxy(byPassRoutes []string) (TProxy, error) {
	pfTable := &pfTable{Name: bypassSentName, bypassCidrs: byPassRoutes}
	return &packetFilter{pfTable, findActiveInterface()}, nil
}

func findActiveInterface() string {
	cmd := exec.Command("route", "-n", "get", "default")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "en0"
	}
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if strings.Contains(line, "interface:") {
			parts := strings.Fields(line)
			if len(parts) > 1 {
				return parts[1]
			}
		}
	}
	return "en0"
}
