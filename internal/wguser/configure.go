package wguser

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/danpashin/wgctrl/wgtypes"
)

// configureDevice configures a device specified by its path.
func (c *Client) configureDevice(device string, cfg wgtypes.Config) error {
	conn, err := c.dial(device)
	if err != nil {
		return err
	}
	defer conn.Close()

	// Start with set command.
	var buf bytes.Buffer
	buf.WriteString("set=1\n")

	// Add any necessary configuration from cfg, then finish with an empty line.
	writeConfig(&buf, cfg)
	buf.WriteString("\n")

	// Apply configuration for the device and then check the error number.
	if _, err := io.Copy(conn, &buf); err != nil {
		return err
	}

	res := make([]byte, 32)
	n, err := conn.Read(res)
	if err != nil {
		return err
	}

	// errno=0 indicates success, anything else returns an error number that
	// matches definitions from errno.h.
	str := strings.TrimSpace(string(res[:n]))
	if str != "errno=0" {
		// TODO(mdlayher): return actual errno on Linux?
		return os.NewSyscallError("read", fmt.Errorf("wguser: %s", str))
	}

	return nil
}

// writeConfig writes textual configuration to w as specified by cfg.
func writeConfig(w io.Writer, cfg wgtypes.Config) {
	if cfg.PrivateKey != nil {
		fmt.Fprintf(w, "private_key=%s\n", hexKey(*cfg.PrivateKey))
	}

	if cfg.ListenPort != nil {
		fmt.Fprintf(w, "listen_port=%d\n", *cfg.ListenPort)
	}

	if cfg.FirewallMark != nil {
		fmt.Fprintf(w, "fwmark=%d\n", *cfg.FirewallMark)
	}

	if cfg.ReplacePeers {
		fmt.Fprintln(w, "replace_peers=true")
	}

	for _, p := range cfg.Peers {
		fmt.Fprintf(w, "public_key=%s\n", hexKey(p.PublicKey))

		if p.Remove {
			fmt.Fprintln(w, "remove=true")
		}

		if p.UpdateOnly {
			fmt.Fprintln(w, "update_only=true")
		}

		if p.PresharedKey != nil {
			fmt.Fprintf(w, "preshared_key=%s\n", hexKey(*p.PresharedKey))
		}

		if p.Endpoint != nil {
			fmt.Fprintf(w, "endpoint=%s\n", p.Endpoint.String())
		}

		if p.PersistentKeepaliveInterval != nil {
			fmt.Fprintf(w, "persistent_keepalive_interval=%d\n", int(p.PersistentKeepaliveInterval.Seconds()))
		}

		if p.ReplaceAllowedIPs {
			fmt.Fprintln(w, "replace_allowed_ips=true")
		}

		for _, ip := range p.AllowedIPs {
			fmt.Fprintf(w, "allowed_ip=%s\n", ip.String())
		}
	}

	advancedSecCfg := cfg.AdvancedSecurityConfig
	if advancedSecCfg.JunkPacketCount != nil {
		fmt.Fprintf(w, "jc=%d\n", *advancedSecCfg.JunkPacketCount)
	}

	if advancedSecCfg.JunkPacketMinSize != nil {
		fmt.Fprintf(w, "jmin=%d\n", *advancedSecCfg.JunkPacketMinSize)
	}

	if advancedSecCfg.JunkPacketMaxSize != nil {
		fmt.Fprintf(w, "jmax=%d\n", *advancedSecCfg.JunkPacketMaxSize)
	}

	if advancedSecCfg.InitPacketJunkSize != nil {
		fmt.Fprintf(w, "s1=%d\n", *advancedSecCfg.InitPacketJunkSize)
	}

	if advancedSecCfg.ResponsePacketJunkSize != nil {
		fmt.Fprintf(w, "s2=%d\n", *advancedSecCfg.ResponsePacketJunkSize)
	}

	if advancedSecCfg.InitPacketMagicHeader != nil {
		fmt.Fprintf(w, "h1=%d\n", *advancedSecCfg.InitPacketMagicHeader)
	}

	if advancedSecCfg.ResponsePacketMagicHeader != nil {
		fmt.Fprintf(w, "h2=%d\n", *advancedSecCfg.ResponsePacketMagicHeader)
	}

	if advancedSecCfg.UnderloadPacketMagicHeader != nil {
		fmt.Fprintf(w, "h3=%d\n", *advancedSecCfg.UnderloadPacketMagicHeader)
	}

	if advancedSecCfg.TransportPacketMagicHeader != nil {
		fmt.Fprintf(w, "h4=%d\n", *advancedSecCfg.TransportPacketMagicHeader)
	}
}

// hexKey encodes a wgtypes.Key into a hexadecimal string.
func hexKey(k wgtypes.Key) string {
	return hex.EncodeToString(k[:])
}
