// Command wgctrl is a testing utility for interacting with WireGuard via package
// wgctrl.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/danpashin/wgctrl"
	"github.com/danpashin/wgctrl/wgtypes"
)

func main() {
	flag.Parse()

	clientTypes := [](wgtypes.ClientType){
		wgtypes.AmneziaClient,
		wgtypes.NativeClient,
	}

	for _, clientType := range clientTypes {
		c, err := wgctrl.New(clientType)
		if err != nil {
			log.Fatalf("failed to open wgctrl: %v", err)
		}
		defer c.Close()

		var devices []*wgtypes.Device
		if device := flag.Arg(0); device != "" {
			d, err := c.Device(device)
			if err != nil {
				log.Fatalf("failed to get device %q: %v", device, err)
			}

			devices = append(devices, d)
		} else {
			devices, err = c.Devices()
			if err != nil {
				log.Fatalf("failed to get devices: %v", err)
			}
		}

		for _, d := range devices {
			printDevice(d)

			for _, p := range d.Peers {
				printPeer(p)
			}
		}
	}
}

func printDevice(d *wgtypes.Device) {
	const f = `interface: %s (%s)
  public key: %s
  private key: (hidden)
  listening port: %d

`

	fmt.Printf(
		f,
		d.Name,
		d.Type.String(),
		d.PublicKey.String(),
		d.ListenPort)

	if d.HasAdvancedSecurity() {
		advSec := d.AdvancedSecurity

		if advSec.JunkPacketCount != 0 {
			fmt.Printf("  jc: %d\n", advSec.JunkPacketCount)
		}
		if advSec.JunkPacketMinSize != 0 {
			fmt.Printf("  jmin: %d\n", advSec.JunkPacketMinSize)
		}
		if advSec.JunkPacketMaxSize != 0 {
			fmt.Printf("  jmax: %d\n", advSec.JunkPacketMaxSize)
		}
		if advSec.InitPacketJunkSize != 0 {
			fmt.Printf("  s1: %d\n", advSec.InitPacketJunkSize)
		}
		if advSec.ResponsePacketJunkSize != 0 {
			fmt.Printf("  s2: %d\n", advSec.ResponsePacketJunkSize)
		}
		if advSec.CookieReplyPacketJunkSize != 0 {
			fmt.Printf("  s3: %d\n", advSec.CookieReplyPacketJunkSize)
		}
		if advSec.TransportPacketJunkSize != 0 {
			fmt.Printf("  s4: %d\n", advSec.TransportPacketJunkSize)
		}
		fmt.Printf("  h1: %s\n", advSec.InitPacketMagicHeader)
		fmt.Printf("  h2: %s\n", advSec.ResponsePacketMagicHeader)
		fmt.Printf("  h3: %s\n", advSec.UnderloadPacketMagicHeader)
		fmt.Printf("  h4: %s\n", advSec.TransportPacketMagicHeader)
		if advSec.FirstSpecialJunkPacket != nil {
			fmt.Printf("  i1: %s\n", *advSec.FirstSpecialJunkPacket)
		}
		if advSec.SecondSpecialJunkPacket != nil {
			fmt.Printf("  i2: %s\n", *advSec.SecondSpecialJunkPacket)
		}
		if advSec.ThirdSpecialJunkPacket != nil {
			fmt.Printf("  i3: %s\n", *advSec.ThirdSpecialJunkPacket)
		}
		if advSec.FourthSpecialJunkPacket != nil {
			fmt.Printf("  i4: %s\n", *advSec.FourthSpecialJunkPacket)
		}
		if advSec.FifthSpecialJunkPacket != nil {
			fmt.Printf("  i5: %s\n", *advSec.FifthSpecialJunkPacket)
		}
		if advSec.HeaderProtectionKey != nil {
			fmt.Printf("  HeaderProtectionKey: %s\n", advSec.HeaderProtectionKey.HexString())
		}
		if advSec.RekeyAfterTime != nil {
			fmt.Printf("  RekeyAfterTime: %s\n", advSec.RekeyAfterTime)
		}
		if advSec.RekeyTimeout != nil {
			fmt.Printf("  RekeyTimeout: %s\n", advSec.RekeyTimeout)
		}
		if advSec.RejectAfterTime != nil {
			fmt.Printf("  RejectAfterTime: %s\n", advSec.RejectAfterTime)
		}
		if advSec.KeepaliveTimeout != nil {
			fmt.Printf("  KeepaliveTimeout: %s\n", advSec.KeepaliveTimeout)
		}
		if advSec.HandshakeAttemptsLimit != nil {
			fmt.Printf("  MaxHandshakeAttempts: %s\n", advSec.HandshakeAttemptsLimit)
		}
		fmt.Printf("  random trailers: %t\n", advSec.RandomTrailers)
		fmt.Printf("  disable cookies: %t\n", advSec.DisableCookies)
		fmt.Println()
	}
}

func printPeer(p wgtypes.Peer) {
	const f = `peer: %s
  endpoint: %s
  allowed ips: %s
  latest handshake: %s
  transfer: %d B received, %d B sent

`

	fmt.Printf(
		f,
		p.PublicKey.String(),
		// TODO(mdlayher): get right endpoint with getnameinfo.
		p.Endpoint.String(),
		ipsString(p.AllowedIPs),
		p.LastHandshakeTime.String(),
		p.ReceiveBytes,
		p.TransmitBytes,
	)
}

func ipsString(ipns []net.IPNet) string {
	ss := make([]string, 0, len(ipns))
	for _, ipn := range ipns {
		ss = append(ss, ipn.String())
	}

	return strings.Join(ss, ", ")
}
