package wginternal

import (
	"errors"
	"io"

	"github.com/danpashin/wgctrl/wgtypes"
)

// ErrReadOnly indicates that the driver backing a device is read-only. It is
// a sentinel value used in integration tests.
// TODO(mdlayher): consider exposing in API.
var ErrReadOnly = errors.New("driver is read-only")

type WgClientType int

const (
	WgNativeClient  WgClientType = 0
	WgAmneziaClient WgClientType = 1

	WGDEVICE_A_JC   = 0x9
	WGDEVICE_A_JMIN = 0xA
	WGDEVICE_A_JMAX = 0xB
	WGDEVICE_A_S1   = 0xC
	WGDEVICE_A_S2   = 0xD
	WGDEVICE_A_H1   = 0xE
	WGDEVICE_A_H2   = 0xF
	WGDEVICE_A_H3   = 0x10
	WGDEVICE_A_H4   = 0x11
)

// A Client is a type which can control a WireGuard device.
type Client interface {
	io.Closer
	Devices() ([]*wgtypes.Device, error)
	Device(name string) (*wgtypes.Device, error)
	ConfigureDevice(name string, cfg wgtypes.Config) error
}
