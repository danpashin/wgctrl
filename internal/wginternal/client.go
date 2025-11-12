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

const (
	WGDEVICE_A_JC   = 0x9
	WGDEVICE_A_JMIN = 0xA
	WGDEVICE_A_JMAX = 0xB
	WGDEVICE_A_S1   = 0xC
	WGDEVICE_A_S2   = 0xD
	WGDEVICE_A_H1   = 0xE
	WGDEVICE_A_H2   = 0xF
	WGDEVICE_A_H3   = 0x10
	WGDEVICE_A_H4   = 0x11
	WGDEVICE_A_S3   = 0x13
	WGDEVICE_A_S4   = 0x14
	WGDEVICE_A_I1   = 0x15
	WGDEVICE_A_I2   = 0x16
	WGDEVICE_A_I3   = 0x17
	WGDEVICE_A_I4   = 0x18
	WGDEVICE_A_I5   = 0x19
	WGDEVICE_A_DI   = 0x1A
	WGDEVICE_A_DR   = 0x1B
	WGDEVICE_A_DC   = 0x1C
	WGDEVICE_A_DT   = 0x1D
)

const (
	WGPEER_F_HAS_ADVANCED_SECURITY = 0x8
)

const (
	WGPEER_A_ADVANCED_SECURITY = 0xB
)

const MAX_AWG_STRING_LEN = 5 * 1024

// A Client is a type which can control a WireGuard device.
type Client interface {
	io.Closer
	Devices() ([]*wgtypes.Device, error)
	Device(name string) (*wgtypes.Device, error)
	ConfigureDevice(name string, cfg wgtypes.Config) error
}
