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
	WGDEVICE_A_JC                       = 0x9
	WGDEVICE_A_JMIN                     = 0xA
	WGDEVICE_A_JMAX                     = 0xB
	WGDEVICE_A_S1                       = 0xC
	WGDEVICE_A_S2                       = 0xD
	WGDEVICE_A_H1                       = 0xE
	WGDEVICE_A_H2                       = 0xF
	WGDEVICE_A_H3                       = 0x10
	WGDEVICE_A_H4                       = 0x11
	WGDEVICE_A_S3                       = 0x13
	WGDEVICE_A_S4                       = 0x14
	WGDEVICE_A_I1                       = 0x15
	WGDEVICE_A_I2                       = 0x16
	WGDEVICE_A_I3                       = 0x17
	WGDEVICE_A_I4                       = 0x18
	WGDEVICE_A_I5                       = 0x19
	WGDEVICE_A_HEADER_PROTECTION_KEY    = 0x1a
	WGDEVICE_A_CONTENT_PADDING_ADDITION = 0x1b
	WGDEVICE_A_REKEY_AFTER_TIME         = 0x1c
	WGDEVICE_A_REKEY_TIMEOUT            = 0x1d
	WGDEVICE_A_REJECT_AFTER_TIME        = 0x1e
	WGDEVICE_A_KEEPALIVE_TIMEOUT        = 0x1f
	WGDEVICE_A_MAX_HANDSHAKE_ATTEMPTS   = 0x20
	WGDEVICE_A_RANDOM_TRAILERS          = 0x21
	WGDEVICE_A_DISABLE_COOKIES          = 0x22
)

const MAX_AWG_STRING_LEN = 5 * 1024

// A Client is a type which can control a WireGuard device.
type Client interface {
	io.Closer
	Devices() ([]*wgtypes.Device, error)
	Device(name string) (*wgtypes.Device, error)
	ConfigureDevice(name string, cfg wgtypes.Config) error
}
