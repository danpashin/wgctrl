//go:build !linux && !openbsd && !windows && !freebsd
// +build !linux,!openbsd,!windows,!freebsd

package wgctrl

import (
	"github.com/danpashin/wgctrl/internal/wginternal"
	"github.com/danpashin/wgctrl/internal/wguser"
	"github.com/danpashin/wgctrl/wgtypes"
)

// newClients configures wginternal.Clients for systems which only support
// userspace WireGuard implementations.
func newClients(clientType wgtypes.ClientType) ([]wginternal.Client, error) {
	c, err := wguser.New(clientType)
	if err != nil {
		return nil, err
	}

	return []wginternal.Client{c}, nil
}
