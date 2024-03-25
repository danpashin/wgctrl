//go:build windows
// +build windows

package wgctrl

import (
	"github.com/danpashin/wgctrl/internal/wginternal"
	"github.com/danpashin/wgctrl/internal/wguser"
	"github.com/danpashin/wgctrl/internal/wgwindows"
	"github.com/danpashin/wgctrl/wgtypes"
)

// newClients configures wginternal.Clients for Windows systems.
func newClients(clientType wgtypes.ClientType) ([]wginternal.Client, error) {
	var clients []wginternal.Client

	// Windows has an in-kernel WireGuard implementation.
	kc := wgwindows.New()
	clients = append(clients, kc)

	uc, err := wguser.New(clientType)
	if err != nil {
		return nil, err
	}

	clients = append(clients, uc)
	return clients, nil
}
