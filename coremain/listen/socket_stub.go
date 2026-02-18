//go:build !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris && !windows

package listen

import (
	"net"
)

func CreateListenConfig(_ bool) net.ListenConfig {
	return net.ListenConfig{}
}
