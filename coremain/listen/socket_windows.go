//go:build windows

package listen

import (
	"net"
	"syscall"
)

func CreateListenConfig(uds bool) net.ListenConfig {
	return net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			if uds {
				return nil
			}
			var e error
			err := c.Control(func(fd uintptr) {
				e = syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
				if e != nil {
					return
				}
				e = syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, 64*1024)
			})
			if err != nil {
				return err
			}
			if e != nil {
				return e
			}
			return nil
		},
	}
}
