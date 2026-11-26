//go:build windows

package main

import (
	"errors"
	"net"
)

func kernelLoop(c Config, conn *net.UDPConn, dest *net.UDPAddr, queue, covers <-chan []byte) (Stats, error) {
	return Stats{}, errors.New("kernel-fq is Linux only; on Windows use --wait-mode native (V7.0 user-space pacing, no kernel TX scheduling)")
}

func kernelPreflight(c Config, dest *net.UDPAddr) error {
	return errors.New("kernel-fq unsupported on Windows; use native")
}
func kernelConfigure(conn *net.UDPConn) error { return errors.New("kernel-fq unsupported on Windows") }
