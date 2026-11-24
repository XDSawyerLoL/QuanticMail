//go:build !windows

package main

import "errors"

func runNative() error { return errors.New("Windows TPM provider required; no software fallback") }

func runNativeBroker() error {
	return errors.New("Windows TPM provider required; no software fallback")
}

func provisionPersistent(string) error {
	return errors.New("Windows TPM provider required; no software fallback")
}
func runPersistentBroker(string, string, string) error {
	return errors.New("Windows TPM provider required; no software fallback")
}

func cleanupPersistent(string, string, string) error {
	return errors.New("Windows TPM provider required; no software fallback")
}

func runGuardedBroker(string, string, string, string, string) error {
	return errors.New("Windows TPM provider required; no software fallback")
}
