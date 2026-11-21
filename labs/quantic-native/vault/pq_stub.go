//go:build !linux || !cgo || !pqopenssl

package main

import "errors"

type pqKey struct{}

var pqUnavailable = errors.New("native PQ backend unavailable; no fallback")

func pqGenerate(string) (pqKey, error)       { return pqKey{}, pqUnavailable }
func pqImport([]byte, string) (pqKey, error) { return pqKey{}, pqUnavailable }
func (pqKey) close()                         {}
func (pqKey) der(bool) ([]byte, error)       { return nil, pqUnavailable }
func (pqKey) dec([]byte) ([]byte, error)     { return nil, pqUnavailable }
func (pqKey) sign([]byte) ([]byte, error)    { return nil, pqUnavailable }
