//go:build !linux

package main

import (
	"errors"
	"os"
)

var noPortableUI = errors.New("software persistent lab requires a validated local terminal and private filesystem; currently Linux only")

func checkPortableDirectory(string) error  { return noPortableUI }
func privatePortableFile(os.FileInfo) bool { return false }
func syncPortableDirectory(string) error   { return noPortableUI }
func localSecret(string) ([]byte, error)   { return nil, noPortableUI }
func localPortableApproval(string) bool    { return false }
