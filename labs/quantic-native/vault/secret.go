package main

import "crypto/subtle"

func reverseSecret(z []byte) []byte {
	for i, j := 0, len(z)-1; i < j; i, j = i+1, j-1 {
		z[i], z[j] = z[j], z[i]
	}
	return z
}
func equalSecret(a, b []byte) bool { return subtle.ConstantTimeCompare(a, b) == 1 }
