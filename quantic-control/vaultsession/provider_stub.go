//go:build (!linux && !windows) || !cgo || !pqopenssl

package vaultsession

func providerAvailable()bool{return false}
func verifyMLDSA65(der,msg,sig []byte)bool{return false}
