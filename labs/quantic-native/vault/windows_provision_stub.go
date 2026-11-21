//go:build !windows || !cgo || !pqopenssl

package main

func windowsVaultCLI(args []string)(bool,error){
 if len(args)>1&&args[1]=="--provision-windows-pq-storage-lab"{return true,portableRefusal}
 return false,nil
}
