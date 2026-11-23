//go:build !windows || !cgo || !pqopenssl

package main

func windowsVaultCLI(args []string)(bool,error){
 if len(args)>1&&(args[1]=="--provision-windows-controller-lab"||args[1]=="--provision-windows-pq-storage-lab"||args[1]=="--broker-windows-pq-quorum-lab"||args[1]=="--broker-windows-pq-quorum-gui-lab"||args[1]=="--windows-import-lab-file"||args[1]=="--windows-client-read-lab"||args[1]=="--windows-client-write-wire-lab"||args[1]=="--windows-scattering-create-lab"||args[1]=="--windows-scattering-config-lab"||args[1]=="--windows-scattering-guard-lab"){return true,portableRefusal}
 return false,nil
}
