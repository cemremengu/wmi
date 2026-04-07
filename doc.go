// Package wmi provides a pure-Go WMI client that communicates with Windows
// hosts over DCOM/RPC using either NTLM or Kerberos authentication.
//
// Connect with NTLM and query using the convenience API:
//
//	client, err := wmi.DialNTLM(ctx, "10.0.0.1", "username", "password")
//
//	if err != nil {
//		log.Fatal(err)
//	}
//	defer client.Close()
//
//	var systems []OperatingSystem
//	if err := client.CollectDecoded(ctx, "SELECT Caption, Version FROM Win32_OperatingSystem", &systems); err != nil {
//		log.Fatal(err)
//	}
package wmi
