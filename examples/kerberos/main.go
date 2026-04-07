package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/cemremengu/wmi"
)

type OperatingSystem struct {
	Caption        string
	Version        string
	LastBootUpTime time.Time
}

type NetworkAdapter struct {
	Name       string
	MACAddress string
	Speed      uint64
}

func main() {
	host := "host.example.com" // FQDN required for Kerberos
	username := "username"
	password := "password"

	start := time.Now()
	ctx := context.Background()

	// Kerberos tickets (TGT + TGS) are cached inside the connection
	// for its lifetime, so multiple queries reuse them automatically.
	client, err := wmi.DialKerberos(ctx, host, username, password, "EXAMPLE.COM",
		wmi.WithKDC("kdc.example.com", 88), // optional: point to a different KDC
	)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	var systems []OperatingSystem
	if err := client.CollectDecoded(
		ctx,
		"SELECT Caption, Version, LastBootUpTime FROM Win32_OperatingSystem",
		&systems,
	); err != nil {
		log.Fatal(err)
	}

	fmt.Println("\n### Win32_OperatingSystem")
	for _, os := range systems {
		fmt.Printf("  Caption=%s Version=%s LastBootUpTime=%s\n",
			os.Caption, os.Version, os.LastBootUpTime.Format(time.RFC3339))
	}

	var adapters []NetworkAdapter
	if err := client.CollectDecoded(
		ctx,
		"SELECT Name, MACAddress, Speed FROM Win32_NetworkAdapter",
		&adapters,
	); err != nil {
		log.Fatal(err)
	}

	fmt.Println("\n### Win32_NetworkAdapter")
	for _, adapter := range adapters {
		fmt.Printf("  Name=%s MAC=%s Speed=%d\n", adapter.Name, adapter.MACAddress, adapter.Speed)
	}

	fmt.Printf("done in %s\n", time.Since(start))
}
