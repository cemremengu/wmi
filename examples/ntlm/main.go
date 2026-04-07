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

type LoggedOnUser struct {
	Antecedent string
	Dependent  string
}

type Product struct {
	Name        string
	Version     string
	InstallDate string
}

type LogicalDiskPerf struct {
	Name             string
	DiskReadsPersec  uint64
	DiskWritesPersec uint64
}

func main() {
	host := "10.0.0.1" // IP address, hostname, or FQDN
	username := "username"
	password := "password"
	domain := "" // optional domain name

	start := time.Now()
	ctx := context.Background()

	client, err := wmi.DialNTLM(ctx, host, username, password, wmi.WithDomain(domain))
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	var osRows []OperatingSystem
	if err := client.CollectDecoded(
		ctx,
		"SELECT Caption, Version, LastBootUpTime FROM Win32_OperatingSystem",
		&osRows,
	); err != nil {
		log.Fatal(err)
	}
	fmt.Println("\n### Win32_OperatingSystem")
	for _, os := range osRows {
		fmt.Printf("  Caption=%s Version=%s LastBootUpTime=%s\n",
			os.Caption, os.Version, os.LastBootUpTime.Format(time.RFC3339))
	}

	var adapterRows []NetworkAdapter
	if err := client.CollectDecoded(
		ctx,
		"SELECT Name, MACAddress, Speed FROM Win32_NetworkAdapter",
		&adapterRows,
	); err != nil {
		log.Fatal(err)
	}
	fmt.Println("\n### Win32_NetworkAdapter")
	for _, adapter := range adapterRows {
		fmt.Printf("  Name=%s MAC=%s Speed=%d\n", adapter.Name, adapter.MACAddress, adapter.Speed)
	}

	var userRows []LoggedOnUser
	if err := client.CollectDecoded(
		ctx,
		"SELECT Antecedent, Dependent FROM Win32_LoggedOnUser",
		&userRows,
	); err != nil {
		log.Fatal(err)
	}
	fmt.Println("\n### Win32_LoggedOnUser")
	for _, user := range userRows {
		fmt.Printf("  Antecedent=%s Dependent=%s\n", user.Antecedent, user.Dependent)
	}

	var productRows []Product
	if err := client.CollectDecoded(
		ctx,
		"SELECT Name, Version, InstallDate FROM Win32_Product",
		&productRows,
	); err != nil {
		log.Fatal(err)
	}
	fmt.Println("\n### Win32_Product")
	for _, product := range productRows {
		fmt.Printf("  Name=%s Version=%s InstallDate=%s\n", product.Name, product.Version, product.InstallDate)
	}

	var diskRows []LogicalDiskPerf
	if err := client.CollectDecoded(
		ctx,
		"SELECT Name, DiskReadsPersec, DiskWritesPersec FROM Win32_PerfFormattedData_PerfDisk_LogicalDisk",
		&diskRows,
	); err != nil {
		log.Fatal(err)
	}
	fmt.Println("\n### Win32_PerfFormattedData_PerfDisk_LogicalDisk")
	for _, disk := range diskRows {
		fmt.Printf("  Name=%s DiskReadsPersec=%d DiskWritesPersec=%d\n",
			disk.Name, disk.DiskReadsPersec, disk.DiskWritesPersec)
	}

	fmt.Printf("done in %s\n", time.Since(start))
}
