package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/cemremengu/wmi"
)

type OperatingSystem struct {
	SerialNumber           string
	Version                string
	TotalVisibleMemorySize uint64
	FreePhysicalMemory     uint64
	LastBootUpTime         time.Time
}

type ComputerSystem struct {
	Name         string
	Domain       string
	Model        string
	Manufacturer string
}

type Processor struct {
	Name          string
	NumberOfCores uint32
	Architecture  uint16
	MaxClockSpeed uint32
}

type ProcessorMetrics struct {
	PercentUserTime      uint64
	PercentProcessorTime uint64
	PercentIdleTime      uint64
}

type Service struct {
	Name      string
	Caption   string
	State     string
	StartMode string
	ProcessID uint32
}

type LogicalDisk struct {
	Name        string
	Description string
	Size        uint64
	FreeSpace   uint64
}

type NetworkAdapter struct {
	Name           string
	Speed          uint64
	AdapterType    string
	InterfaceIndex uint32
	MACAddress     string
	Availability   uint16
}

type NetworkMetrics struct {
	Name                  string
	CurrentBandwidth      uint64
	BytesReceivedPersec   uint64
	BytesSentPersec       uint64
	PacketsReceivedPerSec uint64
	PacketsSentPerSec     uint64
}

type Process struct {
	ProcessID      uint32
	Name           string
	WorkingSetSize uint64
	ExecutionState uint16
}

type ProcessPerf struct {
	IDProcess            uint32
	PercentProcessorTime uint64
}

func main() {
	// wmi.EnableDebug()

	var (
		host     = flag.String("host", "", "target host")
		username = flag.String("username", "", "username")
		password = flag.String("password", "", "password")
		domain   = flag.String("domain", "", "domain (optional)")
	)
	flag.Parse()

	if *host == "" || *username == "" || *password == "" {
		flag.Usage()
		log.Fatal("host, username, and password are required")
	}

	ctx := context.Background()
	start := time.Now()

	client, err := wmi.DialNTLM(
		ctx,
		*host,
		*username,
		*password,
		wmi.WithDomain(*domain),
		wmi.WithConnectTimeout(5*time.Second))
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	osRows := loadOrLog[OperatingSystem](
		ctx,
		client,
		"os",
		`SELECT SerialNumber, Version, TotalVisibleMemorySize, FreePhysicalMemory, LastBootUpTime FROM Win32_OperatingSystem`,
	)
	sysRows := loadOrLog[ComputerSystem](
		ctx,
		client,
		"sys",
		`SELECT Name, Domain, Model, Manufacturer FROM Win32_ComputerSystem`,
	)
	cpuRows := loadOrLog[Processor](
		ctx,
		client,
		"cpu",
		`SELECT Name, NumberOfCores, Architecture, MaxClockSpeed FROM Win32_Processor`,
	)
	cpuMetricRows := loadOrLog[ProcessorMetrics](
		ctx,
		client,
		"cpu_metrics",
		`SELECT PercentUserTime, PercentProcessorTime, PercentIdleTime FROM Win32_PerfFormattedData_PerfOS_Processor WHERE Name = '_Total'`,
	)
	serviceRows := loadOrLog[Service](
		ctx,
		client,
		"service",
		`SELECT Name, Caption, State, StartMode, ProcessId FROM Win32_Service`,
	)
	diskRows := loadOrLog[LogicalDisk](
		ctx,
		client,
		"disk",
		`SELECT Name, Description, Size, FreeSpace FROM Win32_LogicalDisk WHERE Size > 0 AND DriveType = 3`,
	)
	netRows := loadOrLog[NetworkAdapter](
		ctx,
		client,
		"net",
		`SELECT Name, Speed, AdapterType, InterfaceIndex, MACAddress, Availability FROM Win32_NetworkAdapter`,
	)
	netMetricRows := loadOrLog[NetworkMetrics](
		ctx,
		client,
		"net_metrics",
		`SELECT Name, CurrentBandwidth, BytesReceivedPersec, BytesSentPersec, PacketsReceivedPerSec, PacketsSentPerSec FROM Win32_PerfFormattedData_Tcpip_NetworkInterface`,
	)
	processRows := loadOrLog[Process](
		ctx,
		client,
		"process",
		`SELECT ProcessId, Name, WorkingSetSize, ExecutionState FROM Win32_Process`,
	)
	processPerfRows := loadOrLog[ProcessPerf](
		ctx,
		client,
		"process_perf",
		`SELECT IDProcess, PercentProcessorTime FROM Win32_PerfFormattedData_PerfProc_Process`,
	)

	printNode(sysRows, osRows)
	printCPU(cpuRows, cpuMetricRows)
	printMemory(osRows)
	printDisks(diskRows)
	printServices(serviceRows)
	printNetwork(netRows, netMetricRows)
	printProcesses(processRows, processPerfRows, osRows, cpuRows)

	fmt.Printf("\ndone in %s\n", time.Since(start))
}

func loadOrLog[T any](ctx context.Context, client *wmi.Client, label, query string) []T {
	var rows []T
	err := client.CollectDecoded(ctx, query, &rows)
	if err != nil {
		log.Printf("query %s failed: %v", label, err)
		return nil
	}
	return rows
}

func printNode(sys []ComputerSystem, os []OperatingSystem) {
	fmt.Println("=== Node ===")
	if len(sys) > 0 {
		fmt.Printf("  Name:     %s\n", sys[0].Name)
		fmt.Printf("  Domain:   %s\n", sys[0].Domain)
		fmt.Printf("  Hardware: %s\n", sys[0].Model)
		fmt.Printf("  Vendor:   %s\n", sys[0].Manufacturer)
	}
	if len(os) > 0 {
		fmt.Printf("  OS:       %s\n", os[0].Version)
		fmt.Printf("  Boot:     %s\n", os[0].LastBootUpTime.Format(time.RFC3339))
		fmt.Printf("  Serial:   %s\n", os[0].SerialNumber)
	}
}

func printCPU(cpu []Processor, metrics []ProcessorMetrics) {
	if len(cpu) == 0 {
		return
	}
	fmt.Println("\n=== CPU ===")
	fmt.Printf("  Name:       %s\n", cpu[0].Name)
	fmt.Printf("  Arch:       %d\n", cpu[0].Architecture)
	fmt.Printf("  Max MHz:    %d\n", cpu[0].MaxClockSpeed)

	totalCores := uint32(0)
	for _, p := range cpu {
		totalCores += p.NumberOfCores
	}
	fmt.Printf("  Cores:      %d\n", totalCores)

	if len(metrics) > 0 {
		fmt.Printf("  %%Processor: %d\n", metrics[0].PercentProcessorTime)
		fmt.Printf("  %%User:      %d\n", metrics[0].PercentUserTime)
		fmt.Printf("  %%Idle:      %d\n", metrics[0].PercentIdleTime)
	}
}

func printMemory(os []OperatingSystem) {
	if len(os) == 0 {
		return
	}
	fmt.Println("\n=== Memory ===")
	fmt.Printf("  Total: %d bytes\n", os[0].TotalVisibleMemorySize*1024)
	fmt.Printf("  Free:  %d bytes\n", os[0].FreePhysicalMemory*1024)
}

func printDisks(disks []LogicalDisk) {
	if len(disks) == 0 {
		return
	}
	fmt.Println("\n=== Disks ===")
	for _, d := range disks {
		fmt.Printf("  %s  size=%d  free=%d  (%s)\n",
			d.Name, d.Size, d.FreeSpace, d.Description)
	}
}

func printServices(services []Service) {
	if len(services) == 0 {
		return
	}
	fmt.Printf("\n=== Services (%d) ===\n", len(services))
	for _, s := range services {
		fmt.Printf("  %-40s state=%-10s start=%s pid=%d\n",
			s.Name, s.State, s.StartMode, s.ProcessID)
	}
}

func printNetwork(adapters []NetworkAdapter, metrics []NetworkMetrics) {
	if len(adapters) == 0 {
		return
	}
	fmt.Println("\n=== Network ===")

	metricsByName := make(map[string]NetworkMetrics, len(metrics))
	for _, m := range metrics {
		metricsByName[m.Name] = m
	}

	for _, a := range adapters {
		m, ok := metricsByName[normalizePerfName(a.Name)]
		if !ok {
			continue
		}
		fmt.Printf("  %s\n", a.Name)
		fmt.Printf("    MAC:       %s\n", a.MACAddress)
		fmt.Printf("    Type:      %s\n", a.AdapterType)
		fmt.Printf("    RxBytes/s: %d\n", m.BytesReceivedPersec)
		fmt.Printf("    TxBytes/s: %d\n", m.BytesSentPersec)
		fmt.Printf("    RxPkts/s:  %d\n", m.PacketsReceivedPerSec)
		fmt.Printf("    TxPkts/s:  %d\n", m.PacketsSentPerSec)
	}
}

func printProcesses(procs []Process, perfs []ProcessPerf, os []OperatingSystem, cpu []Processor) {
	if len(procs) == 0 || len(os) == 0 {
		return
	}
	fmt.Printf("\n=== Processes (%d) ===\n", len(procs))

	totalMemBytes := os[0].TotalVisibleMemorySize * 1024

	totalCores := uint32(0)
	for _, p := range cpu {
		totalCores += p.NumberOfCores
	}
	if totalCores == 0 {
		totalCores = 1
	}

	perfByPID := make(map[uint32]ProcessPerf, len(perfs))
	for _, perf := range perfs {
		perfByPID[perf.IDProcess] = perf
	}

	for _, p := range procs {
		perf := perfByPID[p.ProcessID]
		cpuPct := float64(perf.PercentProcessorTime) / float64(totalCores)

		memPct := 0.0
		if totalMemBytes > 0 {
			memPct = float64(p.WorkingSetSize) / float64(totalMemBytes) * 100
		}

		fmt.Printf("  pid=%-6d  cpu=%5.2f%%  mem=%5.2f%%  %s\n",
			p.ProcessID, cpuPct, memPct, p.Name)
	}
}

func normalizePerfName(s string) string {
	return strings.ReplaceAll(s, "#", "_")
}
