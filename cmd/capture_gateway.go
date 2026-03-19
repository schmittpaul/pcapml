//go:build ebpf

package cmd

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/schmittpaul/pcapml/internal/pcapng"
)

const (
	gwCfgIncludeDNS = 1
)

func runCaptureGateway(args []string, outFile string, snapLen uint, wanIface string, includeDNS bool, noResolve bool) {
	if wanIface == "" {
		log.Fatal("gateway mode requires --wan <interface> (specify the WAN/uplink interface; traffic direction is inferred from it)")
	}

	// Verify interface exists
	if _, err := net.InterfaceByName(wanIface); err != nil {
		log.Fatalf("interface %q not found: %v", wanIface, err)
	}

	// Compute boot time offset for wall-clock timestamps
	bootOffset, err := getBootTimeOffset()
	if err != nil {
		log.Fatalf("failed to get boot time offset: %v", err)
	}

	// Load eBPF objects
	objs := gatewayObjects{}
	if err := loadGatewayObjects(&objs, nil); err != nil {
		log.Fatalf("failed to load gateway eBPF objects: %v", err)
	}
	defer objs.Close()

	resolve := !noResolve

	// Always include DNS in eBPF when resolution is enabled
	if includeDNS || resolve {
		if err := objs.GwConfig.Update(uint32(gwCfgIncludeDNS), uint32(1), ebpf.UpdateAny); err != nil {
			log.Fatalf("failed to set include_dns config: %v", err)
		}
	}

	// Initialize resolver
	var res *resolver
	if resolve {
		res = newResolver()
		log.Println("domain resolution enabled: labels will include dst=<domain> from DNS/SNI")
	}

	// Attach TC programs via tc(8).
	// Requires: opkg install tc-tiny (or tc-full) on OpenWrt.
	tcCleanup, err := attachTC(wanIface, objs.TcWanIngress, objs.TcWanEgress)
	if err != nil {
		log.Fatalf("failed to attach TC programs (is 'tc' installed? try: opkg install tc-tiny): %v", err)
	}
	defer tcCleanup()

	// Open ring buffer
	rd, err := ringbuf.NewReader(objs.GwEvents)
	if err != nil {
		log.Fatalf("failed to open ring buffer reader: %v", err)
	}
	defer rd.Close()

	// Open pcapng output
	writer, err := pcapng.NewWriter(outFile, pcapng.LinkTypeRawIPv4, uint32(snapLen))
	if err != nil {
		log.Fatalf("failed to create pcapng file: %v", err)
	}
	defer writer.Close()

	// Flow tracking for sample IDs (same 5-tuple normalization as host mode)
	type flowKey struct {
		ipA, ipB     [4]byte
		portA, portB uint16
		proto        uint8
	}
	sampleIDs := make(map[flowKey]uint64)
	nextSampleID := uint64(0)

	parseFlowKey := func(pkt []byte) (flowKey, bool) {
		var fk flowKey
		if len(pkt) < 20 {
			return fk, false
		}
		ihl := int(pkt[0]&0x0F) * 4
		if ihl < 20 || len(pkt) < ihl+4 {
			return fk, false
		}
		fk.proto = pkt[9]
		var srcIP, dstIP [4]byte
		copy(srcIP[:], pkt[12:16])
		copy(dstIP[:], pkt[16:20])
		srcPort := uint16(pkt[ihl])<<8 | uint16(pkt[ihl+1])
		dstPort := uint16(pkt[ihl+2])<<8 | uint16(pkt[ihl+3])
		if bytes.Compare(srcIP[:], dstIP[:]) > 0 ||
			(bytes.Equal(srcIP[:], dstIP[:]) && srcPort > dstPort) {
			fk.ipA, fk.ipB = dstIP, srcIP
			fk.portA, fk.portB = dstPort, srcPort
		} else {
			fk.ipA, fk.ipB = srcIP, dstIP
			fk.portA, fk.portB = srcPort, dstPort
		}
		return fk, true
	}

	getSampleID := func(fk flowKey) uint64 {
		if id, ok := sampleIDs[fk]; ok {
			return id
		}
		id := nextSampleID
		nextSampleID++
		sampleIDs[fk] = id
		return id
	}

	// Signal handling
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	var st captureStats

	go func() {
		<-sig
		log.Println("shutting down...")
		rd.Close()
	}()

	log.Printf("gateway mode: capturing on WAN interface %s (snap_len=%d)", wanIface, snapLen)
	if !includeDNS && !resolve {
		log.Println("DNS traffic (port 53) filtered out (use --include-dns to capture)")
	} else if !includeDNS && resolve {
		log.Println("DNS traffic (port 53) used for resolution but not written to output")
	}
	log.Println("press Ctrl+C to stop")

	// Main event loop
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				break
			}
			log.Printf("ring buffer read error: %v", err)
			continue
		}

		raw := record.RawSample
		st.eventsReceived++
		if len(raw) < gwHdrSize {
			st.packetsDropped++
			continue
		}

		var hdr gwPktEventHdr
		if err := binary.Read(bytes.NewReader(raw[:gwHdrSize]), binary.NativeEndian, &hdr); err != nil {
			st.packetsDropped++
			continue
		}

		capLen := hdr.CapLen
		if snapLen > 0 && capLen > uint32(snapLen) {
			capLen = uint32(snapLen)
		}
		dataEnd := gwHdrSize + int(capLen)
		if dataEnd > len(raw) {
			dataEnd = len(raw)
		}
		pktData := raw[gwHdrSize:dataEnd]

		// DNS/SNI resolution
		isDNS := false
		if res != nil {
			isDNS = res.processDNS(pktData)
			sni := extractSNI(pktData)
			if sni == "" {
				sni = extractQUICSNI(pktData)
			}
			if sni != "" && len(pktData) >= 20 {
				var dstIP [4]byte
				copy(dstIP[:], pktData[16:20])
				res.addMapping(dstIP, sni, 3600)
			}
		}

		if isDNS && !includeDNS {
			continue
		}

		fk, ok := parseFlowKey(pktData)
		if !ok {
			st.packetsDropped++
			continue
		}
		sid := getSampleID(fk)

		// Label format: s=<id>,dir=<wan2lan|lan2wan>[,dst=<domain>]
		dir := "wan2lan"
		if hdr.Direction == 1 {
			dir = "lan2wan"
		}
		comment := fmt.Sprintf("s=%d,dir=%s", sid, dir)
		if res != nil {
			if domain := res.resolveLabel(pktData); domain != "" {
				comment += ",dst=" + domain
			}
		}

		wallNs := int64(hdr.TimestampNs) + bootOffset
		wallUs := uint64(wallNs / 1000)

		if err := writer.WritePacket(wallUs, pktData, hdr.PktLen, comment); err != nil {
			log.Printf("write error: %v", err)
			st.packetsDropped++
			continue
		}
		st.packetsCapt++
	}

	fmt.Println()
	fmt.Println("--- pcapml gateway capture stats ---")
	fmt.Printf("interface:         %s\n", wanIface)
	fmt.Printf("events received:   %d\n", st.eventsReceived)
	fmt.Printf("packets captured:  %d\n", st.packetsCapt)
	fmt.Printf("packets dropped:   %d\n", st.packetsDropped)
	fmt.Printf("unique flows:      %d\n", len(sampleIDs))
	fmt.Printf("output: %s\n", outFile)


}

const bpfPinDir = "/sys/fs/bpf/pcapml_gw"

// attachTC pins BPF programs and attaches them via tc(8) + clsact qdisc.
// Returns a cleanup function.
func attachTC(iface string, ingress, egress *ebpf.Program) (func(), error) {
	if _, err := exec.LookPath("tc"); err != nil {
		return nil, fmt.Errorf("'tc' not found in PATH; install it (e.g. opkg install tc-tiny)")
	}

	// Pin programs to bpffs
	if err := os.MkdirAll(bpfPinDir, 0700); err != nil {
		return nil, fmt.Errorf("mkdir bpffs: %w", err)
	}
	inPin := filepath.Join(bpfPinDir, "ingress")
	egPin := filepath.Join(bpfPinDir, "egress")

	// Clean up stale pins
	os.Remove(inPin)
	os.Remove(egPin)

	if err := ingress.Pin(inPin); err != nil {
		return nil, fmt.Errorf("pin ingress: %w", err)
	}
	if err := egress.Pin(egPin); err != nil {
		return nil, fmt.Errorf("pin egress: %w", err)
	}

	cleanup := func() {
		exec.Command("tc", "filter", "del", "dev", iface, "ingress").Run()
		exec.Command("tc", "filter", "del", "dev", iface, "egress").Run()
		os.Remove(inPin)
		os.Remove(egPin)
		os.Remove(bpfPinDir)
	}

	// Add clsact qdisc (ignore error if already exists)
	exec.Command("tc", "qdisc", "add", "dev", iface, "clsact").CombinedOutput()

	// Remove any stale pcapml filters
	exec.Command("tc", "filter", "del", "dev", iface, "ingress").CombinedOutput()
	exec.Command("tc", "filter", "del", "dev", iface, "egress").CombinedOutput()

	// Attach BPF programs as direct-action filters
	if out, err := exec.Command("tc", "filter", "add", "dev", iface, "ingress",
		"bpf", "da", "object-pinned", inPin).CombinedOutput(); err != nil {
		cleanup()
		return nil, fmt.Errorf("tc filter add ingress: %s (%w)", string(out), err)
	}
	if out, err := exec.Command("tc", "filter", "add", "dev", iface, "egress",
		"bpf", "da", "object-pinned", egPin).CombinedOutput(); err != nil {
		cleanup()
		return nil, fmt.Errorf("tc filter add egress: %s (%w)", string(out), err)
	}

	log.Println("attached via tc (clsact + direct-action)")
	return cleanup, nil
}
