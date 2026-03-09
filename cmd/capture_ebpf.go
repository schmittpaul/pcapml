//go:build ebpf

package cmd

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"

	"github.com/schmittpaul/pcapml/internal/pcapng"
)

const captureDescription = "Live capture with eBPF (exact process attribution, Linux only)"

const (
	maxCommLen = 16
	maxPktLen  = 1500
	hdrSize    = 8 + 4 + 4 + 4 + 4 + 1 + 3 + 16 // 44 bytes

	cfgSnapLen    = 0
	cfgUseAllow   = 1
	cfgUseDeny    = 2
	cfgIncludeDNS = 3
)

type pktEventHdr struct {
	TimestampNs uint64
	Pid         uint32
	Uid         uint32
	PktLen      uint32
	CapLen      uint32
	Direction   uint8
	Pad         [3]uint8
	Comm        [maxCommLen]byte
}

type captureStats struct {
	packetsCapt    uint64
	packetsDropped uint64
	packetsUnknown uint64
}

func runCapture(args []string) {
	fs := flag.NewFlagSet("capture", flag.ExitOnError)
	var (
		outFile    string
		allow      string
		deny       string
		snapLen    uint
		cgroupP    string
		includeDNS bool
		noResolve  bool
	)

	fs.StringVar(&outFile, "o", "capture.pcapng", "output pcapng file")
	fs.StringVar(&allow, "allow", "", "comma-separated allow list of process names")
	fs.StringVar(&deny, "deny", "", "comma-separated deny list of process names")
	fs.UintVar(&snapLen, "snap-len", maxPktLen, "max bytes to capture per packet")
	fs.StringVar(&cgroupP, "cgroup", "/sys/fs/cgroup", "cgroup v2 path to attach to")
	fs.BoolVar(&includeDNS, "include-dns", false, "include DNS (port 53) traffic in capture")
	fs.BoolVar(&noResolve, "no-resolve", false, "disable DNS/SNI domain resolution in labels")

	fs.Parse(args)

	if allow != "" && deny != "" {
		log.Fatal("cannot use both --allow and --deny")
	}

	// Compute boot time offset for wall-clock timestamps
	bootOffset, err := getBootTimeOffset()
	if err != nil {
		log.Fatalf("failed to get boot time offset: %v", err)
	}

	// Load eBPF objects
	objs := pcapmlObjects{}
	if err := loadPcapmlObjects(&objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Fatalf("verifier error:\n%+v", ve)
		}
		log.Fatalf("failed to load eBPF objects: %v", err)
	}
	defer objs.Close()

	// Populate config map
	if err := objs.PcapmlConfig.Update(uint32(cfgSnapLen), uint32(snapLen), ebpf.UpdateAny); err != nil {
		log.Fatalf("failed to set snap_len config: %v", err)
	}
	resolve := !noResolve

	// When resolution is enabled, we need DNS packets from eBPF for parsing,
	// even if the user doesn't want them in the output file.
	if includeDNS || resolve {
		if err := objs.PcapmlConfig.Update(uint32(cfgIncludeDNS), uint32(1), ebpf.UpdateAny); err != nil {
			log.Fatalf("failed to set include_dns config: %v", err)
		}
		if includeDNS {
			log.Println("DNS traffic (port 53) will be included in capture")
		}
	}

	// Initialize resolver for DNS/SNI domain resolution
	var res *resolver
	if resolve {
		res = newResolver()
		log.Println("domain resolution enabled: labels will include dst=<domain> from DNS/SNI")
	}

	// Populate allow/deny lists
	if allow != "" {
		if err := objs.PcapmlConfig.Update(uint32(cfgUseAllow), uint32(1), ebpf.UpdateAny); err != nil {
			log.Fatalf("failed to set allow config: %v", err)
		}
		for _, name := range strings.Split(allow, ",") {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			var key [maxCommLen]byte
			copy(key[:], name)
			if err := objs.CommAllow.Update(key, uint8(1), ebpf.UpdateAny); err != nil {
				log.Fatalf("failed to add %q to allow list: %v", name, err)
			}
			log.Printf("allow: %s", name)
		}
	}
	if deny != "" {
		if err := objs.PcapmlConfig.Update(uint32(cfgUseDeny), uint32(1), ebpf.UpdateAny); err != nil {
			log.Fatalf("failed to set deny config: %v", err)
		}
		for _, name := range strings.Split(deny, ",") {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			var key [maxCommLen]byte
			copy(key[:], name)
			if err := objs.CommDeny.Update(key, uint8(1), ebpf.UpdateAny); err != nil {
				log.Fatalf("failed to add %q to deny list: %v", name, err)
			}
			log.Printf("deny: %s", name)
		}
	}

	// Attach kprobes
	kpTcpConnect, err := link.Kprobe("tcp_connect", objs.KpTcpConnect, nil)
	if err != nil {
		log.Fatalf("failed to attach kprobe/tcp_connect: %v", err)
	}
	defer kpTcpConnect.Close()

	krpAccept, err := link.Kretprobe("inet_csk_accept", objs.KpInetCskAcceptRet, nil)
	if err != nil {
		log.Fatalf("failed to attach kretprobe/inet_csk_accept: %v", err)
	}
	defer krpAccept.Close()

	kpTcpClose, err := link.Kprobe("tcp_close", objs.KpTcpClose, nil)
	if err != nil {
		log.Fatalf("failed to attach kprobe/tcp_close: %v", err)
	}
	defer kpTcpClose.Close()

	kpUdpSend, err := link.Kprobe("udp_sendmsg", objs.KpUdpSendmsg, nil)
	if err != nil {
		log.Fatalf("failed to attach kprobe/udp_sendmsg: %v", err)
	}
	defer kpUdpSend.Close()

	kpUdpDestroy, err := link.Kprobe("udp_destroy_sock", objs.KpUdpDestroySock, nil)
	if err != nil {
		log.Fatalf("failed to attach kprobe/udp_destroy_sock: %v", err)
	}
	defer kpUdpDestroy.Close()

	// Attach cgroup_skb programs
	cgroupFd, err := os.Open(cgroupP)
	if err != nil {
		log.Fatalf("failed to open cgroup %s: %v", cgroupP, err)
	}
	defer cgroupFd.Close()

	cgEgress, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupP,
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: objs.CgroupSkbEgress,
	})
	if err != nil {
		log.Fatalf("failed to attach cgroup_skb/egress: %v", err)
	}
	defer cgEgress.Close()

	cgIngress, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupP,
		Attach:  ebpf.AttachCGroupInetIngress,
		Program: objs.CgroupSkbIngress,
	})
	if err != nil {
		log.Fatalf("failed to attach cgroup_skb/ingress: %v", err)
	}
	defer cgIngress.Close()

	// Open ring buffer reader
	rd, err := ringbuf.NewReader(objs.Events)
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

	// Sample ID tracking (per-flow grouping by normalized 5-tuple)
	type flowKey struct {
		ipA, ipB     [4]byte
		portA, portB uint16
		proto        uint8
	}
	sampleIDs := make(map[flowKey]uint64)
	flowComm := make(map[flowKey]string)
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
		// Normalize: smaller IP:port pair first so both directions match
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

	getSampleID := func(fk flowKey, comm string) uint64 {
		if id, ok := sampleIDs[fk]; ok {
			return id
		}
		id := nextSampleID
		nextSampleID++
		sampleIDs[fk] = id
		flowComm[fk] = comm
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

	log.Printf("capturing to %s (snap_len=%d, cgroup=%s)", outFile, snapLen, cgroupP)
	if allow != "" {
		log.Printf("allow list: %s", allow)
	}
	if deny != "" {
		log.Printf("deny list: %s", deny)
	}
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
		if len(raw) < hdrSize {
			st.packetsDropped++
			continue
		}

		var hdr pktEventHdr
		if err := binary.Read(bytes.NewReader(raw[:hdrSize]), binary.LittleEndian, &hdr); err != nil {
			st.packetsDropped++
			continue
		}

		dataEnd := hdrSize + int(hdr.CapLen)
		if dataEnd > len(raw) {
			dataEnd = len(raw)
		}
		pktData := raw[hdrSize:dataEnd]

		comm := strings.TrimRight(string(hdr.Comm[:]), "\x00")
		if comm == "" {
			comm = "_unknown"
			st.packetsUnknown++
		}

		// Resolution: process DNS responses and extract SNI
		isDNS := false
		if res != nil {
			isDNS = res.processDNS(pktData)

			// Extract SNI from TLS ClientHello
			if sni := extractSNI(pktData); sni != "" {
				// Map the destination IP to this SNI domain
				if len(pktData) >= 20 {
					var dstIP [4]byte
					copy(dstIP[:], pktData[16:20])
					res.addMapping(dstIP, sni, 3600) // 1hr TTL for SNI
				}
			}
		}

		// Skip writing DNS packets unless user explicitly wants them
		if isDNS && !includeDNS {
			continue
		}

		fk, ok := parseFlowKey(pktData)
		if !ok {
			st.packetsDropped++
			continue
		}
		sid := getSampleID(fk, comm)

		// Label format: sample_id,process,d=e|i[,dst=domain]
		dir := "e"
		if hdr.Direction == 0 {
			dir = "i"
		}
		comment := fmt.Sprintf("%d,%s,d=%s", sid, comm, dir)
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
	fmt.Println("--- pcapml capture stats ---")
	fmt.Printf("packets captured:  %d\n", st.packetsCapt)
	fmt.Printf("packets dropped:   %d\n", st.packetsDropped)
	fmt.Printf("unique flows:      %d\n", len(sampleIDs))
	if len(sampleIDs) > 0 {
		fmt.Println("sample ID mapping:")
		for fk, id := range sampleIDs {
			fmt.Printf("  %d -> %s (%d.%d.%d.%d:%d <-> %d.%d.%d.%d:%d proto=%d)\n",
				id, flowComm[fk],
				fk.ipA[0], fk.ipA[1], fk.ipA[2], fk.ipA[3], fk.portA,
				fk.ipB[0], fk.ipB[1], fk.ipB[2], fk.ipB[3], fk.portB,
				fk.proto)
		}
	}
	fmt.Printf("output: %s\n", outFile)
}

func getBootTimeOffset() (int64, error) {
	var bootTs unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &bootTs); err != nil {
		return 0, fmt.Errorf("clock_gettime BOOTTIME: %w", err)
	}
	bootNs := bootTs.Sec*1e9 + bootTs.Nsec
	wallNs := time.Now().UnixNano()
	return wallNs - bootNs, nil
}
