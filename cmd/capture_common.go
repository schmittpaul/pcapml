//go:build ebpf

package cmd

import (
	"fmt"
	"time"

	"golang.org/x/sys/unix"
)

const (
	maxCommLen = 16
	maxPktLen  = 1500

	// Host mode header: includes cgroup_id (56 bytes)
	hostHdrSize = 8 + 4 + 4 + 4 + 4 + 1 + 3 + 16 + 4 + 8 // 56 bytes

	// Gateway mode header: no cgroup_id (44 bytes)
	gwHdrSize = 8 + 4 + 4 + 4 + 4 + 1 + 3 + 16 // 44 bytes
)

// pktEventHdr is the host-mode event header (matches bpf/pcapml.bpf.c pkt_event).
type pktEventHdr struct {
	TimestampNs uint64
	Pid         uint32
	Uid         uint32
	PktLen      uint32
	CapLen      uint32
	Direction   uint8
	Pad         [3]uint8
	Comm        [maxCommLen]byte
	Pad2        uint32
	CgroupId    uint64
}

// gwPktEventHdr is the gateway-mode event header (matches bpf/gateway.bpf.c pkt_event).
type gwPktEventHdr struct {
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
	eventsReceived uint64
}

func getBootTimeOffset() (int64, error) {
	var bootTs unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &bootTs); err != nil {
		return 0, fmt.Errorf("clock_gettime BOOTTIME: %w", err)
	}
	bootNs := int64(bootTs.Sec)*1e9 + int64(bootTs.Nsec)
	wallNs := time.Now().UnixNano()
	return wallNs - bootNs, nil
}
