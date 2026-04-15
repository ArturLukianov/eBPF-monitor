package correlator

import (
	"sync"
	"time"

	"github.com/ArturLukianov/eBPF-monitor/internal/helpers"
)

// This struct is used to identify started, but not accepted connections
type IncompleteConnection struct {
	SrcAddr uint32
	SrcPort uint16
	DstAddr uint32
	DstPort uint16
}

// This struct is used to store information from connect of incomplete connections
type PendingConnectionEntry struct {
	Timestamp   time.Time
	SrcCgroupID uint64
	SrcPID      uint32
}

// This struct holds info about accepted connections with data from connect
type ConnectionEntry struct {
	Timestamp   time.Time
	SrcCgroupID uint64
	SrcPID      uint32

	DstCgroupID uint64
	DstPID      uint32

	SrcAddr string
	SrcPort uint16
	DstAddr string
	DstPort uint16
}

type Correlator struct {
	mu      sync.Mutex
	pending map[IncompleteConnection]*PendingConnectionEntry
	timeout time.Duration
	output  chan ConnectionEntry
}

func New(timeout time.Duration) *Correlator {
	corr := &Correlator{
		timeout: timeout,
		pending: make(map[IncompleteConnection]*PendingConnectionEntry),
		output:  make(chan ConnectionEntry, 1024),
	}
	go corr.Cleanup()

	return corr
}

func (c *Correlator) Output() <-chan ConnectionEntry {
	return c.output
}

func (c *Correlator) Close() {
	if c.output != nil {
		close(c.output)
	}
}

// Loops and removes timed out connections
func (c *Correlator) Cleanup() {
	ticker := time.NewTicker(1 * time.Second)
	for range ticker.C {
		c.mu.Lock()
		now := time.Now()
		for key, entry := range c.pending {
			if now.Sub(entry.Timestamp) > c.timeout {
				delete(c.pending, key)
			}
		}
		c.mu.Unlock()
	}
}

// Handlers - called from event loop

func (c *Correlator) HandleConnect(srcAddr uint32, srcPort uint16,
	dstAddr uint32, dstPort uint16,
	cgroupID uint64, pid uint32) {

	conn := IncompleteConnection{
		SrcAddr: srcAddr,
		SrcPort: srcPort,
		DstAddr: dstAddr,
		DstPort: dstPort,
	}
	// fmt.Printf("Saving %s:%d -> %s:%d\n", helpers.BytesToIPv4(srcAddr), srcPort, helpers.BytesToIPv4(dstAddr), dstPort)

	c.mu.Lock()
	defer c.mu.Unlock()
	c.pending[conn] = &PendingConnectionEntry{
		Timestamp:   time.Now(),
		SrcCgroupID: cgroupID,
		SrcPID:      pid,
	}
}

// local - who receives the connection, remote - who initiates
func (c *Correlator) HandleAccept(localAddr uint32, localPort uint16,
	remoteAddr uint32, remotePort uint16,
	cgroupID uint64, pid uint32) {

	conn := IncompleteConnection{
		SrcAddr: remoteAddr,
		SrcPort: remotePort,
		DstAddr: localAddr,
		DstPort: localPort,
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.pending[conn]
	if !ok {
		// fmt.Printf("Not found %s:%d -> %s:%d\n", helpers.BytesToIPv4(remoteAddr), remotePort, helpers.BytesToIPv4(localAddr), localPort)
		return
	}

	connEntry := ConnectionEntry{
		Timestamp:   entry.Timestamp,
		SrcCgroupID: entry.SrcCgroupID,
		SrcPID:      entry.SrcPID,
		DstCgroupID: cgroupID,
		DstPID:      pid,

		SrcAddr: helpers.BytesToIPv4(remoteAddr),
		SrcPort: remotePort,
		DstAddr: helpers.BytesToIPv4(localAddr),
		DstPort: localPort,
	}

	c.output <- connEntry // TODO: handle if channel is full

	delete(c.pending, conn)
}
