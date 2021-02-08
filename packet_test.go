package main

import (
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	// import layers to run its init function
	_ "github.com/google/gopacket/layers"

	"github.com/stretchr/testify/assert"
)

var testDecoders []PayloadDecoder

func init() {
	testDecoders = []PayloadDecoder{
		&HL7Decoder{},
		&DicomDecoder{},
	}
	for _, decoder := range testDecoders {
		err := decoder.Initialize()
		if err != nil {
			panic(err)
		}
	}
}

func TestPacketParseSimple(t *testing.T) {
	// Read a small pcap file and process the packets using handlePacket.  Use the
	// statistics generated at the end to check for correctness.

	setupLogging(false)

	// Initialize objects later used by handlePacket
	stats = *NewStats()
	apiClient := NewAPIClient("", "", "", 1, false)
	assetCSVWriter, err := NewAssetCSVWriter("")
	assert.NoError(t, err)

	// Read a pcap file
	handle, err := pcap.OpenOffline("testdata/HL7-ADT-UDI-PRT.pcap")
	assert.NoError(t, err)
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// Handle each packet from the pcap file
	var numPackets uint64
	for packet := range packetSource.Packets() {
		handlePacket(packet, testDecoders, apiClient, assetCSVWriter, nil)
		numPackets++
	}

	// Check stats
	nPrt16 := stats.Provenances["HL7 PRT-16"]
	assert.Equal(t, nPrt16, uint64(1))
	assert.Equal(t, stats.TotalPacketCount, numPackets)
}

// Create an empty Packet and ignore it
func TestSkipEmptyPacket(t *testing.T) {
	var data []byte
	pkt := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
	stats = *NewStats()
	handlePacket(pkt, testDecoders, nil, nil, nil)

	assert.Equal(t, stats.TotalPacketCount, uint64(1))
	assert.Equal(t, len(stats.Identifiers), 0)
}

// Create an empty Packet to measure the overhead of ignoring it
func BenchmarkSkipEmptyPacket(b *testing.B) {
	var data []byte
	pkt := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
	stats = *NewStats()
	for i := 0; i < b.N; i++ {
		handlePacket(pkt, testDecoders, nil, nil, nil)
	}
}
