// Unit tests for HL7 v2 decoding

package main

import (
	"strings"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testHl7Decoder HL7Decoder

func init() {
	testHl7Decoder.Initialize()
}

func TestHL7DecodeFile(t *testing.T) {
	handle, err := pcap.OpenOffline("testdata/HL7-ADT-UDI-PRT.pcap")
	require.NoError(t, err)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		app := packet.ApplicationLayer()
		if app == nil {
			continue // Ignore packets without an application layer
		}

		_, _, err := testHl7Decoder.DecodePayload(&app)
		assert.NoError(t, err)
	}
}

func appLayerFromString(s string) *gopacket.ApplicationLayer {
	bytes := []byte(s)
	appLayer := gopacket.ApplicationLayer(gopacket.Payload(bytes))
	return &appLayer
}

func TestHL7DecodeTooShort(t *testing.T) {
	appLayer := appLayerFromString(".")
	ident, _, err := testHl7Decoder.DecodePayload(appLayer)
	assert.Equal(t, ident, "")
	assert.Error(t, err)
}

func testHL7DecodeEmpty(s string, t *testing.T) {
	appLayer := appLayerFromString(s)
	ident, _, err := testHl7Decoder.DecodePayload(appLayer)
	assert.Equal(t, ident, "")
	assert.NoError(t, err)
}

func TestHL7DecodeEmpty1(t *testing.T) { testHL7DecodeEmpty("MSH|^~\\&", t) }
func TestHL7DecodeEmpty2(t *testing.T) { testHL7DecodeEmpty("MSH|^~\\&|", t) }

func identFromString(s string) (string, error) {
	appLayer := appLayerFromString(s)
	ident, _, err := testHl7Decoder.DecodePayload(appLayer)
	return ident, err
}

// Well-formed message header segment to be prepended to messages for testing
const okHL7Header = ("" +
	// Header and delimiter
	"MSH|^~\\&|" +

	// Envelope information
	"Sender|Sender Facility|" +
	"Receiver|Receiver Facility|" +

	// Timestamp (YYYYMMDDHHMM) + Security (blank)
	"201801131030||" +

	// Message type: ORU = observations & results
	"ORU^R01|" +

	// Control ID
	"CNTRL-12345|" +

	// Processing ID
	"P|" +

	// Version ID + segment delimiter (carriage return)
	"2.4\r")

func getNRecordString(nrec int) string {
	if nrec < 1 || nrec > 26 {
		return ""
	}
	alphas := make([]string, nrec)
	for i := 0; i < nrec; i++ {
		alphas[i] = string(byte('A' + i))
	}
	return strings.Join(alphas, "|")
}

func TestNRecordString(t *testing.T) {
	tcs := []struct {
		n int
		s string
	}{
		{-1, ""},
		{0, ""},
		{27, ""},
		{1, "A"},
		{3, "A|B|C"},
	}

	for _, tc := range tcs {
		assert.Equal(t, getNRecordString(tc.n), tc.s)
	}
}

func TestHL7IdentFromOBX18(t *testing.T) {
	str := okHL7Header + "OBX|" + getNRecordString(17) + "|Grospira Peach B+\r"
	parsed, err := identFromString(str)
	assert.NoError(t, err)
	assert.Equal(t, parsed, "Grospira Peach B+")
}

func BenchmarkHL7IdentFromOBX18(b *testing.B) {
	str := okHL7Header + "OBX|" + getNRecordString(17) + "|Grospira Peach B+\r"
	for i := 0; i < b.N; i++ {
		_, _ = identFromString(str)
	}
}

func TestHL7IdentFromPRT16(t *testing.T) {
	str := okHL7Header + "PRT|" + getNRecordString(15) + "|Grospira Peach B+\r"
	parsed, err := identFromString(str)
	assert.NoError(t, err)
	assert.Equal(t, parsed, "Grospira Peach B+")
}

func TestHL7IdentFromPrt16TrailingPipes(t *testing.T) {
	str := okHL7Header + "PRT|A|B|C|D|E|F|G|H|I|||||||Grospira Pluot C+||||\r"
	parsed, err := identFromString(str)
	assert.NoError(t, err)
	assert.Equal(t, parsed, "Grospira Pluot C+")
}

func BenchmarkHL7IdentFromPRT16(b *testing.B) {
	str := okHL7Header + "PRT|" + getNRecordString(15) + "|Grospira Peach B+\r"
	for i := 0; i < b.N; i++ {
		identFromString(str)
	}
}
