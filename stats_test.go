/*
Unit tests for stats functions.
*/
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestStatsString(t *testing.T) {
	// Stringify a stats object
	testIP := "10.0.0.1"
	testMAC := "11:22:33:44:55:66"

	stats := NewStats()
	stats.AddError(fmt.Errorf("No application layer"))
	stats.AddError(fmt.Errorf("No identifier"))
	stats.AddAsset(&Asset{
		testIP,
		"0000:0000:0000:0000:0000:FFFF:0A00:0001",
		"8000",
		"2575",
		testMAC,
		"Hospira Plum A+",
		"HL7",
		time.Time{},
		"ID0",
	})
	stats.AddUpload()
	stats.AddUploadError(fmt.Errorf("Error making request"))

	var resultStats Stats
	err := json.Unmarshal([]byte(stats.String()), &resultStats)

	assert.NoError(t, err)
	assert.Equal(t, resultStats.TotalPacketCount, stats.TotalPacketCount)
	assert.Equal(t, len(resultStats.IPv4Addresses), 1)
	assert.Equal(t, resultStats.IPv4Addresses[testIP], 1)
	assert.Equal(t, len(resultStats.IPv6Addresses), 1)
	assert.Equal(t, len(resultStats.Ports), 2)
	assert.Equal(t, len(resultStats.MACs), 1)
	assert.Equal(t, resultStats.MACs[testMAC], 1)
	assert.Equal(t, len(resultStats.Identifiers), 1)
	assert.Equal(t, len(resultStats.Provenances), 1)
	assert.Equal(t, len(resultStats.UploadResults), 2)
	assert.Equal(t, len(resultStats.Errors), 2)
}

func TestStatsSameID(t *testing.T) {
	// Two different devices with the same identifier, but different network data.
	stats := NewStats()
	stats.AddPacket()
	stats.AddAsset(&Asset{
		"10.0.0.1",
		"0000:0000:0000:0000:0000:FFFF:0A00:0001",
		"8000",
		"2575",
		"11:22:33:44:55:66",
		"Hospira Plum A+",
		"HL7",
		time.Time{},
		"ID0",
	})
	stats.AddPacket()
	stats.AddAsset(&Asset{
		"10.0.0.2",
		"0000:0000:0000:0000:0000:FFFF:0A00:0002",
		"8000",
		"2575",
		"11:22:33:44:55:67",
		"Hospira Plum A+",
		"HL7",
		time.Time{},
		"ID0",
	})

	assert.Equal(t, stats.TotalPacketCount, 2)
	assert.Equal(t, stats.Provenances["HL7"], 2)
	assert.Equal(t, len(stats.MACs), 2)
	assert.Equal(t, len(stats.IPv4Addresses), 2)
	assert.Equal(t, len(stats.IPv6Addresses), 2)
	assert.Equal(t, len(stats.Ports), 2)
	assert.Equal(t, len(stats.Identifiers), 1)
}

func TestStatsDifferentID(t *testing.T) {
	// Two different devices with different identifiers and network data
	stats := NewStats()
	stats.AddPacket()
	stats.AddAsset(&Asset{
		"10.0.0.1",
		"0000:0000:0000:0000:0000:FFFF:0A00:0001",
		"8000",
		"2575",
		"11:22:33:44:55:66",
		"Hospira Plum A+",
		"HL7",
		time.Time{},
		"ID0",
	})
	stats.AddPacket()
	stats.AddAsset(&Asset{
		"10.0.0.2",
		"0000:0000:0000:0000:0000:FFFF:0A00:0002",
		"9000",
		"2575",
		"11:22:33:44:55:67",
		"Alaris 8000",
		"HL7",
		time.Time{},
		"ID0",
	})

	assert.Equal(t, stats.TotalPacketCount, 2)
	assert.Equal(t, stats.Provenances["HL7"], 2)
	assert.Equal(t, len(stats.MACs), 2)
	assert.Equal(t, len(stats.IPv4Addresses), 2)
	assert.Equal(t, len(stats.IPv6Addresses), 2)
	assert.Equal(t, len(stats.Ports), 3)
	assert.Equal(t, len(stats.Identifiers), 2)
}

func TestStatsSameEverything(t *testing.T) {
	// Two observations from the same device.
	stats := NewStats()
	stats.AddPacket()
	stats.AddAsset(&Asset{
		"10.0.0.1",
		"0000:0000:0000:0000:0000:FFFF:0A00:0001",
		"8000",
		"2575",
		"11:22:33:44:55:66",
		"Hospira Plum A+",
		"HL7",
		time.Time{},
		"ID0",
	})
	stats.AddPacket()
	stats.AddAsset(&Asset{
		"10.0.0.1",
		"0000:0000:0000:0000:0000:FFFF:0A00:0001",
		"8000",
		"2575",
		"11:22:33:44:55:66",
		"Hospira Plum A+",
		"HL7",
		time.Time{},
		"ID0",
	})

	assert.Equal(t, stats.TotalPacketCount, 2)
	assert.Equal(t, stats.Provenances["HL7"], 2)
	assert.Equal(t, len(stats.MACs), 1)
	assert.Equal(t, len(stats.IPv4Addresses), 1)
	assert.Equal(t, len(stats.IPv6Addresses), 1)
	assert.Equal(t, len(stats.Ports), 2)
	assert.Equal(t, len(stats.Identifiers), 1)
}

func TestAddError(t *testing.T) {
	stats := NewStats()
	errStr := "A strange error string"
	stats.AddError(errors.New(errStr))

	assert.Equal(t, len(stats.Errors), 1)
	for key := range stats.Errors {
		assert.Equal(t, key, errStr)
	}
}
