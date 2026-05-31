package server

import (
	"math/big"
	"testing"

	"github.com/livepeer/go-livepeer/core"
	"github.com/livepeer/go-livepeer/net"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestCapabilityIdToPipelineSlug(t *testing.T) {
	require.Equal(t, "live-video-to-video", capabilityIdToPipelineSlug(uint32(core.Capability_LiveVideoToVideo)))
	require.Equal(t, "text-to-image", capabilityIdToPipelineSlug(uint32(core.Capability_TextToImage)))
	require.Equal(t, "", capabilityIdToPipelineSlug(uint32(core.Capability_H264)))
}

func TestPipelineModelFromNetCapabilities(t *testing.T) {
	caps := &net.Capabilities{
		Constraints: &net.Capabilities_Constraints{
			PerCapability: map[uint32]*net.Capabilities_CapabilityConstraints{
				uint32(core.Capability_LiveVideoToVideo): {
					Models: map[string]*net.Capabilities_CapabilityConstraints_ModelConstraint{
						"daydream-video": {},
					},
				},
			},
		},
	}
	pair := pipelineModelFromNetCapabilities(caps)
	require.Equal(t, "live-video-to-video", pair.Pipeline)
	require.Equal(t, "daydream-video", pair.ModelID)
}

func TestPipelineModelFromCapabilitiesBytes(t *testing.T) {
	caps := &net.Capabilities{
		Constraints: &net.Capabilities_Constraints{
			PerCapability: map[uint32]*net.Capabilities_CapabilityConstraints{
				uint32(core.Capability_TextToImage): {
					Models: map[string]*net.Capabilities_CapabilityConstraints_ModelConstraint{
						"stabilityai/sd-turbo": {},
					},
				},
			},
		},
	}
	blob, err := proto.Marshal(caps)
	require.NoError(t, err)

	pair := pipelineModelFromCapabilities(blob, "")
	require.Equal(t, "text-to-image", pair.Pipeline)
	require.Equal(t, "stabilityai/sd-turbo", pair.ModelID)
}

func TestPipelineModelFromCapabilitiesLv2vFallback(t *testing.T) {
	pair := pipelineModelFromCapabilities(nil, RemoteType_LiveVideoToVideo)
	require.Equal(t, PipelineLiveVideoToVideo, pair.Pipeline)
	require.Equal(t, "", pair.ModelID)
}

func TestBuildRemotePaymentUsage(t *testing.T) {
	fee := new(big.Rat).SetInt64(1_000_000_000_000_000)
	bal := new(big.Rat).SetInt64(500)
	usage := buildRemotePaymentUsage(
		"req-1",
		fee,
		42,
		1.5,
		bal,
		3,
		2,
		pipelineModelPair{Pipeline: "live-video-to-video", ModelID: "daydream-video"},
	)
	require.NotNil(t, usage)
	require.Equal(t, "req-1", usage.RequestID)
	require.Equal(t, "1000000000000000", usage.ComputedFeeWei)
	require.Equal(t, "42", usage.Pixels)
	require.Equal(t, "live-video-to-video", usage.Pipeline)
	require.Equal(t, "daydream-video", usage.ModelID)
	require.Equal(t, int64(3), usage.SequenceNumber)
	require.Equal(t, int64(2), usage.NumTickets)
}
