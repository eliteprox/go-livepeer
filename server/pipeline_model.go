package server

import (
	"math/big"
	"strconv"
	"strings"

	"github.com/livepeer/go-livepeer/core"
	"github.com/livepeer/go-livepeer/net"
	"google.golang.org/protobuf/proto"
)

type pipelineModelPair struct {
	Pipeline string
	ModelID  string
}

// aiCapabilityPipelineSlugs maps AI capability enum values to NaaP pipeline slugs
// (matches pymthouse capabilityIdToPipelineId / python-gateway capability_pipeline_id).
var aiCapabilityPipelineSlugs = map[core.Capability]string{
	core.Capability_TextToImage:      "text-to-image",
	core.Capability_ImageToImage:     "image-to-image",
	core.Capability_ImageToVideo:     "image-to-video",
	core.Capability_Upscale:          "upscale",
	core.Capability_AudioToText:        "audio-to-text",
	core.Capability_SegmentAnything2: "segment-anything-2",
	core.Capability_LLM:              "llm",
	core.Capability_ImageToText:      "image-to-text",
	core.Capability_LiveVideoToVideo: "live-video-to-video",
	core.Capability_TextToSpeech:     "text-to-speech",
	core.Capability_BYOC:             "byoc",
}

func capabilityIdToPipelineSlug(capID uint32) string {
	return aiCapabilityPipelineSlugs[core.Capability(capID)]
}

func pipelineModelFromCapabilities(capsBytes []byte, jobType string) pipelineModelPair {
	if len(capsBytes) > 0 {
		var caps net.Capabilities
		if err := proto.Unmarshal(capsBytes, &caps); err == nil {
			if pair := pipelineModelFromNetCapabilities(&caps); pair.Pipeline != "" {
				return pair
			}
		}
	}
	if jobType == RemoteType_LiveVideoToVideo {
		return pipelineModelPair{Pipeline: PipelineLiveVideoToVideo}
	}
	return pipelineModelPair{}
}

func pipelineModelFromNetCapabilities(caps *net.Capabilities) pipelineModelPair {
	if caps == nil || caps.Constraints == nil || caps.Constraints.PerCapability == nil {
		return pipelineModelPair{}
	}
	for capID, constraints := range caps.Constraints.PerCapability {
		pipeline := capabilityIdToPipelineSlug(capID)
		if pipeline == "" || constraints == nil || len(constraints.Models) == 0 {
			continue
		}
		for modelID := range constraints.Models {
			modelID = strings.TrimSpace(modelID)
			if modelID == "" {
				continue
			}
			return pipelineModelPair{Pipeline: pipeline, ModelID: modelID}
		}
	}
	return pipelineModelPair{}
}

func buildRemotePaymentUsage(
	requestID string,
	fee *big.Rat,
	pixels int64,
	billableSecs float64,
	newBal *big.Rat,
	sequenceNumber int64,
	numTickets int64,
	pipelineModel pipelineModelPair,
) *RemotePaymentUsage {
	if fee == nil {
		return nil
	}
	usdSnapshot := computeFeeUsdSnapshot(fee)
	usage := &RemotePaymentUsage{
		RequestID:      requestID,
		ComputedFeeWei: fee.FloatString(0),
		Pixels:         strconv.FormatInt(pixels, 10),
		BillableSecs:   strconv.FormatFloat(billableSecs, 'f', -1, 64),
		SequenceNumber: sequenceNumber,
		NumTickets:     numTickets,
		Pipeline:       pipelineModel.Pipeline,
		ModelID:        pipelineModel.ModelID,
	}
	if newBal != nil {
		usage.SessionBalance = newBal.FloatString(0)
	}
	if usdSnapshot.ComputedFeeUsdMicros != "" {
		usage.ComputedFeeUsdMicros = usdSnapshot.ComputedFeeUsdMicros
		usage.EthUsdPrice = usdSnapshot.EthUsdPrice
		usage.EthUsdRoundID = usdSnapshot.EthUsdRoundID
		usage.EthUsdUpdatedAt = usdSnapshot.EthUsdUpdatedAt
	}
	return usage
}
