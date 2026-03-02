package core

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"sync"

	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/golang/glog"
	"github.com/livepeer/go-livepeer/trickle"
)

type ExternalCapability struct {
	Name          string `json:"name"`
	Description   string `json:"description"`
	Url           string `json:"url"`
	Capacity      int    `json:"capacity"`
	PricePerUnit  int64  `json:"price_per_unit"`
	PriceScaling  int64  `json:"price_scaling"`
	PriceCurrency string `json:"currency"`
	AuthToken     string `json:"token"`
	WorkerOptions []map[string]interface{} `json:"worker_options,omitempty"`
	price *AutoConvertedPrice

	Mu   sync.RWMutex
	Load int
}

type StreamInfo struct {
	StreamID   string
	Capability string

	//Orchestrator fields
	Sender         ethcommon.Address
	StreamRequest  []byte
	pubChannel     *trickle.TrickleLocalPublisher
	subChannel     *trickle.TrickleLocalPublisher
	controlChannel *trickle.TrickleLocalPublisher
	eventsChannel  *trickle.TrickleLocalPublisher
	dataChannel    *trickle.TrickleLocalPublisher
	//Stream fields
	JobParams    string
	StreamCtx    context.Context
	CancelStream context.CancelFunc

	cleanupOnce sync.Once
	sdm         sync.Mutex
}

func (sd *StreamInfo) IsActive() bool {
	sd.sdm.Lock()
	defer sd.sdm.Unlock()
	if sd.StreamCtx.Err() != nil {
		return false
	}

	if sd.controlChannel == nil {
		return false
	}

	return true
}

func (sd *StreamInfo) UpdateParams(params string) {
	sd.sdm.Lock()
	defer sd.sdm.Unlock()
	sd.JobParams = params
}

func (sd *StreamInfo) SetChannels(pub, sub, control, events, data *trickle.TrickleLocalPublisher) {
	sd.sdm.Lock()
	defer sd.sdm.Unlock()
	sd.pubChannel = pub
	sd.subChannel = sub
	sd.controlChannel = control
	sd.eventsChannel = events
	sd.dataChannel = data
}

func (sd *StreamInfo) cleanup() {
	sd.cleanupOnce.Do(func() {
		// Close all channels exactly once
		if sd.pubChannel != nil {
			sd.pubChannel.Close()
		}
		if sd.subChannel != nil {
			sd.subChannel.Close()
		}
		if sd.controlChannel != nil {
			sd.controlChannel.Close()
		}
		if sd.eventsChannel != nil {
			sd.eventsChannel.Close()
		}
		if sd.dataChannel != nil {
			sd.dataChannel.Close()
		}
	})
}

type ExternalCapabilities struct {
	capm         sync.Mutex
	Capabilities map[string]map[string]*ExternalCapability // outer key = capability name, inner key = runner URL
	Streams      map[string]*StreamInfo
}

func NewExternalCapabilities() *ExternalCapabilities {
	return &ExternalCapabilities{
		Capabilities: make(map[string]map[string]*ExternalCapability),
		Streams:      make(map[string]*StreamInfo)}
}

func (extCaps *ExternalCapabilities) AddStream(streamID string, capability string, streamReq []byte) (*StreamInfo, error) {
	extCaps.capm.Lock()
	defer extCaps.capm.Unlock()
	_, ok := extCaps.Streams[streamID]
	if ok {
		return nil, fmt.Errorf("stream already exists: %s", streamID)
	}

	//add to streams
	ctx, cancel := context.WithCancel(context.Background())
	stream := StreamInfo{
		StreamID:      streamID,
		Capability:    capability,
		StreamRequest: streamReq,
		StreamCtx:     ctx,
		CancelStream:  cancel,
	}
	extCaps.Streams[streamID] = &stream

	//clean up when stream ends
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		defer stream.cleanup()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// Periodically check if stream still exists in map
				extCaps.capm.Lock()
				_, exists := extCaps.Streams[streamID]
				extCaps.capm.Unlock()
				if !exists {
					return
				}
			}
		}
	}()

	return &stream, nil
}

func (extCaps *ExternalCapabilities) RemoveStream(streamID string) {
	extCaps.capm.Lock()
	defer extCaps.capm.Unlock()

	streamInfo, ok := extCaps.Streams[streamID]
	if ok {
		//confirm stream context is canceled before deleting
		if streamInfo.StreamCtx.Err() == nil {
			streamInfo.CancelStream()
		}
	}

	delete(extCaps.Streams, streamID)
}

func (extCaps *ExternalCapabilities) GetStream(streamID string) (*StreamInfo, bool) {
	extCaps.capm.Lock()
	defer extCaps.capm.Unlock()

	streamInfo, ok := extCaps.Streams[streamID]
	return streamInfo, ok
}

func (extCaps *ExternalCapabilities) StreamExists(streamID string) bool {
	extCaps.capm.Lock()
	defer extCaps.capm.Unlock()

	_, ok := extCaps.Streams[streamID]
	return ok
}

func (extCaps *ExternalCapabilities) RemoveCapability(extCap string) {
	extCaps.capm.Lock()
	defer extCaps.capm.Unlock()

	delete(extCaps.Capabilities, extCap)
}

// RemoveCapabilityRunner removes a single runner URL from a capability. If it is
// the last runner for that capability, the capability entry is also removed.
func (extCaps *ExternalCapabilities) RemoveCapabilityRunner(name, url string) {
	extCaps.capm.Lock()
	defer extCaps.capm.Unlock()

	runners, ok := extCaps.Capabilities[name]
	if !ok {
		return
	}
	delete(runners, url)
	if len(runners) == 0 {
		delete(extCaps.Capabilities, name)
	}
}

// GetCapability returns any one runner for the given capability name.
func (extCaps *ExternalCapabilities) GetCapability(extCap string) (*ExternalCapability, bool) {
	extCaps.capm.Lock()
	defer extCaps.capm.Unlock()
	runners, ok := extCaps.Capabilities[extCap]
	if !ok {
		return nil, false
	}
	for _, cap := range runners {
		return cap, true
	}
	return nil, false
}

// GetCapabilityRunner returns the specific runner entry for a capability name + URL pair.
func (extCaps *ExternalCapabilities) GetCapabilityRunner(name, url string) (*ExternalCapability, bool) {
	extCaps.capm.Lock()
	defer extCaps.capm.Unlock()
	runners, ok := extCaps.Capabilities[name]
	if !ok {
		return nil, false
	}
	cap, ok := runners[url]
	return cap, ok
}

// GetTotalCapacity returns the sum of available capacity across all runners for
// the given capability name. It holds capm for the entire read.
func (extCaps *ExternalCapabilities) GetTotalCapacity(name string) int64 {
	extCaps.capm.Lock()
	defer extCaps.capm.Unlock()
	runners, ok := extCaps.Capabilities[name]
	if !ok {
		return 0
	}
	var total int64
	for _, cap := range runners {
		if cap.Load < cap.Capacity {
			total += int64(cap.Capacity - cap.Load)
		}
	}
	return total
}

// GetFilteredCapacity returns the sum of available capacity across runners for
// the given capability name that also satisfy the options filter.
// If filter is empty, all runners are counted (equivalent to GetTotalCapacity).
func (extCaps *ExternalCapabilities) GetFilteredCapacity(name string, filter map[string]string) int64 {
	extCaps.capm.Lock()
	defer extCaps.capm.Unlock()
	runners, ok := extCaps.Capabilities[name]
	if !ok {
		return 0
	}
	var total int64
	for _, cap := range runners {
		if !AnyOptionsMatch(filter, cap.GetWorkerOptionsCopy()) {
			continue
		}
		if cap.Load < cap.Capacity {
			total += int64(cap.Capacity - cap.Load)
		}
	}
	return total
}

// ReserveCapacity atomically finds the first runner with available capacity and
// increments its Load. Returns an error if no runner has available capacity.
func (extCaps *ExternalCapabilities) ReserveCapacity(name string) error {
	extCaps.capm.Lock()
	defer extCaps.capm.Unlock()
	runners, ok := extCaps.Capabilities[name]
	if !ok {
		return fmt.Errorf("external capability not found: %s", name)
	}
	for _, cap := range runners {
		cap.Mu.Lock()
		if cap.Load < cap.Capacity {
			cap.Load++
			cap.Mu.Unlock()
			return nil
		}
		cap.Mu.Unlock()
	}
	return fmt.Errorf("no available capacity for capability: %s", name)
}

// FreeCapacity decrements the Load of the first runner with non-zero Load.
func (extCaps *ExternalCapabilities) FreeCapacity(name string) error {
	extCaps.capm.Lock()
	defer extCaps.capm.Unlock()
	runners, ok := extCaps.Capabilities[name]
	if !ok {
		return fmt.Errorf("external capability not found: %s", name)
	}
	for _, cap := range runners {
		cap.Mu.Lock()
		if cap.Load > 0 {
			cap.Load--
			cap.Mu.Unlock()
			return nil
		}
		cap.Mu.Unlock()
	}
	return fmt.Errorf("external capability not found: %s", name)
}

// SelectRunner returns the runner with the most available capacity for the given
// capability name that also satisfies the options filter. If filter is empty all
// runners are considered. Returns nil if no matching runner is found.
func (extCaps *ExternalCapabilities) SelectRunner(name string, filter map[string]string) *ExternalCapability {
	extCaps.capm.Lock()
	defer extCaps.capm.Unlock()
	runners, ok := extCaps.Capabilities[name]
	if !ok {
		return nil
	}
	var best *ExternalCapability
	var bestAvail int
	for _, cap := range runners {
		if !AnyOptionsMatch(filter, cap.GetWorkerOptionsCopy()) {
			continue
		}
		avail := cap.Capacity - cap.Load
		if avail > bestAvail {
			bestAvail = avail
			best = cap
		}
	}
	return best
}

// SelectAndReserveRunner atomically selects the runner with the most available
// capacity that satisfies the options filter, then increments its Load.
// If filter is empty all runners are considered.
// Returns an error if no matching runner with available capacity is found.
func (extCaps *ExternalCapabilities) SelectAndReserveRunner(name string, filter map[string]string) (*ExternalCapability, error) {
	extCaps.capm.Lock()
	defer extCaps.capm.Unlock()
	runners, ok := extCaps.Capabilities[name]
	if !ok {
		return nil, fmt.Errorf("no runners registered for capability %v", name)
	}
	var best *ExternalCapability
	var bestAvail int
	for _, cap := range runners {
		if !AnyOptionsMatch(filter, cap.GetWorkerOptionsCopy()) {
			continue
		}
		avail := cap.Capacity - cap.Load
		if avail > bestAvail {
			bestAvail = avail
			best = cap
		}
	}
	if best == nil || bestAvail <= 0 {
		return nil, fmt.Errorf("no available capacity for capability %v", name)
	}
	best.Mu.Lock()
	best.Load++
	best.Mu.Unlock()
	return best, nil
}

// GetCapabilityWorkerOptions returns the aggregated WorkerOptions from all runners
// registered for the given capability name.
func (extCaps *ExternalCapabilities) GetCapabilityWorkerOptions(extCap string) []map[string]interface{} {
	extCaps.capm.Lock()
	defer extCaps.capm.Unlock()

	runners, ok := extCaps.Capabilities[extCap]
	if !ok {
		return nil
	}
	var result []map[string]interface{}
	for _, cap := range runners {
		result = append(result, cap.GetWorkerOptionsCopy()...)
	}
	return result
}

// GetAllWorkerOptions returns the cached WorkerOptions from every registered runner
// across all capabilities, flattened into a single slice.
func (extCaps *ExternalCapabilities) GetAllWorkerOptions() []map[string]interface{} {
	extCaps.capm.Lock()
	defer extCaps.capm.Unlock()

	var result []map[string]interface{}
	for _, runners := range extCaps.Capabilities {
		for _, cap := range runners {
			result = append(result, cap.GetWorkerOptionsCopy()...)
		}
	}
	return result
}

// GetAllWorkerOptionsByCapability returns the cached WorkerOptions grouped by
// capability name. Each key is a capability name; the value is the merged
// options from all runners registered for that capability.
func (extCaps *ExternalCapabilities) GetAllWorkerOptionsByCapability() map[string][]map[string]interface{} {
	extCaps.capm.Lock()
	defer extCaps.capm.Unlock()

	result := make(map[string][]map[string]interface{})
	for capName, runners := range extCaps.Capabilities {
		for _, cap := range runners {
			result[capName] = append(result[capName], cap.GetWorkerOptionsCopy()...)
		}
	}
	return result
}

func (extCaps *ExternalCapabilities) RegisterCapability(extCapability string) (*ExternalCapability, error) {
	extCaps.capm.Lock()
	defer extCaps.capm.Unlock()
	if extCaps.Capabilities == nil {
		extCaps.Capabilities = make(map[string]map[string]*ExternalCapability)
	}
	var extCap ExternalCapability
	err := json.Unmarshal([]byte(extCapability), &extCap)
	if err != nil {
		return nil, err
	}

	//ensure PriceScaling is not 0
	if extCap.PriceScaling == 0 {
		extCap.PriceScaling = 1
	}
	extCap.price, err = NewAutoConvertedPrice(extCap.PriceCurrency, big.NewRat(extCap.PricePerUnit, extCap.PriceScaling), func(price *big.Rat) {
		glog.V(6).Infof("Capability %s price set to %s wei per compute unit", extCap.Name, price.FloatString(3))
	})

	if err != nil {
		panic(fmt.Errorf("error converting price: %v", err))
	}
	if nameMap, ok := extCaps.Capabilities[extCap.Name]; ok {
		if cap, ok := nameMap[extCap.Url]; ok {
			cap.Url = extCap.Url
			cap.Capacity = extCap.Capacity
			cap.price = extCap.price
			cap.AuthToken = extCap.AuthToken
			return cap, err
		}
	}

	if extCaps.Capabilities[extCap.Name] == nil {
		extCaps.Capabilities[extCap.Name] = make(map[string]*ExternalCapability)
	}
	extCaps.Capabilities[extCap.Name][extCap.Url] = &extCap

	return &extCap, err
}

func (extCap *ExternalCapability) GetPrice() *big.Rat {
	extCap.Mu.RLock()
	defer extCap.Mu.RUnlock()
	return extCap.price.Value()
}

func (extCap *ExternalCapability) SetWorkerOptions(options []map[string]interface{}) {
	extCap.Mu.Lock()
	defer extCap.Mu.Unlock()
	extCap.WorkerOptions = copyWorkerOptionsList(options)
}

func (extCap *ExternalCapability) GetWorkerOptionsCopy() []map[string]interface{} {
	extCap.Mu.RLock()
	defer extCap.Mu.RUnlock()
	return copyWorkerOptionsList(extCap.WorkerOptions)
}


func copyWorkerOptionsList(in []map[string]interface{}) []map[string]interface{} {
	if len(in) == 0 {
		return nil
	}
	out := make([]map[string]interface{}, len(in))
	for i, m := range in {
		mc := make(map[string]interface{}, len(m))
		for k, v := range m {
			mc[k] = v
		}
		out[i] = mc
	}
	return out
}

