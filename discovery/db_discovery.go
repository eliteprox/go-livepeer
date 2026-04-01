package discovery

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"math/big"
	gonet "net"
	"net/http"
	"net/url"
	"strings"
	"time"

	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/livepeer/go-livepeer/clog"
	"github.com/livepeer/go-livepeer/common"
	"github.com/livepeer/go-livepeer/core"
	"github.com/livepeer/go-livepeer/eth"
	lpTypes "github.com/livepeer/go-livepeer/eth/types"
	"github.com/livepeer/go-livepeer/monitor"
	"github.com/livepeer/go-livepeer/net"
	"github.com/livepeer/go-livepeer/pm"
	"github.com/livepeer/go-livepeer/server"

	"github.com/golang/glog"
)

// orchDrainHTTPClient is used for /events/drain calls to orchestrators.
// Orchestrators commonly use self-signed TLS certificates (the same pattern
// as the rest of the Livepeer gateway→orchestrator HTTP path), so certificate
// verification is intentionally skipped.
var orchDrainTLSConfig = &tls.Config{InsecureSkipVerify: true}
var orchDrainHTTPClient = &http.Client{
	Transport: &http.Transport{
		TLSClientConfig: orchDrainTLSConfig,
		DialTLSContext: func(ctx context.Context, network, addr string) (gonet.Conn, error) {
			tlsDialer := &tls.Dialer{Config: orchDrainTLSConfig}
			return tlsDialer.DialContext(ctx, network, addr)
		},
		ForceAttemptHTTP2: true,
	},
	Timeout: 5 * time.Second,
}

type ticketParamsValidator interface {
	ValidateTicketParams(ticketParams *pm.TicketParams) error
}

type DBOrchestratorPoolCache struct {
	store                 common.OrchestratorStore
	lpEth                 eth.LivepeerEthClient
	ticketParamsValidator ticketParamsValidator
	rm                    common.RoundsManager
	bcast                 common.Broadcaster
	orchBlacklist         []string
	discoveryTimeout      time.Duration
	ignoreCapacityCheck   bool
	node                  *core.LivepeerNode
	cursorStore           *EventCursorStore
}

func NewDBOrchestratorPoolCache(ctx context.Context, node *core.LivepeerNode, rm common.RoundsManager, orchBlacklist []string, discoveryTimeout time.Duration, liveAICapReportInterval time.Duration) (*DBOrchestratorPoolCache, error) {
	return DBOrchestratorPoolCacheConfig{
		Ctx:                     ctx,
		Node:                    node,
		RoundsManager:           rm,
		OrchBlacklist:           orchBlacklist,
		DiscoveryTimeout:        discoveryTimeout,
		LiveAICapReportInterval: liveAICapReportInterval,
	}.New()
}

type DBOrchestratorPoolCacheConfig struct {
	Ctx                     context.Context
	Node                    *core.LivepeerNode
	RoundsManager           common.RoundsManager
	OrchBlacklist           []string
	DiscoveryTimeout        time.Duration
	LiveAICapReportInterval time.Duration
	IgnoreCapacityCheck     bool
}

func (cfg DBOrchestratorPoolCacheConfig) New() (*DBOrchestratorPoolCache, error) {
	node := cfg.Node
	if node.Eth == nil {
		return nil, fmt.Errorf("could not create DBOrchestratorPoolCache: LivepeerEthClient is nil")
	}

	var cursorStore *EventCursorStore
	if node.Database != nil {
		cursorStore = NewEventCursorStore(node.Database.DBHandle())
	}

	dbo := &DBOrchestratorPoolCache{
		store:                 node.Database,
		lpEth:                 node.Eth,
		ticketParamsValidator: node.Sender,
		rm:                    cfg.RoundsManager,
		bcast:                 core.NewBroadcaster(node),
		orchBlacklist:         cfg.OrchBlacklist,
		discoveryTimeout:      cfg.DiscoveryTimeout,
		ignoreCapacityCheck:   cfg.IgnoreCapacityCheck,
		node:                  node,
		cursorStore:           cursorStore,
	}

	cacheOrchestrators := func() error {
		if err := dbo.cacheTranscoderPool(); err != nil {
			return err
		}

		if err := dbo.cacheOrchestratorStake(); err != nil {
			return err
		}

		if err := dbo.pollOrchestratorInfo(cfg.Ctx, cfg.LiveAICapReportInterval); err != nil {
			return err
		}
		return nil
	}

	if node.OrchestratorPool != nil {
		// We already have Orchestrator Pool, so we're fine caching in the background and not delay the startup
		go func() {
			err := cacheOrchestrators()
			if err != nil {
				clog.Errorf(context.Background(), "Error caching orchestrators: %v", err)
			}
		}()
	} else {
		// We don't have yet Orchestrator Pool, so we need to fetch it synchronously here
		return dbo, cacheOrchestrators()
	}

	return dbo, nil
}

func (dbo *DBOrchestratorPoolCache) getURLs() ([]*url.URL, error) {
	orchs, err := dbo.store.SelectOrchs(
		&common.DBOrchFilter{
			CurrentRound:   dbo.rm.LastInitializedRound(),
			UpdatedLastDay: true,
		},
	)
	if err != nil || len(orchs) <= 0 {
		return nil, err
	}

	var uris []*url.URL
	for _, orch := range orchs {
		if uri, err := url.Parse(orch.ServiceURI); err == nil {
			uris = append(uris, uri)
		}
	}
	return uris, nil
}

func (dbo *DBOrchestratorPoolCache) GetInfos() []common.OrchestratorLocalInfo {
	uris, _ := dbo.getURLs()
	infos := make([]common.OrchestratorLocalInfo, 0, len(uris))
	for _, uri := range uris {
		infos = append(infos, common.OrchestratorLocalInfo{URL: uri, Score: common.Score_Untrusted})
	}
	return infos
}

func (dbo *DBOrchestratorPoolCache) GetOrchestrators(ctx context.Context, numOrchestrators int, suspender common.Suspender, caps common.CapabilityComparator,
	scorePred common.ScorePred) (common.OrchestratorDescriptors, error) {

	uris, err := dbo.getURLs()
	if err != nil || len(uris) <= 0 {
		return nil, err
	}

	pred := func(info *net.OrchestratorInfo) bool {
		// Return early if no ETH address is specified
		if len(info.Address) == 0 {
			return false
		}

		if err := dbo.ticketParamsValidator.ValidateTicketParams(pmTicketParams(info.TicketParams)); err != nil {
			clog.V(common.DEBUG).Infof(ctx, "invalid ticket params orch=%v err=%q",
				info.GetTranscoder(),
				err,
			)
			return false
		}

		// check if O has a valid price
		price, err := common.RatPriceInfo(info.PriceInfo)
		if err != nil {
			clog.V(common.DEBUG).Infof(ctx, "invalid price info orch=%v err=%q", info.GetTranscoder(), err)
			return false
		}
		if price == nil {
			clog.V(common.DEBUG).Infof(ctx, "no price info received for orch=%v", info.GetTranscoder())
			return false
		}
		if price.Sign() < 0 {
			clog.V(common.DEBUG).Infof(ctx, "invalid price received for orch=%v price=%v", info.GetTranscoder(), price.RatString())
			return false
		}
		return true
	}

	orchPool, err := NewOrchestratorPoolWithConfig(OrchestratorPoolConfig{
		Broadcaster:         dbo.bcast,
		URIs:                uris,
		Pred:                pred,
		Score:               common.Score_Untrusted,
		OrchBlacklist:       dbo.orchBlacklist,
		DiscoveryTimeout:    dbo.discoveryTimeout,
		IgnoreCapacityCheck: dbo.ignoreCapacityCheck,
		ExtraNodes:          dbo.bcast.ExtraNodes(),
	})
	if err != nil {
		return nil, err
	}
	orchInfos, err := orchPool.GetOrchestrators(ctx, numOrchestrators, suspender, caps, scorePred)
	if err != nil || len(orchInfos) <= 0 {
		return nil, err
	}

	return orchInfos, nil
}

func (dbo *DBOrchestratorPoolCache) Size() int {
	count, _ := dbo.store.OrchCount(
		&common.DBOrchFilter{
			CurrentRound:   dbo.rm.LastInitializedRound(),
			UpdatedLastDay: true,
		},
	)
	return count
}

func (dbo *DBOrchestratorPoolCache) SizeWith(scorePred common.ScorePred) int {
	if scorePred(common.Score_Untrusted) {
		return dbo.Size()
	}
	return 0
}

func (dbo *DBOrchestratorPoolCache) cacheTranscoderPool() error {
	orchestrators, err := dbo.lpEth.TranscoderPool()
	if err != nil {
		return fmt.Errorf("Could not refresh DB list of orchestrators: %v", err)
	}

	for _, o := range orchestrators {
		if err := dbo.store.UpdateOrch(ethOrchToDBOrch(o)); err != nil {
			glog.Errorf("Unable to update orchestrator %v in DB: %v", o.Address.Hex(), err)
		}
	}

	return nil
}

func (dbo *DBOrchestratorPoolCache) cacheOrchestratorStake() error {
	orchs, err := dbo.store.SelectOrchs(
		&common.DBOrchFilter{
			CurrentRound: dbo.rm.LastInitializedRound(),
		},
	)
	if err != nil {
		return fmt.Errorf("could not retrieve orchestrators from DB: %v", err)
	}

	resc, errc := make(chan *common.DBOrch, len(orchs)), make(chan error, len(orchs))
	timeout := getOrchestratorTimeoutLoop // Needs to be same or longer than GRPCConnectTimeout in server/rpc.go
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	currentRound := dbo.rm.LastInitializedRound()

	getStake := func(o *common.DBOrch) {
		ep, err := dbo.lpEth.GetTranscoderEarningsPoolForRound(ethcommon.HexToAddress(o.EthereumAddr), currentRound)
		if err != nil {
			errc <- err
			return
		}

		stakeFp, err := common.BaseTokenAmountToFixed(ep.TotalStake)
		if err != nil {
			errc <- err
			return
		}
		o.Stake = stakeFp

		resc <- o
	}

	for _, o := range orchs {
		go getStake(o)
	}

	for i := 0; i < len(orchs); i++ {
		select {
		case res := <-resc:
			if err := dbo.store.UpdateOrch(res); err != nil {
				glog.Error("Error updating Orchestrator in DB: ", err)
			}
		case err := <-errc:
			glog.Errorln(err)
		case <-ctx.Done():
			glog.Info("Done fetching stake for orchestrators, context timeout")
			return nil
		}
	}

	return nil
}

func (dbo *DBOrchestratorPoolCache) pollOrchestratorInfo(ctx context.Context, liveAICapReportInterval time.Duration) error {
	if err := dbo.cacheOrchInfos(); err != nil {
		glog.Errorf("unable to poll orchestrator info: %v", err)
		return err
	}

	ticker := time.NewTicker(liveAICapReportInterval)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := dbo.cacheOrchInfos(); err != nil {
					glog.Errorf("unable to poll orchestrator info: %v", err)
				}
			}
		}
	}()

	return nil
}

func (dbo *DBOrchestratorPoolCache) cacheOrchInfos() error {
	//get list of orchestrators to poll info for.  If -orchAddr or -orchWebhookUrl is used it will
	//limit the set of orchestrators polled to those specified.
	var orchs []common.OrchestratorLocalInfo
	if dbo.node.OrchestratorPool != nil {
		orchs = dbo.node.OrchestratorPool.GetInfos()
		glog.Infof("Using orchestrator pool with %d orchestrators", len(orchs))
	} else {
		// Orchestrator pool set to use DBOrchestratorPoolCache after initial polling
		// of OrchestratorInfo runs.  Fall back to using DB orchestrators from the registered
		// orchestrators in the DB.
		dbOrchs, err := dbo.store.SelectOrchs(
			&common.DBOrchFilter{
				CurrentRound: dbo.rm.LastInitializedRound(),
			},
		)
		if err != nil {
			return fmt.Errorf("could not retrieve orchestrators from DB: %v", err)
		}

		for _, o := range dbOrchs {
			url, err := parseURI(o.ServiceURI)
			if err != nil {
				continue
			}
			orchs = append(orchs, common.OrchestratorLocalInfo{URL: url})
		}

		glog.Infof("Using DB orchestrator pool with %d orchestrators", len(orchs))
	}

	type orchPollingInfo struct {
		level    int
		orchInfo *net.OrchestratorInfo
		dbOrch   *common.DBOrch
	}

	nodesPerOrch := dbo.bcast.ExtraNodes()
	// Each base orchestrator can contribute itself plus up to nodesPerOrch first-level advertised nodes.
	maxOrchs := len(orchs) * (nodesPerOrch + 1)
	resc, errc := make(chan orchPollingInfo, maxOrchs), make(chan error, maxOrchs)
	timeout := getOrchestratorTimeoutLoop // Needs to be same or longer than GRPCConnectTimeout in server/rpc.go
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	getOrchInfoRPC := serverGetOrchInfo
	if pool, ok := dbo.node.OrchestratorPool.(*orchestratorPool); ok && pool.getOrchInfo != nil {
		getOrchInfoRPC = pool.getOrchInfo
	}

	getOrchInfo := func(orch common.OrchestratorLocalInfo, level int) {
		uri, err := parseURI(orch.URL.String())
		if err != nil {
			errc <- err
			return
		}
		// Do not connect if URI host is not set
		if uri.Host == "" {
			errc <- fmt.Errorf("skipping orch=%v, URI not set", orch.URL.String())
			return
		}
		info, err := getOrchInfoRPC(ctx, dbo.bcast, uri, server.GetOrchestratorInfoParams{
			IgnoreCapacityCheck: dbo.ignoreCapacityCheck,
		})
		if err != nil {
			errc <- err
			return
		}

		// Return early if no ETH address is specified
		if len(info.Address) == 0 {
			errc <- fmt.Errorf("missing ETH address orch=%v", info.GetTranscoder())
			return
		}

		price, err := common.RatPriceInfo(info.PriceInfo)
		if err != nil {
			errc <- fmt.Errorf("invalid price info orch=%v err=%q", info.GetTranscoder(), err)
			return
		}

		// PriceToFixed also checks if the input is nil, but this check tells us
		// which orch was missing price info
		if price == nil {
			errc <- fmt.Errorf("missing price info orch=%v", info.GetTranscoder())
			return
		}

		var dbOrch *common.DBOrch
		if info.GetTicketParams() != nil {
			dbOrch = &common.DBOrch{
				EthereumAddr: ethcommon.BytesToAddress(info.TicketParams.Recipient).Hex(),
			}

			dbOrch.PricePerPixel, err = common.PriceToFixed(price)
			if err != nil {
				errc <- err
				return
			}
		}

		resc <- orchPollingInfo{
			level:    level,
			orchInfo: info,
			dbOrch:   dbOrch,
		}
	}

	seen := make(map[string]bool, maxOrchs)
	numOrchs := 0
	startOrchLookup := func(orch common.OrchestratorLocalInfo, level int) {
		if orch.URL == nil {
			return
		}
		key := orch.URL.String()
		if key == "" || seen[key] {
			return
		}
		seen[key] = true
		numOrchs++
		go getOrchInfo(orch, level)
	}

	for _, orch := range orchs {
		startOrchLookup(orch, 0)
	}

	var orchNetworkCapabilities []*common.OrchNetworkCapabilities
	for i := 0; i < numOrchs; i++ {
		select {
		case res := <-resc:
			//add response to network capabilities
			orchNetworkCapabilities = append(orchNetworkCapabilities, orchInfoToOrchNetworkCapabilities(res.orchInfo))

			// discover newly advertised nodes. only recurse the first level.
			if res.level == 0 && len(res.orchInfo.GetNodes()) > 0 {
				for idx, inst := range res.orchInfo.GetNodes() {
					if idx >= nodesPerOrch {
						break
					}
					u, err := parseURI(inst)
					if err != nil {
						glog.Errorf("Invalid node URL orch=%v node=%v err=%q", res.orchInfo.GetTranscoder(), inst, err)
						continue
					}
					startOrchLookup(common.OrchestratorLocalInfo{URL: u, Score: common.Score_Untrusted}, res.level+1)
				}
			}

			//update db with response
			if res.dbOrch != nil {
				if err := dbo.store.UpdateOrch(res.dbOrch); err != nil {
					glog.Error("Error updating Orchestrator in DB: ", err)
				}
			}
		case err := <-errc:
			glog.Errorln(err)
		case <-ctx.Done():
			glog.Infof("Done fetching orch info for orchestrators, context timeout (fetched: %v out of %v)", i, numOrchs)
			i = numOrchs //exit loop
		}
	}

	// Save network capabilities in LivepeerNode
	dbo.node.UpdateNetworkCapabilities(orchNetworkCapabilities)

	// Report AI container capacity metrics
	reportAICapacityFromNetworkCapabilities(orchNetworkCapabilities)

	// Drain lifecycle events from each orchestrator (Mechanism 3 — cursor drain)
	if dbo.cursorStore != nil {
		for _, cap := range orchNetworkCapabilities {
			go dbo.drainOrchEvents(cap)
		}
	}

	return nil
}

// orchPendingEvent mirrors byoc.PendingEvent for decoding the /events/drain response.
type orchPendingEvent struct {
	ID        int64           `json:"id"`
	UUID      string          `json:"uuid"`
	Type      string          `json:"type"`
	Data      json.RawMessage `json:"data"`
	CreatedAt int64           `json:"created_at_ms"`
}

// drainOrchEvents fetches lifecycle events from an orchestrator's /events/drain endpoint
// since the last stored cursor, enriches them with orchestrator_info, and publishes to Kafka.
func (dbo *DBOrchestratorPoolCache) drainOrchEvents(cap *common.OrchNetworkCapabilities) {
	orchURL := cap.OrchURI
	if orchURL == "" {
		return
	}

	cursorMs, err := dbo.cursorStore.Get(orchURL)
	if err != nil {
		glog.V(4).Infof("discovery: drainOrchEvents failed to get cursor orch=%v err=%v", orchURL, err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	events, err := fetchOrchEventsSince(ctx, orchURL, cursorMs)
	if err != nil {
		if err != errOrchEventsDrainNotSupported {
			glog.V(4).Infof("discovery: drainOrchEvents failed to fetch events orch=%v err=%v", orchURL, err)
		}
		return
	}

	if len(events) == 0 {
		return
	}

	for _, e := range events {
		topic := lifecycleEventTopic(e.Type)
		if topic == "" {
			continue
		}
		var data map[string]interface{}
		if jsonErr := json.Unmarshal(e.Data, &data); jsonErr != nil {
			continue
		}
		data["orchestrator_info"] = map[string]string{
			"address": cap.Address,
			"url":     orchURL,
		}
		// Preserve the UUID assigned at orch insert time for consumer dedup.
		data["id"] = e.UUID
		monitor.SendQueueEventAsync(topic, data)
	}

	// Advance cursor to the created_at of the last event received.
	newCursor := events[len(events)-1].CreatedAt
	if setErr := dbo.cursorStore.Set(orchURL, newCursor); setErr != nil {
		glog.V(4).Infof("discovery: drainOrchEvents failed to set cursor orch=%v err=%v", orchURL, setErr)
	}
}

// errOrchEventsDrainNotSupported is returned when an orchestrator does not
// expose the /events/drain endpoint (404). Callers treat this as a silent
// no-op rather than a warning-level error.
var errOrchEventsDrainNotSupported = fmt.Errorf("events/drain not supported by orchestrator")

// fetchOrchEventsSince calls GET {orchURI}/events/drain?since_ms={sinceMs} and decodes the response.
// Returns errOrchEventsDrainNotSupported on 404 so callers can distinguish
// "old orchestrator" (expected) from real network/server errors.
func fetchOrchEventsSince(ctx context.Context, orchURI string, sinceMs int64) ([]orchPendingEvent, error) {
	u := strings.TrimRight(orchURI, "/") + fmt.Sprintf("/events/drain?since_ms=%d", sinceMs)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := orchDrainHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, errOrchEventsDrainNotSupported
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d from %s", resp.StatusCode, u)
	}
	var events []orchPendingEvent
	if err := json.NewDecoder(resp.Body).Decode(&events); err != nil {
		return nil, err
	}
	return events, nil
}

// lifecycleEventTopic maps orchestrator lifecycle event types to their Kafka topic names.
func lifecycleEventTopic(eventType string) string {
	switch eventType {
	case "worker_registered", "worker_unregistered", "worker_capacity_exhausted":
		return "worker_lifecycle"
	default:
		return ""
	}
}

func reportAICapacityFromNetworkCapabilities(orchNetworkCapabilities []*common.OrchNetworkCapabilities) {
	if !monitor.Enabled {
		return
	}
	// Build structured capacity data
	modelCapacities := make(map[string]*monitor.ModelAICapacities)

	for _, orchCap := range orchNetworkCapabilities {
		for _, price := range orchCap.CapabilitiesPrices {
			if price.Capability != uint32(core.Capability_LiveVideoToVideo) {
				continue
			}
			pricePerUnit := price.PricePerUnit
			pixelsPerUnit := price.PixelsPerUnit
			pricePerPixel := big.NewRat(pricePerUnit, pixelsPerUnit)
			monitor.LiveAIPricePerPixel(orchCap.OrchURI, pricePerPixel)
		}

		models := getModelCapsFromNetCapabilities(orchCap.Capabilities)

		for modelID, model := range models {
			if _, exists := modelCapacities[modelID]; !exists {
				modelCapacities[modelID] = &monitor.ModelAICapacities{
					ModelID:       modelID,
					Orchestrators: make(map[string]monitor.AIContainerCapacity),
				}
			}

			capacity := monitor.AIContainerCapacity{
				Idle:  int(model.Capacity),
				InUse: int(model.CapacityInUse),
			}
			modelCapacities[modelID].Orchestrators[orchCap.OrchURI] = capacity
		}
	}

	monitor.ReportAIContainerCapacity(modelCapacities)
}

func getModelCapsFromNetCapabilities(caps *net.Capabilities) map[string]*net.Capabilities_CapabilityConstraints_ModelConstraint {
	if caps == nil || caps.Constraints == nil || caps.Constraints.PerCapability == nil {
		return nil
	}
	liveAI, ok := caps.Constraints.PerCapability[uint32(core.Capability_LiveVideoToVideo)]
	if !ok {
		return nil
	}

	return liveAI.Models
}

func (dbo *DBOrchestratorPoolCache) Broadcaster() common.Broadcaster {
	return dbo.bcast
}

func parseURI(addr string) (*url.URL, error) {
	if !strings.HasPrefix(addr, "http") {
		addr = "https://" + addr
	}
	uri, err := url.ParseRequestURI(addr)
	if err != nil {
		return nil, fmt.Errorf("Could not parse orchestrator URI: %v", err)
	}
	return uri, nil
}

func ethOrchToDBOrch(orch *lpTypes.Transcoder) *common.DBOrch {
	if orch == nil {
		return nil
	}

	dbo := &common.DBOrch{
		ServiceURI:        orch.ServiceURI,
		EthereumAddr:      orch.Address.String(),
		ActivationRound:   common.ToInt64(orch.ActivationRound),
		DeactivationRound: common.ToInt64(orch.DeactivationRound),
	}

	return dbo
}

func pmTicketParams(params *net.TicketParams) *pm.TicketParams {
	if params == nil {
		return nil
	}

	return &pm.TicketParams{
		Recipient:         ethcommon.BytesToAddress(params.Recipient),
		FaceValue:         new(big.Int).SetBytes(params.FaceValue),
		WinProb:           new(big.Int).SetBytes(params.WinProb),
		RecipientRandHash: ethcommon.BytesToHash(params.RecipientRandHash),
		Seed:              new(big.Int).SetBytes(params.Seed),
		ExpirationBlock:   new(big.Int).SetBytes(params.ExpirationBlock),
		ExpirationParams: &pm.TicketExpirationParams{
			CreationRound:          params.ExpirationParams.GetCreationRound(),
			CreationRoundBlockHash: ethcommon.BytesToHash(params.ExpirationParams.GetCreationRoundBlockHash()),
		},
	}
}

func orchInfoToOrchNetworkCapabilities(info *net.OrchestratorInfo) *common.OrchNetworkCapabilities {
	var orch common.OrchNetworkCapabilities

	// add orch operating information if available
	if info != nil {
		orch.LocalAddress = ethcommon.BytesToAddress(info.GetAddress()).Hex()
		orch.OrchURI = info.GetTranscoder()
		orch.Capabilities = info.GetCapabilities()
		orch.PriceInfo = info.GetPriceInfo()
		orch.Hardware = info.GetHardware()
		orch.CapabilitiesPrices = info.GetCapabilitiesPrices()
		if info.GetTicketParams() != nil {
			orch.Address = string(ethcommon.BytesToAddress(info.TicketParams.Recipient).Hex())
		}
	}

	return &orch
}
