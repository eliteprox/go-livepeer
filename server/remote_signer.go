package server

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	ethcommon "github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/golang/glog"
	"github.com/golang/protobuf/proto"
	"github.com/livepeer/go-livepeer/ai/runner"
	"github.com/livepeer/go-livepeer/clog"
	"github.com/livepeer/go-livepeer/common"
	"github.com/livepeer/go-livepeer/core"
	lpcrypto "github.com/livepeer/go-livepeer/crypto"
	"github.com/livepeer/go-livepeer/monitor"
	"github.com/livepeer/go-livepeer/net"
	"github.com/livepeer/lpms/stream"
)

const HTTPStatusRefreshSession = 480
const HTTPStatusPriceExceeded = 481
const HTTPStatusNoTickets = 482
const RefreshSessionOrchestratorURLHeader = "Livepeer-Orchestrator-URL"
const RemoteType_Live = "live"
const RemoteType_LiveVideoToVideo = "lv2v"
const RemoteType_Fixed = "fixed"
const RemoteType_Usage = "usage"
const PipelineLiveVideoToVideo = "live-video-to-video"
const remoteSignerAuthIDHeader = "Signer-Auth-Id"

// SignOrchestratorInfo handles signing GetOrchestratorInfo requests for multiple orchestrators
func (ls *LivepeerServer) SignOrchestratorInfo(w http.ResponseWriter, r *http.Request) {
	ctx := clog.AddVal(r.Context(), "request_id", string(core.RandomManifestID()))
	remoteAddr := getRemoteAddr(r)
	clog.Info(ctx, "Orch info signature request", "ip", remoteAddr)

	// Get the broadcaster (signer)
	// In remote signer mode, we may not have an OrchestratorPool, so create a broadcaster directly
	gw := core.NewBroadcaster(ls.LivepeerNode)

	// Create empty params for signing
	params := GetOrchestratorInfoParams{}

	// Generate the request (this creates the signature)
	req, err := genOrchestratorReq(gw, params)
	if err != nil {
		clog.Errorf(ctx, "Failed to generate request: err=%q", err)
		respondJsonError(ctx, w, err, http.StatusInternalServerError)
		return
	}

	// Extract signature and format as hex
	var (
		signature = "0x" + hex.EncodeToString(req.Sig)
		address   = gw.Address().String()
	)

	results := map[string]string{
		"address":   address,
		"signature": signature,
	}

	// Return JSON response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(results)
}

// StartRemoteSignerServer starts the HTTP server for remote signer mode
func StartRemoteSignerServer(ls *LivepeerServer, bind string) error {
	// Register the remote signer endpoints
	ls.HTTPMux.Handle("POST /sign-orchestrator-info", http.HandlerFunc(ls.SignOrchestratorInfo))
	ls.HTTPMux.Handle("POST /generate-live-payment", http.HandlerFunc(ls.GenerateLivePayment))
	if ls.LivepeerNode.RemoteDiscovery {
		rdp := RemoteDiscoveryConfig{
			Pool:     ls.LivepeerNode.OrchestratorPool,
			Node:     ls.LivepeerNode,
			Interval: ls.LivepeerNode.LiveAICapReportInterval,
		}.New()
		ls.HTTPMux.Handle("GET /discover-orchestrators", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ls.GetOrchestrators(rdp, w, r)
		}))
	}

	// Start the HTTP server
	glog.Info("Starting Remote Signer server on ", bind)
	gw := core.NewBroadcaster(ls.LivepeerNode)
	sig, err := gw.Sign([]byte(fmt.Sprintf("%v", gw.Address().Hex())))
	if err != nil {
		return err
	}
	ls.LivepeerNode.InfoSig = sig
	srv := http.Server{
		Addr:        bind,
		Handler:     ls.HTTPMux,
		IdleTimeout: HTTPIdleTimeout,
	}
	return srv.ListenAndServe()
}

// HexBytes represents a byte slice that marshals/unmarshals as hex with 0x prefix
type HexBytes []byte

func (h HexBytes) MarshalJSON() ([]byte, error) {
	hexStr := "0x" + hex.EncodeToString(h)
	return json.Marshal(hexStr)
}

func (h *HexBytes) UnmarshalJSON(data []byte) error {
	var hexStr string
	if err := json.Unmarshal(data, &hexStr); err != nil {
		return err
	}

	// Remove 0x prefix if present
	if len(hexStr) >= 2 && hexStr[:2] == "0x" {
		hexStr = hexStr[2:]
	}

	// Decode hex string to bytes
	decoded, err := hex.DecodeString(hexStr)
	if err != nil {
		return fmt.Errorf("invalid hex string: %v", err)
	}

	*h = decoded
	return nil
}

// OrchInfoSigResponse represents the response from the remote signer
type OrchInfoSigResponse struct {
	Address   HexBytes `json:"address"`
	Signature HexBytes `json:"signature"`
}

// State required for remote ticket creation.
// Treated as an opaque, signed blob by the gateway.
type RemotePaymentState struct {
	StateID              string
	PMSessionID          string
	LastUpdate           time.Time
	OrchestratorAddress  ethcommon.Address
	App                  string
	AuthExpiry           int64
	SenderNonce          uint32
	Balance              string
	InitialPricePerUnit  int64
	InitialPixelsPerUnit int64
	Type                 string
	SequenceNumber       uint64
	AuthID               string
	QuoteID              string
	SellUnit             string
	UpchargeBps          int
}

type RemotePaymentStateSig struct {
	State []byte
	Sig   []byte
}

// RemotePaymentRequest is sent by the gateway to the remote signer to request a batch of tickets.
// TODO length limits for string / byte fields
type RemotePaymentRequest struct {
	// State is an opaque, signed blob previously returned by the remote signer.
	State RemotePaymentStateSig `json:"state,omitempty"`

	// protobuf bytes of net.OrchestratorInfo. Required
	Orchestrator []byte `json:"orchestrator"`

	// Set if an ID is needed to tie into orch accounting for a session. Optional
	ManifestID string

	// Application associated with the payment. Optional.
	App string `json:"app,omitempty"`

	// Number of pixels to generate a ticket for. Required if `type` is not set.
	InPixels int64 `json:"inPixels"`

	// Job type to automatically calculate payments. Valid values: `live`, `lv2v`, `fixed`. Optional.
	Type string `json:"type"`

	// Maximum acceptable price for this request. Optional.
	MaxPrice *runner.LiveRunnerPriceInfo `json:"maxPrice,omitempty"`

	// Orch-signed quote from the 402 challenge. Required for type=usage on first mint.
	Quote *runner.LiveRunnerQuote `json:"quote,omitempty"`

	// Orch-signed usage attestation. Required to settle type=usage.
	Attestation *runner.LiveRunnerUsageAttestation `json:"attestation,omitempty"`

	// Capabilities to include in the ticket. Optional; may be set for the lv2v job type.
	Capabilities []byte `json:"capabilities"`
}

// Returned by the remote signer and includes a new payment plus updated state.
type RemotePaymentResponse struct {
	Payment  string                `json:"payment"`
	SegCreds string                `json:"segCreds,omitempty"`
	State    RemotePaymentStateSig `json:"state"`
}

type generateLivePaymentWebhookBody struct {
	Headers map[string][]string `json:"headers"`
	State   *RemotePaymentState `json:"state,omitempty"`
}

type authResponse struct {
	// HTTP status that GenerateLivePayment should return to the caller.
	Status *int `json:"status,omitempty"`
	// Optional error message when Status is non-200.
	Reason string `json:"reason,omitempty"`
	// Unix timestamp (seconds) until which auth is considered valid.
	// Allows for skipping webhook callbacks until this time is exceeded.
	Expiry int64 `json:"expiry,omitempty"`
	// Optional opaque identifier.
	AuthID string `json:"auth_id,omitempty"`
	// Optional maximum acceptable challenge price.
	MaxPrice *runner.LiveRunnerPriceInfo `json:"maxPrice,omitempty"`
}

type remotePaymentPriceCeiling struct {
	source string
	price  *big.Rat
}

func parseRemotePaymentMaxPrice(maxPrice *runner.LiveRunnerPriceInfo, paymentType string) (*big.Rat, error) {
	if maxPrice == nil {
		return nil, nil
	}

	price, ok := new(big.Rat).SetString(strings.TrimSpace(maxPrice.Price.String()))
	if !ok || price.Sign() <= 0 {
		return nil, errors.New("maxPrice.price must be a positive decimal")
	}
	if strings.ToLower(strings.TrimSpace(maxPrice.Currency)) != "wei" {
		return nil, errors.New("maxPrice.currency must be wei")
	}

	var expectedUnit string
	switch paymentType {
	case RemoteType_Live:
		expectedUnit = "seconds"
	case RemoteType_LiveVideoToVideo:
		expectedUnit = "720p-pixel-seconds"
	case RemoteType_Fixed:
		expectedUnit = "fixed"
	case RemoteType_Usage:
		expectedUnit = runner.LiveRunnerPaymentUnitUsage
	default:
		return nil, errors.New("maxPrice requires payment type live, lv2v, fixed, or usage")
	}
	if unit := strings.ToLower(strings.TrimSpace(maxPrice.Unit)); unit != expectedUnit {
		return nil, fmt.Errorf("maxPrice.unit must be %s for payment type %s", expectedUnit, paymentType)
	}

	return price, nil
}

func checkRemotePaymentPrice(orchPrice *big.Rat, ceilings ...remotePaymentPriceCeiling) error {
	var effective remotePaymentPriceCeiling
	for _, ceiling := range ceilings {
		if ceiling.price == nil {
			continue
		}
		if effective.price == nil || ceiling.price.Cmp(effective.price) < 0 {
			effective = ceiling
		}
	}
	if effective.price != nil && orchPrice.Cmp(effective.price) > 0 {
		return fmt.Errorf("orchestrator price %v exceeds %s ceiling %v", orchPrice.FloatString(3), effective.source, effective.price.FloatString(3))
	}
	return nil
}

// Signs the serialized state with the remote signer's Ethereum key.
func signState(ls *LivepeerServer, stateBytes []byte) ([]byte, error) {
	if ls == nil || ls.LivepeerNode == nil || ls.LivepeerNode.Eth == nil {
		return nil, fmt.Errorf("ethereum client not configured for remote signer")
	}
	sig, err := ls.LivepeerNode.Eth.Sign(stateBytes)
	if err != nil {
		return nil, err
	}
	return sig, nil
}

// verifyStateSignature verifies that sig is a valid signature over stateBytes produced
// by the remote signer's Ethereum account.
func verifyStateSignature(ls *LivepeerServer, stateBytes []byte, sig []byte) error {
	if ls == nil || ls.LivepeerNode == nil || ls.LivepeerNode.Eth == nil {
		return fmt.Errorf("ethereum client not configured for remote signer")
	}
	addr := ls.LivepeerNode.Eth.Account().Address
	if !lpcrypto.VerifySig(addr, stateBytes, sig) {
		return fmt.Errorf("invalid state signature")
	}
	return nil
}

func (ls *LivepeerServer) authLivePayment(r *http.Request, state *RemotePaymentState) (int, *authResponse, error) {
	if ls == nil || ls.LivepeerNode == nil {
		return http.StatusOK, nil, nil
	}
	callbackURL := ls.LivepeerNode.RemoteSignerWebhookURL
	callbackHeaders := ls.LivepeerNode.RemoteSignerWebhookHeaders
	if callbackURL == nil {
		return http.StatusOK, nil, nil
	}
	if state != nil && state.AuthExpiry != 0 && time.Now().Unix() <= state.AuthExpiry {
		return http.StatusOK, nil, nil
	}

	body, err := json.Marshal(generateLivePaymentWebhookBody{Headers: r.Header, State: state})
	if err != nil {
		return http.StatusInternalServerError, nil, fmt.Errorf("failed to encode signer auth payload: %v", err)
	}
	webhookReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, callbackURL.String(), bytes.NewReader(body))
	if err != nil {
		return http.StatusInternalServerError, nil, fmt.Errorf("failed to build signer auth request: %v", err)
	}
	webhookReq.Header.Set("Content-Type", "application/json")
	for key, value := range callbackHeaders {
		webhookReq.Header.Set(key, value)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(webhookReq)
	if err != nil {
		return http.StatusInternalServerError, nil, fmt.Errorf("failed to call remote signer webhook: %v", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return http.StatusInternalServerError, nil, fmt.Errorf("failed to read signer auth response: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		// Error with webhook service or signer misconfiguration, so treat as internal
		return http.StatusInternalServerError, nil, fmt.Errorf("signer auth error status %d", resp.StatusCode)
	}

	var webhookResp authResponse
	if err := json.Unmarshal(respBody, &webhookResp); err != nil {
		return http.StatusInternalServerError, nil, fmt.Errorf("signer auth invalid response: %v", err)
	}
	if webhookResp.Status == nil || *webhookResp.Status <= 0 {
		return http.StatusInternalServerError, nil, errors.New("signer auth invalid status")
	}
	if *webhookResp.Status != http.StatusOK && webhookResp.Reason == "" {
		webhookResp.Reason = fmt.Sprintf("signer auth rejected request with status %d", *webhookResp.Status)
	}

	return *webhookResp.Status, &webhookResp, errors.New(webhookResp.Reason)
}

// GenerateLivePayment handles remote generation of a payment for live streams.
func (ls *LivepeerServer) GenerateLivePayment(w http.ResponseWriter, r *http.Request) {
	requestID := string(core.RandomManifestID())
	ctx := clog.AddVal(r.Context(), "request_id", requestID)
	remoteAddr := getRemoteAddr(r)
	clog.Info(ctx, "Live payment request", "ip", remoteAddr)

	// TODO avoid using the global Balances; keep balance changes request-local
	if ls.LivepeerNode.Balances == nil || ls.LivepeerNode.Sender == nil {
		err := fmt.Errorf("LivepeerNode missing balances or sender")
		respondJsonError(ctx, w, err, http.StatusInternalServerError)
		return
	}
	balances, sender := ls.LivepeerNode.Balances, ls.LivepeerNode.Sender

	var req RemotePaymentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		clog.Errorf(ctx, "Failed to decode RemotePaymentRequest err=%q", err)
		respondJsonError(ctx, w, err, http.StatusBadRequest)
		return
	}

	if len(req.Orchestrator) == 0 {
		err := fmt.Errorf("missing orchestrator")
		respondJsonError(ctx, w, err, http.StatusBadRequest)
		return
	}

	var oInfo net.OrchestratorInfo
	if err := proto.Unmarshal(req.Orchestrator, &oInfo); err != nil {
		clog.Errorf(ctx, "Failed to unmarshal orch info err=%q", err)
		respondJsonError(ctx, w, err, http.StatusBadRequest)
		return
	}
	priceInfo := oInfo.PriceInfo
	if priceInfo == nil || priceInfo.PricePerUnit == 0 || priceInfo.PixelsPerUnit == 0 {
		err := fmt.Errorf("missing or zero priceInfo")
		respondJsonError(ctx, w, err, http.StatusBadRequest)
		return
	}
	if oInfo.TicketParams == nil {
		err := fmt.Errorf("missing ticketParams in OrchestratorInfo")
		respondJsonError(ctx, w, err, http.StatusBadRequest)
		return
	}

	orchAddr := ethcommon.BytesToAddress(oInfo.Address)

	// Load or initialize state
	var (
		state *RemotePaymentState
		err   error
	)
	reqState, reqSig := req.State.State, req.State.Sig
	hasState := len(reqState) != 0 || len(reqSig) != 0
	if hasState {
		if err := verifyStateSignature(ls, reqState, reqSig); err != nil {
			err = errors.New("invalid sig")
			respondJsonError(ctx, w, err, http.StatusBadRequest)
			return
		}
		if err := json.Unmarshal(reqState, &state); err != nil {
			err = errors.New("invalid state")
			respondJsonError(ctx, w, err, http.StatusBadRequest)
			return
		}
		if state.OrchestratorAddress != orchAddr {
			err := fmt.Errorf("orchestratorAddress mismatch")
			respondJsonError(ctx, w, err, http.StatusBadRequest)
			return
		}
		if state.App != req.App {
			err := fmt.Errorf("app mismatch")
			respondJsonError(ctx, w, err, http.StatusBadRequest)
			return
		}
		if state.Type != "" && state.Type != req.Type {
			err := fmt.Errorf("job type mismatch")
			respondJsonError(ctx, w, err, http.StatusBadRequest)
			return
		}
		state.Type = req.Type
		state.SequenceNumber++
	} else {
		state = &RemotePaymentState{
			StateID:              string(core.RandomManifestID()),
			OrchestratorAddress:  orchAddr,
			App:                  req.App,
			InitialPricePerUnit:  priceInfo.PricePerUnit,
			InitialPixelsPerUnit: priceInfo.PixelsPerUnit,
			Type:                 req.Type,
		}
		if req.Type == RemoteType_Usage {
			if err := lockUsageQuote(state, req, priceInfo, orchAddr); err != nil {
				respondJsonError(ctx, w, err, http.StatusBadRequest)
				return
			}
		}
	}

	stateID := core.ManifestID(state.StateID)
	ctx = clog.AddVal(ctx, "state_id", state.StateID)
	ctx = clog.AddVal(ctx, "seqNo", fmt.Sprintf("%d", state.SequenceNumber))

	manifestID := req.ManifestID
	if manifestID == "" {
		if hasState {
			// Required for lv2v so stateful requests stay tied to the same id.
			err := errors.New("missing manifestID")
			respondJsonError(ctx, w, err, http.StatusBadRequest)
			return
		}
		manifestID = string(core.RandomManifestID())
	}
	ctx = clog.AddVal(ctx, "manifest_id", manifestID)

	streamParams := &core.StreamParameters{
		// Embedded within genSegCreds, may be used by orch for payment accounting
		ManifestID: core.ManifestID(manifestID),
	}
	if len(req.Capabilities) > 0 {
		var caps net.Capabilities
		if err := proto.Unmarshal(req.Capabilities, &caps); err != nil {
			clog.Errorf(ctx, "Failed to unmarshal capabilities err=%q", err)
			respondJsonError(ctx, w, err, http.StatusBadRequest)
			return
		}
		streamParams.Capabilities = core.CapabilitiesFromNetCapabilities(&caps)
	}

	pmParams := pmTicketParams(oInfo.TicketParams)
	if pmParams == nil {
		err := fmt.Errorf("failed to derive ticket params from OrchestratorInfo")
		respondJsonError(ctx, w, err, http.StatusBadRequest)
		return
	}
	sessionBalance := core.NewBalance(orchAddr, stateID, balances)

	// Restore balance
	oldBal := &big.Rat{}
	if state.Balance != "" {
		if _, ok := oldBal.SetString(state.Balance); ok {
			// Reset existing balance for this stream and apply saved value
			sessionBalance.Reserve()
			sessionBalance.Credit(oldBal)
		}
	}

	// Reset nonce if session has been refreshed.
	sessionID := pmParams.RecipientRandHash.Hex()
	nonce := state.SenderNonce
	if state.PMSessionID != sessionID {
		nonce = 0
	}

	initialPrice := &net.PriceInfo{
		PricePerUnit:  state.InitialPricePerUnit,
		PixelsPerUnit: state.InitialPixelsPerUnit,
	}

	sess := &BroadcastSession{
		Broadcaster:      core.NewBroadcaster(ls.LivepeerNode),
		Params:           streamParams,
		Sender:           sender,
		Balances:         balances,
		Balance:          sessionBalance,
		lock:             &sync.RWMutex{},
		OrchestratorInfo: &oInfo,
		CleanupSession:   sender.CleanupSession,
		PMSessionID:      sender.StartSessionWithNonce(*pmParams, nonce),
		InitialPrice:     initialPrice,
	}
	defer sess.CleanupSession(sess.PMSessionID)

	if should, err := shouldRefreshSession(ctx, sess); err == nil && should {
		err := errors.New("refresh session for remote signer")
		w.Header().Set(RefreshSessionOrchestratorURLHeader, oInfo.Transcoder)
		respondJsonError(ctx, w, err, HTTPStatusRefreshSession)
		return
	} else if err != nil {
		err = fmt.Errorf("remote signer could not check whether to refresh session: %w", err)
		respondJsonError(ctx, w, err, http.StatusBadRequest)
		return
	}

	pixels := int64(0)
	billableUnits := int64(req.InPixels)
	var usageUnits *big.Rat
	now := time.Now()
	lastUpdate := state.LastUpdate
	if lastUpdate.IsZero() {
		lastUpdate = now
	}
	billableSecs := now.Sub(lastUpdate).Seconds()
	if req.Type == RemoteType_LiveVideoToVideo {
		info := defaultSegInfo
		if billableSecs <= 0 {
			// preload with 60 seconds of data for LV2V
			billableSecs = (60 * time.Second).Seconds()
		}
		pixelsPerSec := float64(info.Height) * float64(info.Width) * float64(info.FPS)
		pixels = int64(pixelsPerSec * billableSecs) // pixels to charge for
		billableUnits = pixels
	} else if req.Type == RemoteType_Live {
		if billableSecs <= 0 {
			billableSecs = (10 * time.Second).Seconds()
		}
		billableUnits = int64(math.Ceil(billableSecs)) // seconds to charge for
	} else if req.Type == RemoteType_Fixed {
		billableUnits = 1
	} else if req.Type == RemoteType_Usage {
		if req.Attestation != nil {
			if err := verifyUsageAttestation(state, req.Attestation, orchAddr); err != nil {
				respondJsonError(ctx, w, err, http.StatusBadRequest)
				return
			}
			units, err := runner.ParsePositiveRat(req.Attestation.BillableUnits)
			if err != nil {
				respondJsonError(ctx, w, err, http.StatusBadRequest)
				return
			}
			usageUnits = units
			billableUnits = runner.CeilRatToInt64(units)
		} else {
			maxUnits := jsonNumberOrDefault(quoteMaxUnits(req.Quote, state), runner.DefaultUsageMaxUnits)
			units, err := runner.ParsePositiveRat(maxUnits)
			if err != nil {
				respondJsonError(ctx, w, fmt.Errorf("invalid quote max_units: %w", err), http.StatusBadRequest)
				return
			}
			usageUnits = units
			billableUnits = runner.CeilRatToInt64(units)
			if billableUnits <= 0 {
				billableUnits = 1
			}
		}
	} else if req.Type != "" {
		err = errors.New("invalid job type")
		respondJsonError(ctx, w, err, http.StatusBadRequest)
		return
	}
	if billableUnits <= 0 && req.Type != RemoteType_Usage {
		err = errors.New("missing billable unit or job type")
		respondJsonError(ctx, w, err, http.StatusBadRequest)
		return
	}

	// Validate orchestrator price against all ceilings available before the auth callback.
	orchPrice := new(big.Rat).SetFrac64(priceInfo.PricePerUnit, priceInfo.PixelsPerUnit)
	requestMaxPrice, err := parseRemotePaymentMaxPrice(req.MaxPrice, req.Type)
	if err != nil {
		respondJsonError(ctx, w, err, http.StatusBadRequest)
		return
	}
	var initialMaxPrice *big.Rat
	if hasState {
		if state.InitialPricePerUnit <= 0 || state.InitialPixelsPerUnit <= 0 {
			respondJsonError(ctx, w, errors.New("invalid initial price in state"), http.StatusBadRequest)
			return
		}
		initialMaxPrice = new(big.Rat).SetFrac64(state.InitialPricePerUnit, state.InitialPixelsPerUnit)
	}
	if err := checkRemotePaymentPrice(orchPrice,
		remotePaymentPriceCeiling{source: "configured maximum price", price: BroadcastCfg.GetCapabilitiesMaxPrice(streamParams.Capabilities)},
		remotePaymentPriceCeiling{source: "request maxPrice", price: requestMaxPrice},
		remotePaymentPriceCeiling{source: "initial session price", price: initialMaxPrice},
	); err != nil {
		clog.Warningf(ctx, "Rejecting payment request: %v", err)
		respondJsonError(ctx, w, err, HTTPStatusPriceExceeded)
		return
	}

	// Compute required fee using initial price
	fee := calculateFee(billableUnits, initialPrice)
	if usageUnits != nil {
		fee = calculateFeeRat(usageUnits, initialPrice)
	}

	// Create balance update
	balUpdate, err := newBalanceUpdate(sess, fee)
	if err != nil {
		err = fmt.Errorf("Failed to update balance: %w", err)
		respondJsonError(ctx, w, err, http.StatusInternalServerError)
		return
	}
	if balUpdate.NumTickets <= 0 {
		if req.Type != RemoteType_Usage || req.Attestation == nil {
			err = errors.New("no tickets")
			clog.Errorf(ctx, "No tickets")
			respondJsonError(ctx, w, err, HTTPStatusNoTickets)
			return
		}
	}
	if balUpdate.NumTickets > 100 {
		// Prevent both draining funds and perf issues
		ev, err := sender.EV(sess.PMSessionID)
		if err != nil {
			clog.Errorf(ctx, "Could not retrieve EV", err)
			ev = new(big.Rat)
		}
		err = fmt.Errorf("numTickets %d exceeds maximum of 100", balUpdate.NumTickets)
		clog.Errorf(ctx, "%v: if legitimate check EV config %s", err, ev.FloatString(3))
		respondJsonError(ctx, w, err, http.StatusBadRequest)
		return
	}
	balUpdate.Debit = fee
	balUpdate.Status = ReceivedChange

	payment := ""
	segCreds := ""
	if balUpdate.NumTickets > 0 {
		payment, err = genPayment(ctx, sess, balUpdate.NumTickets)
		if err != nil {
			clog.Errorf(ctx, "Could not create payment err=%q", err)
			if monitor.Enabled {
				monitor.PaymentCreateError(ctx)
			}
			statusCode := http.StatusInternalServerError
			if strings.Contains(err.Error(), "Orchestrator price has more than doubled") {
				statusCode = HTTPStatusPriceExceeded
			}
			respondJsonError(ctx, w, err, statusCode)
			return
		}
		creds, credErr := genSegCreds(sess, &stream.HLSSegment{}, nil, false)
		if credErr != nil {
			respondJsonError(ctx, w, credErr, http.StatusInternalServerError)
			return
		}
		segCreds = creds
	}

	// Complete balance update and set state to new balance
	completeBalanceUpdate(sess, balUpdate) // Updates sessionBalance internally
	newBal := sessionBalance.Balance()
	if newBal == nil {
		if req.Type == RemoteType_Usage && req.Attestation != nil {
			newBal = new(big.Rat)
		} else {
			err = errors.New("zero balance?")
			respondJsonError(ctx, w, err, http.StatusInternalServerError)
			return
		}
	}
	state.Balance = newBal.RatString()
	state.LastUpdate = now
	state.PMSessionID = sess.PMSessionID
	state.SenderNonce, err = sender.Nonce(sess.PMSessionID)
	if err != nil {
		err = fmt.Errorf("remote signer failed to retrieve nonce: %w", err)
		respondJsonError(ctx, w, err, http.StatusInternalServerError)
		return
	}

	callbackStatus, callbackResp, callbackErr := ls.authLivePayment(r, state)
	if callbackStatus != http.StatusOK {
		respondJsonError(ctx, w, callbackErr, callbackStatus)
		return
	}
	if callbackResp != nil {
		state.AuthExpiry = callbackResp.Expiry
		if callbackResp.MaxPrice != nil {
			authMaxPrice, err := parseRemotePaymentMaxPrice(callbackResp.MaxPrice, req.Type)
			if err != nil {
				respondJsonError(ctx, w, fmt.Errorf("signer auth invalid maxPrice: %w", err), http.StatusBadGateway)
				return
			}
			if err := checkRemotePaymentPrice(orchPrice, remotePaymentPriceCeiling{source: "auth webhook maxPrice", price: authMaxPrice}); err != nil {
				clog.Warningf(ctx, "Rejecting payment request: %v", err)
				respondJsonError(ctx, w, err, HTTPStatusPriceExceeded)
				return
			}
		}
	}
	authID := r.Header.Get(remoteSignerAuthIDHeader)
	if callbackResp != nil && callbackResp.AuthID != "" {
		authID = callbackResp.AuthID
	}
	if authID != "" && state.AuthID != authID {
		if state.AuthID != "" {
			clog.Warningf(ctx, "Remote signer auth ID changed oldAuthID=%s newAuthID=%s", state.AuthID, authID)
			respondJsonError(ctx, w, errors.New("remote signer auth ID changed"), http.StatusInternalServerError)
			return
		}
		state.AuthID = authID
	}
	ctx = clog.AddVal(ctx, "auth_id", state.AuthID)

	// Encode and sign updated state
	stateBytes, err := json.Marshal(state)
	if err != nil {
		clog.Errorf(ctx, "Failed to encode updated RemotePaymentState err=%q", err)
		respondJsonError(ctx, w, err, http.StatusInternalServerError)
		return
	}

	stateSig, err := signState(ls, stateBytes)
	if err != nil {
		clog.Errorf(ctx, "Could not sign state err=%q", err)
		respondJsonError(ctx, w, err, http.StatusInternalServerError)
		return
	}

	clog.Info(ctx, "Signed", "numTickets", balUpdate.NumTickets, "nonce", state.SenderNonce, "fee", fee.FloatString(0), "sessionId", oInfo.AuthToken.SessionId, "pmSessionId", sess.PMSessionID, "oldBalance", oldBal.FloatString(0), "newBalance", newBal.FloatString(0))

	if monitor.Enabled {
		sessionStatus := "continuing"
		if state.SequenceNumber == 0 {
			sessionStatus = "new"
		}
		pipeline := ""
		if req.Type == RemoteType_LiveVideoToVideo {
			pipeline = PipelineLiveVideoToVideo
		} else if req.Type == RemoteType_Live {
			pipeline = RemoteType_Live
		} else if req.Type == RemoteType_Fixed {
			pipeline = RemoteType_Fixed
		} else if req.Type == RemoteType_Usage {
			pipeline = RemoteType_Usage
		}
		emitKafka := req.Type != RemoteType_Usage || req.Attestation != nil
		if emitKafka {
			event := map[string]interface{}{
				"session_id":         state.StateID,
				"session_status":     sessionStatus,
				"app":                state.App,
				"pipeline":           pipeline,
				"request_id":         requestID,
				"orch_address":       orchAddr.Hex(),
				"orch_url":           oInfo.Transcoder,
				"manifest_id":        manifestID,
				"pm_session_id":      sess.PMSessionID,
				"current_time":       now.UTC(),
				"current_time_unix":  now.UTC().UnixMilli(),
				"previous_time":      lastUpdate.UTC(),
				"previous_time_unix": lastUpdate.UTC().UnixMilli(),
				"billable_secs":      billableSecs,
				"pixels":             pixels,
				"session_balance":    newBal.FloatString(0),
				"computed_fee":       fee.FloatString(0),
				"cost":               orchPrice.FloatString(10),
				"sequence_number":    state.SequenceNumber,
				"num_tickets":        balUpdate.NumTickets,
				"auth_id":            state.AuthID,
			}
			if req.Type == RemoteType_Usage {
				if usageUnits != nil {
					units, _ := usageUnits.Float64()
					event["billable_units"] = units
				}
				event["quote_id"] = state.QuoteID
				event["sell_unit"] = state.SellUnit
				event["upcharge_bps"] = state.UpchargeBps
			}
			monitor.SendQueueEventAsync("create_signed_ticket", event)
		}
	}

	// Return payment (tickets), creds and signed state
	resp := RemotePaymentResponse{
		Payment:  payment,
		SegCreds: segCreds,
		State:    RemotePaymentStateSig{State: stateBytes, Sig: stateSig},
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// Gateway helper that calls the remote signer service for the GetOrchestratorInfo signature
func GetOrchInfoSig(remoteSignerHost *url.URL, headers map[string]string) (*OrchInfoSigResponse, error) {

	url := remoteSignerHost.ResolveReference(&url.URL{Path: "/sign-orchestrator-info"})

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	req, err := http.NewRequest(http.MethodPost, url.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	// Make the request
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call remote signer: %w", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("remote signer returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var signerResp OrchInfoSigResponse
	if err := json.NewDecoder(resp.Body).Decode(&signerResp); err != nil {
		return nil, fmt.Errorf("failed to parse remote signer response: %w", err)
	}

	return &signerResp, nil
}

// discoveryResponse is intentionally typed. Do NOT add raw json.RawMessage blobs
// here or pass through arbitrary orchestrator /discovery fields; every exposed
// response field must be reviewed and modeled explicitly.
type discoveryResponse struct {
	Address      string                             `json:"address,omitempty"`
	Score        float32                            `json:"score,omitempty"`
	Capabilities []string                           `json:"capabilities,omitempty"`
	Runners      []runner.LiveRunnerDiscoveryRunner `json:"runners,omitempty"`
}

// GetOrchestrators returns the configured orchestrators in webhook-compatible format
func (ls *LivepeerServer) GetOrchestrators(pool *remoteDiscoveryPool, w http.ResponseWriter, r *http.Request) {
	ctx := clog.AddVal(r.Context(), "request_id", string(core.RandomManifestID()))
	remoteAddr := getRemoteAddr(r)
	clog.Info(ctx, "Get orchestrators request", "ip", remoteAddr)

	if pool == nil {
		respondJsonError(ctx, w, errors.New("no orchestrator pool configured"), http.StatusServiceUnavailable)
		return
	}

	if pool.Size() == 0 {
		respondJsonError(ctx, w, errors.New("cache empty"), http.StatusServiceUnavailable)
		return
	}

	caps := r.URL.Query()["caps"]
	filteredCaps := make([]string, 0, len(caps))
	for _, capability := range caps {
		if capability != "" {
			filteredCaps = append(filteredCaps, capability)
		}
	}

	infos := pool.Orchestrators(filteredCaps)
	resp := make([]discoveryResponse, 0, len(infos))
	for _, cached := range infos {
		resp = append(resp, discoveryResponse{
			Address:      cached.URL.String(),
			Score:        common.Score_Trusted, // Legacy go-livepeer webhook field.
			Capabilities: append([]string(nil), cached.Capabilities...),
			Runners:      append([]runner.LiveRunnerDiscoveryRunner(nil), cached.Runners...),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func lockUsageQuote(state *RemotePaymentState, req RemotePaymentRequest, priceInfo *net.PriceInfo, orchAddr ethcommon.Address) error {
	if req.Quote == nil {
		return errors.New("usage payment requires an orch-signed quote")
	}
	if err := verifyOrchSigned(orchAddr, req.Quote.OrchSig, req.Quote.SigningBytes); err != nil {
		return fmt.Errorf("invalid quote signature: %w", err)
	}
	if req.ManifestID != "" && req.Quote.ManifestID != req.ManifestID {
		return errors.New("quote manifest_id mismatch")
	}
	if req.Quote.ExpiresAt > 0 && time.Now().Unix() > req.Quote.ExpiresAt {
		return errors.New("quote expired")
	}
	if req.Quote.WeiPricePerUnit <= 0 || req.Quote.WeiPixelsPerUnit <= 0 {
		return errors.New("quote is missing converted sell price")
	}
	if priceInfo.GetPricePerUnit() != req.Quote.WeiPricePerUnit || priceInfo.GetPixelsPerUnit() != req.Quote.WeiPixelsPerUnit {
		return errors.New("quote sell price does not match orchestrator price")
	}
	state.InitialPricePerUnit = req.Quote.WeiPricePerUnit
	state.InitialPixelsPerUnit = req.Quote.WeiPixelsPerUnit
	state.QuoteID = req.Quote.QuoteID
	state.SellUnit = req.Quote.SellUnit
	state.UpchargeBps = req.Quote.UpchargeBps
	return nil
}

func verifyUsageAttestation(state *RemotePaymentState, att *runner.LiveRunnerUsageAttestation, orchAddr ethcommon.Address) error {
	if att == nil {
		return errors.New("missing usage attestation")
	}
	if state.QuoteID == "" || att.QuoteID != state.QuoteID {
		return errors.New("attestation quote_id does not match locked quote")
	}
	return verifyOrchSigned(orchAddr, att.OrchSig, att.SigningBytes)
}

func verifyOrchSigned(orchAddr ethcommon.Address, sigHex string, payload func() ([]byte, error)) error {
	raw, err := payload()
	if err != nil {
		return err
	}
	sig, err := decodeOrchSig(sigHex)
	if err != nil {
		return err
	}
	if !lpcrypto.VerifySig(orchAddr, ethcrypto.Keccak256(raw), sig) {
		return errors.New("invalid orchestrator signature")
	}
	return nil
}

func decodeOrchSig(sigHex string) ([]byte, error) {
	trimmed := strings.TrimSpace(sigHex)
	if strings.HasPrefix(trimmed, "0x") || strings.HasPrefix(trimmed, "0X") {
		trimmed = trimmed[2:]
	}
	if trimmed == "" {
		return nil, errors.New("missing signature")
	}
	return hex.DecodeString(trimmed)
}

func quoteMaxUnits(quote *runner.LiveRunnerQuote, state *RemotePaymentState) json.Number {
	if quote != nil && strings.TrimSpace(quote.MaxUnits.String()) != "" {
		return quote.MaxUnits
	}
	return json.Number(runner.DefaultUsageMaxUnits)
}

func jsonNumberOrDefault(value json.Number, fallback string) json.Number {
	if strings.TrimSpace(value.String()) == "" {
		return json.Number(fallback)
	}
	return value
}
