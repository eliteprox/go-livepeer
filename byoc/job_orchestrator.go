package byoc

//based on segment_rpc.go

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/livepeer/go-livepeer/clog"
	"github.com/livepeer/go-livepeer/common"
	"github.com/livepeer/go-livepeer/core"
	"github.com/livepeer/go-livepeer/net"

	ethcommon "github.com/ethereum/go-ethereum/common"

	"github.com/golang/glog"
	"github.com/pkg/errors"
)

// worker registers to Orchestrator
func (bs *BYOCOrchestratorServer) RegisterCapability() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		orch := bs.orch
		auth := r.Header.Get("Authorization")
		if auth != orch.TranscoderSecret() {
			http.Error(w, "invalid authorization", http.StatusBadRequest)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Error reading request body", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()
		remoteAddr := getRemoteAddr(r)

		// The request body contains the capability settings JSON with the token field
		extCapSettings := string(body)

		cap, err := orch.RegisterExternalCapability(extCapSettings)

		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			clog.Errorf(context.TODO(), "Error registering capability: %v", err)
			w.Write([]byte(fmt.Sprintf("Error registering capability: %v", err)))
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
		cap.SetWorkerOptions(cap.WorkerOptions)
		optsJSON, _ := json.Marshal(cap.WorkerOptions)
		hwJSON, _ := json.Marshal(cap.Hardware)
		clog.Infof(context.TODO(), "registered capability remoteAddr=%v capability=%v url=%v price=%v auth_token=%v worker_options=%v hardware=%v", remoteAddr, cap.Name, cap.Url, big.NewRat(cap.PricePerUnit, cap.PriceScaling), cap.AuthToken != "", string(optsJSON), string(hwJSON))
		if bs.pendingEvents != nil {
			bs.pendingEvents.Enqueue("worker_registered", map[string]interface{}{
				"capability":            cap.Name,
				"worker_url":            cap.Url,
				"price_per_unit":        cap.PricePerUnit,
				"price_scaling":         cap.PriceScaling,
				"worker_options_count":  len(cap.WorkerOptions),
				"worker_options":        cap.WorkerOptions,
			})
		}
	})
}

func (bs *BYOCOrchestratorServer) UnregisterCapability() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		orch := bs.orch
		auth := r.Header.Get("Authorization")
		if auth != orch.TranscoderSecret() {
			http.Error(w, "invalid authorization", http.StatusBadRequest)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Error reading request body", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()
		remoteAddr := getRemoteAddr(r)

		// Try JSON {name, url} format first; fall back to plain capability name string.
		var unregReq struct {
			Name string `json:"name"`
			Url  string `json:"url"`
		}
		capName := string(body)
		var removeErr error
		if jsonErr := json.Unmarshal(body, &unregReq); jsonErr == nil && unregReq.Name != "" {
			capName = unregReq.Name
			if unregReq.Url != "" {
				bs.node.ExternalCapabilities.RemoveCapabilityRunner(unregReq.Name, unregReq.Url)
			} else {
				removeErr = orch.RemoveExternalCapability(capName)
			}
		} else {
			removeErr = orch.RemoveExternalCapability(capName)
		}
		if removeErr != nil {
			clog.Errorf(context.TODO(), "Error removing capability: %v", removeErr)
			http.Error(w, fmt.Sprintf("Error removing capability: %v", removeErr), http.StatusBadRequest)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
		clog.Infof(context.TODO(), "removed capability remoteAddr=%v capability=%v", remoteAddr, capName)
		if bs.pendingEvents != nil {
			reason := "explicit_deregister"
			if unregReq.Url != "" {
				reason = "runner_replacement"
			}
			bs.pendingEvents.Enqueue("worker_unregistered", map[string]interface{}{
				"capability": capName,
				"worker_url": unregReq.Url,
				"reason":     reason,
			})
		}
	})
}

// GetWorkerOptions returns the cached WorkerOptions for all registered
// capabilities on this Orchestrator. Called by the Gateway's /process/options aggregator.
func (bso *BYOCOrchestratorServer) GetWorkerOptions() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		options := map[string][]map[string]interface{}{}
		if bso.node != nil && bso.node.ExternalCapabilities != nil {
			if all := bso.node.ExternalCapabilities.GetAllWorkerOptionsByCapability(); len(all) > 0 {
				options = all
			}
		}
		optsJSON, _ := json.Marshal(options)
		clog.Infof(r.Context(), "GetWorkerOptions remoteAddr=%v num_capabilities=%v options=%v", r.RemoteAddr, len(options), string(optsJSON))

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(options)
	})
}

func (bso *BYOCOrchestratorServer) GetJobToken() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if bso.node.NodeType != core.OrchestratorNode {
			http.Error(w, "request not allowed", http.StatusBadRequest)
			return
		}

		remoteAddr := getRemoteAddr(r)

		orch := bso.orch

		jobEthAddrHdr := r.Header.Get(jobEthAddressHdr)
		if jobEthAddrHdr == "" {
			glog.Infof("generate token failed, invalid request remoteAddr=%v", remoteAddr)
			http.Error(w, fmt.Sprintf("Must have eth address and signature on address in Livepeer-Eth-Address header"), http.StatusBadRequest)
			return
		}
		jobSenderAddr, err := bso.verifyTokenCreds(r.Context(), jobEthAddrHdr)
		if err != nil {
			glog.Infof("generate token failed, invalid request with bad eth address header remoteAddr=%v", remoteAddr)
			http.Error(w, fmt.Sprintf("Invalid eth address header "), http.StatusBadRequest)
			return
		}

		jobCapsHdr := r.Header.Get(jobCapabilityHdr)
		if jobCapsHdr == "" {
			glog.Infof("generate token failed, invalid request, no capabilities included remoteAddr=%v", remoteAddr)
			http.Error(w, fmt.Sprintf("Job capabilities not provided, must provide comma separated capabilities in Livepeer-Capability header"), http.StatusBadRequest)
			return
		}

		// Read optional options filter from query param. When present, the
		// returned AvailableCapacity will reflect only runners matching the
		// filter, avoiding wasted round-trips to orchestrators whose capacity
		// is held by runners that don't match the gateway's requirements.
		var optionsFilter map[string]string
		if filterStr := r.URL.Query().Get("options_filter"); filterStr != "" {
			_ = json.Unmarshal([]byte(filterStr), &optionsFilter)
		}

		w.Header().Set("Content-Type", "application/json")
		jobToken := JobToken{SenderAddress: nil, TicketParams: nil, Balance: 0, Price: nil}

		var capacity int64
		if bso.node != nil && bso.node.ExternalCapabilities != nil {
			capacity = bso.node.ExternalCapabilities.GetFilteredCapacity(jobCapsHdr, optionsFilter)
		} else {
			capacity = orch.CheckExternalCapabilityCapacity(jobCapsHdr)
		}

		senderAddr := ethcommon.HexToAddress(jobSenderAddr.Addr)

		jobPrice, err := orch.JobPriceInfo(senderAddr, jobCapsHdr)
		if err != nil {
			statusCode := http.StatusBadRequest
			if err.Error() == "insufficient sender reserve" {
				statusCode = http.StatusServiceUnavailable
			}
			glog.Errorf("could not get price err=%v", err.Error())
			http.Error(w, fmt.Sprintf("Could not get price err=%v", err.Error()), statusCode)
			return
		}
		ticketParams, err := orch.TicketParams(senderAddr, jobPrice)
		if err != nil {
			glog.Errorf("could not get ticket params err=%v", err.Error())
			http.Error(w, fmt.Sprintf("Could not get ticket params err=%v", err.Error()), http.StatusBadRequest)
			return
		}

		capBal := orch.Balance(senderAddr, core.ManifestID(jobCapsHdr))
		if capBal != nil {
			capBal, err = common.PriceToInt64(capBal)
			if err != nil {
				clog.Errorf(context.TODO(), "could not convert balance to int64 sender=%v capability=%v err=%v", senderAddr.Hex(), jobCapsHdr, err.Error())
				capBal = big.NewRat(0, 1)
			}
		} else {
			capBal = big.NewRat(0, 1)
		}
		//convert to int64. Note: returns with 000 more digits to allow for precision of 3 decimal places.
		capBalInt, err := common.PriceToFixed(capBal)
		if err != nil {
			glog.Errorf("could not convert balance to int64 sender=%v capability=%v err=%v", senderAddr.Hex(), jobCapsHdr, err.Error())
			capBalInt = 0
		} else {
			// Remove the last three digits from capBalInt
			capBalInt = capBalInt / 1000
		}

		var workerOptions []map[string]interface{}
		if bso.node != nil && bso.node.ExternalCapabilities != nil {
			workerOptions = bso.node.ExternalCapabilities.GetCapabilityWorkerOptions(jobCapsHdr)
		}

		jobToken = JobToken{
			SenderAddress:     jobSenderAddr,
			TicketParams:      ticketParams,
			Balance:           capBalInt,
			Price:             jobPrice,
			ServiceAddr:       orch.ServiceURI().String(),
			AvailableCapacity: capacity,
			WorkerOptions:     workerOptions,
		}

		//send response indicating compatible
		w.WriteHeader(http.StatusOK)

		json.NewEncoder(w).Encode(jobToken)
	})
}

func (bso *BYOCOrchestratorServer) ProcessJob() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		// Orchestrator node
		bso.processJob(ctx, w, r)
	})
}

func (bso *BYOCOrchestratorServer) processJob(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	remoteAddr := getRemoteAddr(r)
	ctx = clog.AddVal(ctx, "client_ip", remoteAddr)
	orch := bso.orch

	// Inject a per-request event accumulator so nested functions can
	// attach events that will be flushed into X-Livepeer-Events header.
	acc := newOrchEventAccumulator()
	ctx = withOrchEventAccumulator(ctx, acc)

	// flushEventsHeader writes accumulated events to the response header.
	// Must be called before any w.WriteHeader() / http.Error() call.
	flushEventsHeader := func() {
		if events := acc.Flush(); len(events) > 0 {
			if b, err := marshalOrchEvents(events); err == nil {
				w.Header().Set("X-Livepeer-Events", b)
			}
		}
	}

	// check the prompt sig from the request
	// confirms capacity available before processing payment info
	orchJob, err := bso.setupOrchJob(ctx, r, true)
	if err != nil {
		flushEventsHeader()
		if err == errNoCapabilityCapacity {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
		} else {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
		return
	}

	// job_orchestrator_received: job accepted, worker selected
	acc.Add("job_orchestrator_received", map[string]interface{}{
		"request_id":     orchJob.Req.ID,
		"sender_address": orchJob.Req.Sender,
		"capability":     orchJob.Req.Capability,
		"worker_url":     orchJob.Req.CapabilityUrl,
		"timeout_ms":     int64(orchJob.Req.Timeout) * 1000,
		"price_per_unit": orchJob.JobPrice.PricePerUnit,
		"pixels_per_unit": orchJob.JobPrice.PixelsPerUnit,
		"has_payment":    r.Header.Get(jobPaymentHeaderHdr) != "",
	})
	taskId := core.RandomManifestID()
	ctx = clog.AddVal(ctx, "job_id", orchJob.Req.ID)
	ctx = clog.AddVal(ctx, "worker_task_id", string(taskId))
	ctx = clog.AddVal(ctx, "capability", orchJob.Req.Capability)
	ctx = clog.AddVal(ctx, "sender", orchJob.Req.Sender)
	clog.V(common.SHORT).Infof(ctx, "Received job, sending for processing")

	// Read the original body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading request body", http.StatusInternalServerError)
		return
	}
	r.Body.Close()

	// Extract the worker resource route from the URL path
	// The prefix is "/process/request/"
	// if the request does not include the last / of the prefix no additional url path is added
	prefix := "/process/request/"
	workerResourceRoute := r.URL.Path
	if strings.HasPrefix(workerResourceRoute, prefix) {
		workerResourceRoute = workerResourceRoute[len(prefix):]
	}

	workerRoute := orchJob.Req.CapabilityUrl
	if workerResourceRoute != "" {
		workerRoute = workerRoute + "/" + workerResourceRoute
	}

	req, err := http.NewRequestWithContext(ctx, "POST", workerRoute, bytes.NewBuffer(body))
	if err != nil {
		clog.Errorf(ctx, "Unable to create request err=%v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// set the headers
	req.Header.Add("Content-Length", r.Header.Get("Content-Length"))
	req.Header.Add("Content-Type", r.Header.Get("Content-Type"))

	// Add Authorization header if auth token is set for this capability
	if nameMap, ok := bso.node.ExternalCapabilities.Capabilities[orchJob.Req.Capability]; ok {
		if extCap, ok := nameMap[orchJob.Req.CapabilityUrl]; ok && extCap.AuthToken != "" {
			req.Header.Add("Authorization", "Bearer "+extCap.AuthToken)
		}
	}

	start := time.Now()

	// chargeAndRecord calls chargeForCompute and appends a payment_compute_charged
	// event to the per-request accumulator.
	chargeAndRecord := func(onError bool) {
		bso.chargeForCompute(start, orchJob.JobPrice, orchJob.Sender, orchJob.Req.Capability)
		elapsed := int64(math.Ceil(time.Since(start).Seconds()))
		var balAfterInt int64
		if balRat := bso.getPaymentBalance(orchJob.Sender, orchJob.Req.Capability); balRat != nil {
			if fixed, ferr := common.PriceToFixed(balRat); ferr == nil {
				balAfterInt = fixed / 1000
			}
		}
		acc.Add("payment_compute_charged", map[string]interface{}{
			"request_id":      orchJob.Req.ID,
			"sender_address":  orchJob.Req.Sender,
			"capability":      orchJob.Req.Capability,
			"elapsed_seconds": elapsed,
			"price_per_unit":  orchJob.JobPrice.PricePerUnit,
			"total_charged":   orchJob.JobPrice.PricePerUnit * elapsed,
			"balance_after":   balAfterInt,
			"on_error":        onError,
		})
	}

	resp, err := sendReqWithTimeout(req, time.Duration(orchJob.Req.Timeout)*time.Second)
	if err != nil {
		clog.Errorf(ctx, "job not able to be processed err=%v ", err.Error())
		//if the request failed with connection error, remove the capability
		//exclude deadline exceeded or context canceled errors does not indicate a fatal error all the time
		if err != context.DeadlineExceeded && !strings.Contains(err.Error(), "context canceled") {
			clog.Errorf(ctx, "removing capability %v due to error %v", orchJob.Req.Capability, err.Error())
			bso.orch.RemoveExternalCapability(orchJob.Req.Capability)
		}

		acc.Add("job_orchestrator_worker_result", map[string]interface{}{
			"request_id":      orchJob.Req.ID,
			"capability":      orchJob.Req.Capability,
			"worker_url":      orchJob.Req.CapabilityUrl,
			"http_status":     0,
			"success":         false,
			"duration_ms":     time.Since(start).Milliseconds(),
			"completed_at":    time.Now().UnixMilli(),
			"charged_compute": true,
			"retryable":       true,
			"error":           err.Error(),
		})
		chargeAndRecord(true)
		w.Header().Set(jobPaymentBalanceHdr, bso.getPaymentBalance(orchJob.Sender, orchJob.Req.Capability).FloatString(0))
		flushEventsHeader()
		http.Error(w, fmt.Sprintf("job not able to be processed, removing capability err=%v", err.Error()), http.StatusInternalServerError)
		return
	}

	// Check for 401 Unauthorized - remove capability so worker can re-register with correct token
	if resp.StatusCode == http.StatusUnauthorized {
		clog.Errorf(ctx, "received 401 Unauthorized from worker, removing capability %v", orchJob.Req.Capability)
		bso.orch.RemoveExternalCapability(orchJob.Req.Capability)
		bso.chargeForCompute(start, orchJob.JobPrice, orchJob.Sender, orchJob.Req.Capability)
		w.Header().Set(jobPaymentBalanceHdr, bso.getPaymentBalance(orchJob.Sender, orchJob.Req.Capability).FloatString(0))
		http.Error(w, "job not able to be processed, removing capability err=worker auth token failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	w.Header().Set("X-Metadata", resp.Header.Get("X-Metadata"))

	//release capacity for another request
	// if requester closes the connection need to release capacity
	defer bso.orch.FreeExternalCapabilityCapacity(orchJob.Req.Capability)

	if !strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream") {
		//non streaming response

		defer resp.Body.Close()
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			clog.Errorf(ctx, "Unable to read response err=%v", err)

			acc.Add("job_orchestrator_worker_result", map[string]interface{}{
				"request_id":      orchJob.Req.ID,
				"capability":      orchJob.Req.Capability,
				"worker_url":      orchJob.Req.CapabilityUrl,
				"http_status":     resp.StatusCode,
				"success":         false,
				"duration_ms":     time.Since(start).Milliseconds(),
				"completed_at":    time.Now().UnixMilli(),
				"charged_compute": true,
				"retryable":       true,
				"error":           err.Error(),
			})
			chargeAndRecord(true)
			w.Header().Set(jobPaymentBalanceHdr, bso.getPaymentBalance(orchJob.Sender, orchJob.Req.Capability).FloatString(0))
			flushEventsHeader()
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		//error response from worker but assume can retry and pass along error response and status code
		if resp.StatusCode > 399 {
			clog.Errorf(ctx, "error processing request err=%v ", string(data))

			acc.Add("job_orchestrator_worker_result", map[string]interface{}{
				"request_id":      orchJob.Req.ID,
				"capability":      orchJob.Req.Capability,
				"worker_url":      orchJob.Req.CapabilityUrl,
				"http_status":     resp.StatusCode,
				"success":         false,
				"duration_ms":     time.Since(start).Milliseconds(),
				"completed_at":    time.Now().UnixMilli(),
				"charged_compute": true,
				"retryable":       resp.StatusCode >= 500,
				"error":           string(data),
			})
			chargeAndRecord(true)
			w.Header().Set(jobPaymentBalanceHdr, bso.getPaymentBalance(orchJob.Sender, orchJob.Req.Capability).FloatString(0))
			flushEventsHeader()
			//return error response from the worker
			http.Error(w, string(data), resp.StatusCode)
			return
		}

		acc.Add("job_orchestrator_worker_result", map[string]interface{}{
			"request_id":      orchJob.Req.ID,
			"capability":      orchJob.Req.Capability,
			"worker_url":      orchJob.Req.CapabilityUrl,
			"http_status":     resp.StatusCode,
			"success":         true,
			"duration_ms":     time.Since(start).Milliseconds(),
			"completed_at":    time.Now().UnixMilli(),
			"charged_compute": true,
			"retryable":       false,
			"error":           nil,
		})
		chargeAndRecord(false)
		w.Header().Set(jobPaymentBalanceHdr, bso.getPaymentBalance(orchJob.Sender, orchJob.Req.Capability).FloatString(0))
		flushEventsHeader()
		clog.V(common.SHORT).Infof(ctx, "Job processed successfully took=%v balance=%v", time.Since(start), bso.getPaymentBalance(orchJob.Sender, orchJob.Req.Capability).FloatString(0))
		w.Write(data)
		//request completed and returned a response

		return
	} else {
		// Handle streaming response (SSE)
		clog.Infof(ctx, "received streaming response")

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		//send payment balance back so client can determine if payment is needed
		bso.addPaymentBalanceHeader(w, orchJob.Sender, orchJob.Req.Capability)

		// Flush to ensure data is sent immediately
		flusher, ok := w.(http.Flusher)
		if !ok {
			clog.Errorf(ctx, "streaming not supported")

			acc.Add("job_orchestrator_worker_result", map[string]interface{}{
				"request_id":      orchJob.Req.ID,
				"capability":      orchJob.Req.Capability,
				"worker_url":      orchJob.Req.CapabilityUrl,
				"http_status":     resp.StatusCode,
				"success":         false,
				"duration_ms":     time.Since(start).Milliseconds(),
				"completed_at":    time.Now().UnixMilli(),
				"charged_compute": true,
				"retryable":       false,
				"error":           "streaming not supported",
			})
			chargeAndRecord(true)
			w.Header().Set(jobPaymentBalanceHdr, bso.getPaymentBalance(orchJob.Sender, orchJob.Req.Capability).FloatString(0))
			flushEventsHeader()
			http.Error(w, "Streaming not supported", http.StatusInternalServerError)
			return
		}

		// Read from upstream and forward to client
		respChan := make(chan string, 100)
		respCtx, _ := context.WithTimeout(ctx, time.Duration(orchJob.Req.Timeout)*time.Second)

		go func() {
			defer resp.Body.Close()
			defer close(respChan)
			scanner := bufio.NewScanner(resp.Body)
			for scanner.Scan() {
				select {
				case <-respCtx.Done():
					orchBal := orch.Balance(orchJob.Sender, core.ManifestID(orchJob.Req.Capability))
					if orchBal == nil {
						orchBal = big.NewRat(0, 1)
					}
					respChan <- fmt.Sprintf("data: {\"balance\": %v}\n\n", orchBal.FloatString(3))
					respChan <- "data: [DONE]\n\n"
					return
				default:
					line := scanner.Text()
					if strings.Contains(line, "[DONE]") {
						orchBal := orch.Balance(orchJob.Sender, core.ManifestID(orchJob.Req.Capability))
						if orchBal == nil {
							orchBal = big.NewRat(0, 1)
						}
						respChan <- fmt.Sprintf("data: {\"balance\": %v}\n\n", orchBal.FloatString(3))
						respChan <- scanner.Text()
						break
					}
					respChan <- scanner.Text()
				}
			}
		}()

		//check for payment balance
		pmtWatcher := time.NewTicker(5 * time.Second)
		defer pmtWatcher.Stop()
	proxyResp:
		for {
			select {
			case <-pmtWatcher.C:
				//check balance and end response if out of funds
				//skips if price is 0
				jobPriceRat := big.NewRat(orchJob.JobPrice.PricePerUnit, orchJob.JobPrice.PixelsPerUnit)
				if jobPriceRat.Cmp(big.NewRat(0, 1)) > 0 {
					bso.orch.DebitFees(orchJob.Sender, core.ManifestID(orchJob.Req.Capability), orchJob.JobPrice, 5)
					senderBalance := bso.getPaymentBalance(orchJob.Sender, orchJob.Req.Capability)
					if senderBalance != nil {
						if senderBalance.Cmp(big.NewRat(0, 1)) < 0 {
							w.Write([]byte("event: insufficient balance\n"))
							w.Write([]byte("data: {\"balance\": 0}\n\n"))
							w.Write([]byte("data: [DONE]\n\n"))
							flusher.Flush()
							break proxyResp
						}
					}
				}
			case <-respCtx.Done():
				break proxyResp
			case line := <-respChan:
				w.Write([]byte(line + "\n"))
				flusher.Flush()
			}
		}

		//capacity released with defer stmt above
		clog.V(common.SHORT).Infof(ctx, "Job processed successfully took=%v balance=%v", time.Since(start), bso.getPaymentBalance(orchJob.Sender, orchJob.Req.Capability).FloatString(0))
		acc.Add("job_orchestrator_worker_result", map[string]interface{}{
			"request_id":      orchJob.Req.ID,
			"capability":      orchJob.Req.Capability,
			"worker_url":      orchJob.Req.CapabilityUrl,
			"http_status":     resp.StatusCode,
			"success":         true,
			"duration_ms":     time.Since(start).Milliseconds(),
			"completed_at":    time.Now().UnixMilli(),
			"charged_compute": true,
			"retryable":       false,
			"error":           nil,
		})
		flushEventsHeader()
	}
}

// SetupOrchJob prepares the orchestrator job by extracting and validating the job request from the HTTP headers.
// Payment is applied if applicable.
func (bso *BYOCOrchestratorServer) setupOrchJob(ctx context.Context, r *http.Request, reserveCapacity bool) (*orchJob, error) {
	job := r.Header.Get(jobRequestHdr)
	orch := bso.orch
	jobReq, err := bso.verifyJobCreds(ctx, job, reserveCapacity)
	if err != nil {
		if err == errZeroCapacity && reserveCapacity {
			return nil, errNoCapabilityCapacity
		} else if err == errNoTimeoutSet {
			return nil, errNoTimeoutSet
		} else {
			clog.Errorf(ctx, "job failed verification: %v", err)
			return nil, errNoJobCreds
		}
	}

	sender := ethcommon.HexToAddress(jobReq.Sender)

	jobPrice, err := orch.JobPriceInfo(sender, jobReq.Capability)
	if err != nil {
		return nil, errors.New("Could not get job price")
	}

	pmtErr := bso.confirmPayment(ctx, sender, jobReq.Capability, jobPrice, r.Header.Get(jobPaymentHeaderHdr))
	if pmtErr != nil {
		orch.FreeExternalCapabilityCapacity(jobReq.Capability)
		return nil, pmtErr
	}

	var jobDetails JobRequestDetails
	err = json.Unmarshal([]byte(jobReq.Request), &jobDetails)
	if err != nil {
		return nil, fmt.Errorf("Unable to unmarshal job request details err=%v", err)
	}

	clog.Infof(ctx, "job request verified id=%v sender=%v capability=%v timeout=%v", jobReq.ID, jobReq.Sender, jobReq.Capability, jobReq.Timeout)

	return &orchJob{Req: jobReq, Sender: sender, JobPrice: jobPrice, Details: &jobDetails}, nil
}

func (bso *BYOCOrchestratorServer) confirmPayment(ctx context.Context, sender ethcommon.Address, capability string, jobPrice *net.PriceInfo, paymentHdr string) error {

	clog.V(common.DEBUG).Infof(ctx, "job price=%v units=%v", jobPrice.PricePerUnit, jobPrice.PixelsPerUnit)

	//no payment included, confirm if balance remains
	jobPriceRat := big.NewRat(jobPrice.PricePerUnit, jobPrice.PixelsPerUnit)
	// if price is 0, no payment required
	if jobPriceRat.Cmp(big.NewRat(0, 1)) > 0 {
		minBal := new(big.Rat).Mul(jobPriceRat, big.NewRat(60, 1)) //minimum 1 minute balance
		//process payment if included
		orchBal, pmtErr := bso.processPayment(ctx, sender, capability, paymentHdr)
		if pmtErr != nil {
			//log if there are payment errors but continue, balance will runout and clean up
			clog.Infof(ctx, "job payment error: %v", pmtErr)
		}

		if orchBal.Cmp(minBal) < 0 {
			if acc := orchEventAccumulatorFromCtx(ctx); acc != nil {
				var balInt int64
				if fixed, ferr := common.PriceToFixed(orchBal); ferr == nil {
					balInt = fixed / 1000
				}
				acc.Add("payment_insufficient_balance", map[string]interface{}{
					"sender":      sender.Hex(),
					"capability":  capability,
					"balance":     balInt,
					"min_balance": minBal.FloatString(3),
				})
			}
			return errInsufficientBalance
		}
	}

	return nil
}

// process payment and return balance
func (bso *BYOCOrchestratorServer) processPayment(ctx context.Context, sender ethcommon.Address, capability string, paymentHdr string) (*big.Rat, error) {
	if paymentHdr != "" {
		payment, err := getPayment(paymentHdr)
		if err != nil {
			clog.Errorf(ctx, "job payment invalid: %v", err)
			return nil, errPaymentError
		}

		if err := bso.orch.ProcessPayment(ctx, payment, core.ManifestID(capability)); err != nil {
			bso.orch.FreeExternalCapabilityCapacity(capability)
			clog.Errorf(ctx, "Error processing payment: %v", err)
			return nil, errPaymentError
		}
	}
	orchBal := bso.getPaymentBalance(sender, capability)

	return orchBal, nil

}

func (bso *BYOCOrchestratorServer) chargeForCompute(start time.Time, price *net.PriceInfo, sender ethcommon.Address, jobId string) {
	// Debit the fee for the total time processed
	took := time.Since(start)
	bso.orch.DebitFees(sender, core.ManifestID(jobId), price, int64(math.Ceil(took.Seconds())))
}

func (bso *BYOCOrchestratorServer) addPaymentBalanceHeader(w http.ResponseWriter, sender ethcommon.Address, jobId string) {
	//check balance and return remaning balance in header of response
	senderBalance := bso.getPaymentBalance(sender, jobId)
	w.Header().Set("Livepeer-Payment-Balance", senderBalance.FloatString(0))
}

func (bso *BYOCOrchestratorServer) getPaymentBalance(sender ethcommon.Address, jobId string) *big.Rat {
	//check balance and return remaning balance in header of response
	senderBalance := bso.orch.Balance(sender, core.ManifestID(jobId))
	if senderBalance == nil {
		senderBalance = big.NewRat(0, 1)
	}

	return senderBalance
}

func (bso *BYOCOrchestratorServer) verifyJobCreds(ctx context.Context, jobCreds string, reserveCapacity bool) (*JobRequest, error) {
	jobData, err := parseJobRequest(jobCreds)
	if err != nil {
		glog.Error("Unable to unmarshal ", err)
		return nil, err
	}

	if jobData.Timeout == 0 {
		return nil, errNoTimeoutSet
	}

	sigHex := jobData.Sig
	if len(jobData.Sig) > 130 {
		sigHex = jobData.Sig[2:]
	}
	sigByte, err := hex.DecodeString(sigHex)
	if err != nil {
		clog.Errorf(ctx, "Unable to hex-decode signature", err)
		return nil, errSegSig
	}

	if !bso.orch.VerifySig(ethcommon.HexToAddress(jobData.Sender), jobData.Request+jobData.Parameters, sigByte) {
		clog.Errorf(ctx, "Sig check failed sender=%v", jobData.Sender)
		if acc := orchEventAccumulatorFromCtx(ctx); acc != nil {
			acc.Add("job_credential_verify_result", map[string]interface{}{
				"sender":  jobData.Sender,
				"success": false,
				"error":   "signature verification failed",
			})
		}
		return nil, errSegSig
	}

	// Use the node's ExternalCapabilities runner registry only when runners are
	// actually registered for this capability; otherwise fall back to the orch
	// interface (used by tests and legacy deployments).
	var hasRunners bool
	if bso.node != nil && bso.node.ExternalCapabilities != nil {
		_, hasRunners = bso.node.ExternalCapabilities.GetCapability(jobData.Capability)
	}
	if hasRunners {
		// Extract options filter from job parameters so runner selection respects
		// the same constraint the gateway used to pick this orchestrator.
		var jobParams JobParameters
		_ = json.Unmarshal([]byte(jobData.Parameters), &jobParams)
		filter := jobParams.OptionsFilter

		// Atomically select and (optionally) reserve the best matching runner,
		// ensuring Reserve and GetUrl always refer to the same runner.
		if reserveCapacity {
			runner, err := bso.node.ExternalCapabilities.SelectAndReserveRunner(jobData.Capability, filter)
			if err != nil {
				if bso.pendingEvents != nil {
					bso.pendingEvents.Enqueue("worker_capacity_exhausted", map[string]interface{}{
						"capability":     jobData.Capability,
						"options_filter": filter,
					})
				}
				if acc := orchEventAccumulatorFromCtx(ctx); acc != nil {
					acc.Add("job_orchestrator_capacity_rejected", map[string]interface{}{
						"capability":     jobData.Capability,
						"options_filter": filter,
						"reason":         "no_capacity",
					})
				}
				return nil, errZeroCapacity
			}
			jobData.CapabilityUrl = runner.Url
			if clog.V(common.VERBOSE) {
				filterJSON, _ := json.Marshal(filter)
				optsJSON, _ := json.Marshal(runner.WorkerOptions)
				clog.V(common.VERBOSE).Infof(ctx, "orch runner selected capability=%v url=%v load=%v capacity=%v filter=%v worker_options=%v",
					jobData.Capability, runner.Url, runner.Load, runner.Capacity, string(filterJSON), string(optsJSON))
			}
		} else {
			runner := bso.node.ExternalCapabilities.SelectRunner(jobData.Capability, filter)
			if runner != nil {
				jobData.CapabilityUrl = runner.Url
				if clog.V(common.VERBOSE) {
					filterJSON, _ := json.Marshal(filter)
					optsJSON, _ := json.Marshal(runner.WorkerOptions)
					clog.V(common.VERBOSE).Infof(ctx, "orch runner selected (no reserve) capability=%v url=%v load=%v capacity=%v filter=%v worker_options=%v",
						jobData.Capability, runner.Url, runner.Load, runner.Capacity, string(filterJSON), string(optsJSON))
				}
			}
		}
	} else {
		// Fallback to interface methods (e.g. in tests with mocked orchestrator)
		if reserveCapacity && bso.orch.ReserveExternalCapabilityCapacity(jobData.Capability) != nil {
			return nil, errZeroCapacity
		}
		jobData.CapabilityUrl = bso.orch.GetUrlForCapability(jobData.Capability)
	}

	if acc := orchEventAccumulatorFromCtx(ctx); acc != nil {
		acc.Add("job_credential_verify_result", map[string]interface{}{
			"sender":     jobData.Sender,
			"capability": jobData.Capability,
			"worker_url": jobData.CapabilityUrl,
			"success":    true,
			"error":      nil,
		})
	}
	return jobData, nil
}

func (bso *BYOCOrchestratorServer) verifyTokenCreds(ctx context.Context, tokenCreds string) (*JobSender, error) {
	buf, err := base64.StdEncoding.DecodeString(tokenCreds)
	if err != nil {
		glog.Error("Unable to base64-decode ", err)
		return nil, errSegEncoding
	}

	var jobSender JobSender
	err = json.Unmarshal(buf, &jobSender)
	if err != nil {
		clog.Errorf(ctx, "Unable to parse the header text: ", err)
		return nil, err
	}

	sigHex := jobSender.Sig
	if len(jobSender.Sig) > 130 {
		sigHex = jobSender.Sig[2:]
	}
	sigByte, err := hex.DecodeString(sigHex)
	if err != nil {
		clog.Errorf(ctx, "Unable to hex-decode signature", err)
		return nil, errSegSig
	}

	if !bso.orch.VerifySig(ethcommon.HexToAddress(jobSender.Addr), jobSender.Addr, sigByte) {
		clog.Errorf(ctx, "Sig check failed")
		return nil, errSegSig
	}

	//signature confirmed
	return &jobSender, nil
}
