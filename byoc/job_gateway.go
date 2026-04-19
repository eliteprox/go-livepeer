package byoc

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"math/rand/v2"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/golang/glog"
	"github.com/livepeer/go-livepeer/clog"
	"github.com/livepeer/go-livepeer/common"
	"github.com/livepeer/go-livepeer/core"
	"github.com/livepeer/go-livepeer/monitor"
	"github.com/livepeer/go-livepeer/net"
	"github.com/pkg/errors"
)

// Gateway handler for job request
func (bsg *BYOCGatewayServer) SubmitJob() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Gateway node
		bsg.submitJob(ctx, w, r)
	})
}

func (bsg *BYOCGatewayServer) submitJob(ctx context.Context, w http.ResponseWriter, r *http.Request) {

	gatewayJob, err := bsg.setupGatewayJob(ctx, r.Header.Get(jobRequestHdr), r.Header.Get(jobOrchSearchTimeoutHdr), r.Header.Get(jobOrchSearchRespTimeoutHdr), false)
	if err != nil {
		clog.Errorf(ctx, "Error setting up job: %s", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	clog.Infof(ctx, "Job request setup complete details=%v params=%v", gatewayJob.Job.Details, gatewayJob.Job.Params)

	ctx = clog.AddVal(ctx, "job_id", gatewayJob.Job.Req.ID)
	ctx = clog.AddVal(ctx, "capability", gatewayJob.Job.Req.Capability)

	logPublicMetricsEntry(ctx, gatewayJob)

	// Read the original request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading request body", http.StatusInternalServerError)
		return
	}
	r.Body.Close()

	//send the request to the Orchestrator(s)
	//the loop ends on Gateway error and bad request errors
	for attemptIdx, orchToken := range gatewayJob.Orchs {
		workerResourceRoute := r.URL.Path

		var optionsFilter map[string]string
		if gatewayJob.Job.Params != nil {
			optionsFilter = gatewayJob.Job.Params.OptionsFilter
		}
		logPublicMetricsOrch(ctx, gatewayJob.Job.Req.Capability, orchToken.Address(), optionsFilter, orchToken.WorkerOptions)

		err := gatewayJob.sign()
		if err != nil {
			clog.Errorf(ctx, "Error signing job, exiting stream processing request: %v", err)
			return
		}

		start := time.Now()
		monitor.SendQueueEventAsync("job_gateway", map[string]interface{}{
			"type":          "job_gateway_submitted",
			"request_id":    gatewayJob.Job.Req.ID,
			"attempt_index": attemptIdx,
			"capability":    gatewayJob.Job.Req.Capability,
			"orchestrator_info": map[string]interface{}{
				"address": orchToken.Address(),
				"url":     orchToken.ServiceAddr,
			},
		})
		resp, code, err := bsg.sendJobToOrch(ctx, r, gatewayJob.Job.Req, gatewayJob.SignedJobReq, orchToken, workerResourceRoute, body)
		if err != nil {
			clog.Errorf(ctx, "job not able to be processed by Orchestrator %v err=%v ", orchToken.ServiceAddr, err.Error())
			monitor.SendQueueEventAsync("job_gateway", map[string]interface{}{
				"type":          "job_gateway_completed",
				"request_id":    gatewayJob.Job.Req.ID,
				"attempt_index": attemptIdx,
				"capability":    gatewayJob.Job.Req.Capability,
				"success":       false,
				"error":         err.Error(),
				"duration_ms":   time.Since(start).Milliseconds(),
				"completed_at":  time.Now().UnixMilli(),
				"orchestrator_info": map[string]interface{}{
					"address": orchToken.Address(),
					"url":     orchToken.ServiceAddr,
				},
			})
			continue
		}

		//error response from Orchestrator
		if code > 399 {
			data, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				clog.Errorf(ctx, "Unable to read response err=%v", err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				continue
			}

			clog.Errorf(ctx, "error processing request err=%v ", string(data))
			//nonretryable error
			if code < 500 {
				//assume non retryable bad request
				//return error response from the worker
				http.Error(w, string(data), code)
				return
			}
			//retryable error, continue to next orchestrator
			continue
		}

		//Orchestrator returns Livepeer-Balance header for streaming and non-streaming responses
		// for streaming responses: the balance is the balance before deducting cost to finish the request
		//                          the ending balance is sent as last line before [DONE] in the SSE stream
		// for non-streaming: the balance is the balance after deducting the cost of the request
		orchBalance := resp.Header.Get(jobPaymentBalanceHdr)
		w.Header().Set(jobPaymentBalanceHdr, orchBalance)
		w.Header().Set("X-Metadata", resp.Header.Get("X-Metadata"))
		w.Header().Set("X-Orchestrator-Url", orchToken.ServiceAddr)

		if !strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream") {
			//non streaming response
			data, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				clog.Errorf(ctx, "Unable to read response err=%v", err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				continue
			}

			gatewayBalance := updateGatewayBalance(bsg.node, orchToken, gatewayJob.Job.Req.Capability, time.Since(start))
			clog.V(common.SHORT).Infof(ctx, "Job processed successfully took=%v balance=%v balance_from_orch=%v", time.Since(start), gatewayBalance.FloatString(0), orchBalance)
			monitor.SendQueueEventAsync("job_gateway", map[string]interface{}{
				"type":          "job_gateway_completed",
				"request_id":    gatewayJob.Job.Req.ID,
				"attempt_index": attemptIdx,
				"capability":    gatewayJob.Job.Req.Capability,
				"success":       true,
				"error":         nil,
				"duration_ms":   time.Since(start).Milliseconds(),
				"completed_at":  time.Now().UnixMilli(),
				"http_status":   code,
				"orchestrator_info": map[string]interface{}{
					"address": orchToken.Address(),
					"url":     orchToken.ServiceAddr,
				},
			})
			w.Write(data)
			return
		} else {
			// Handle streaming response (SSE)
			clog.Infof(ctx, "received streaming response")

			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-cache")
			w.Header().Set("Connection", "keep-alive")

			// Flush to ensure data is sent immediately
			flusher, ok := w.(http.Flusher)
			if !ok {
				clog.Errorf(ctx, "streaming not supported")
				http.Error(w, "Streaming not supported", http.StatusInternalServerError)
				return
			}

			w.WriteHeader(http.StatusOK)
			// Read from upstream and forward to client
			respChan := make(chan string, 100)
			respCtx, respCancel := context.WithTimeout(ctx, time.Duration(gatewayJob.Job.Req.Timeout+10)*time.Second) //include a small buffer to let Orchestrator close the connection on the timeout
			defer respCancel()

			go func() {
				defer resp.Body.Close()
				defer close(respChan)
				scanner := bufio.NewScanner(resp.Body)

				for scanner.Scan() {
					select {
					case <-respCtx.Done():
						respChan <- "data: [DONE]\n\n"
						return
					default:
						line := scanner.Text()
						respChan <- line
						if strings.Contains(line, "[DONE]") {
							break
						}
					}
				}
			}()

			orchBalance := big.NewRat(0, 1)
		proxyResp:
			for {
				select {
				case line := <-respChan:
					w.Write([]byte(line + "\n"))
					flusher.Flush()
					if strings.Contains(line, "balance:") {
						orchBalance = parseBalance(line)
					}
					if strings.Contains(line, "[DONE]") {
						break proxyResp
					}

				case <-respCtx.Done():
					break proxyResp
				}
			}

			gatewayBalance := updateGatewayBalance(bsg.node, orchToken, gatewayJob.Job.Req.Capability, time.Since(start))

			clog.V(common.SHORT).Infof(ctx, "Job processed successfully took=%v balance=%v balance_from_orch=%v", time.Since(start), gatewayBalance.FloatString(0), orchBalance.FloatString(0))
			monitor.SendQueueEventAsync("job_gateway", map[string]interface{}{
				"type":          "job_gateway_completed",
				"request_id":    gatewayJob.Job.Req.ID,
				"attempt_index": attemptIdx,
				"capability":    gatewayJob.Job.Req.Capability,
				"success":       true,
				"error":         nil,
				"duration_ms":   time.Since(start).Milliseconds(),
				"completed_at":  time.Now().UnixMilli(),
				"http_status":   code,
				"streaming":     true,
				"orchestrator_info": map[string]interface{}{
					"address": orchToken.Address(),
					"url":     orchToken.ServiceAddr,
				},
			})
		}
	}
}

func (bsg *BYOCGatewayServer) sendJobToOrch(ctx context.Context, r *http.Request, jobReq *JobRequest, signedReqHdr string, orchToken JobToken, route string, body []byte) (*http.Response, int, error) {
	orchUrl := orchToken.ServiceAddr + route
	req, err := http.NewRequestWithContext(ctx, "POST", orchUrl, bytes.NewBuffer(body))
	if err != nil {
		clog.Errorf(ctx, "Unable to create request err=%v", err)
		return nil, http.StatusInternalServerError, err
	}

	// set the headers from the incoming request if present
	// byoc requests start with being passthrough oriented so reuse what we can when we can
	if r != nil {
		req.Header.Add("Content-Length", r.Header.Get("Content-Length"))
		req.Header.Add("Content-Type", r.Header.Get("Content-Type"))
	} else {
		//this is for live requests which will be json to start stream
		// update requests should include the content type/length
		req.Header.Add("Content-Type", "application/json")
	}

	req.Header.Add(jobRequestHdr, signedReqHdr)
	if orchToken.Price.PricePerUnit > 0 {
		paymentHdr, err := bsg.createPayment(ctx, jobReq, &orchToken)
		if err != nil {
			clog.Errorf(ctx, "Unable to create payment err=%v", err)
			return nil, http.StatusInternalServerError, fmt.Errorf("Unable to create payment err=%v", err)
		}
		if paymentHdr != "" {
			req.Header.Add(jobPaymentHeaderHdr, paymentHdr)
		}
	}

	resp, err := sendJobReqWithTimeout(req, time.Duration(jobReq.Timeout+5)*time.Second) //include 5 second buffer
	if err != nil {
		clog.Errorf(ctx, "job not able to be processed by Orchestrator %v err=%v ", orchToken.ServiceAddr, err.Error())
		return nil, http.StatusBadRequest, err
	}

	// Mechanism 2: extract orchestrator-side events from X-Livepeer-Events header
	if raw := resp.Header.Get("X-Livepeer-Events"); raw != "" {
		var orchEvents []struct {
			Type string          `json:"type"`
			Data json.RawMessage `json:"data"`
		}
		if jsonErr := json.Unmarshal([]byte(raw), &orchEvents); jsonErr == nil {
			for _, e := range orchEvents {
				topic := orchEventTopic(e.Type)
				if topic == "" {
					continue
				}
				var enriched map[string]interface{}
				json.Unmarshal(e.Data, &enriched)
				if enriched == nil {
					enriched = make(map[string]interface{})
				}
				enriched["orchestrator_info"] = map[string]string{
					"address": orchToken.Address(),
					"url":     orchToken.ServiceAddr,
				}
				monitor.SendQueueEventAsync(topic, enriched)
			}
		}
	}

	return resp, resp.StatusCode, nil
}

// orchEventTopic maps orchestrator-side event types to their Kafka topic names.
func orchEventTopic(eventType string) string {
	switch {
	case eventType == "job_credential_verify_result":
		return "job_auth"
	case strings.HasPrefix(eventType, "job_orchestrator_"):
		return "job_orchestrator"
	case strings.HasPrefix(eventType, "payment_"):
		return "job_payment"
	default:
		return ""
	}
}

func (bs *BYOCGatewayServer) sendPayment(ctx context.Context, orchPmtUrl, capability, jobReq, payment string) (int, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", orchPmtUrl, nil)
	if err != nil {
		clog.Errorf(ctx, "Unable to create request err=%v", err)
		return http.StatusBadRequest, err
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add(jobRequestHdr, jobReq)
	req.Header.Add(jobPaymentHeaderHdr, payment)

	resp, err := sendJobReqWithTimeout(req, 10*time.Second)
	if err != nil {
		clog.Errorf(ctx, "job payment not able to be processed by Orchestrator %v err=%v ", orchPmtUrl, err.Error())
		return http.StatusBadRequest, err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	return resp.StatusCode, nil
}

func (bsg *BYOCGatewayServer) setupGatewayJob(ctx context.Context, jobReqHdr string, orchSearchTimeoutHdr string, orchSearchRespTimeoutHdr string, skipOrchSearch bool) (*gatewayJob, error) {

	var orchs []JobToken

	clog.Infof(ctx, "processing job request req=%v", jobReqHdr)
	jobReq, err := bsg.verifyJobCreds(jobReqHdr)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Unable to parse job request, err=%v", err))
	}

	var jobDetails JobRequestDetails
	if err := json.Unmarshal([]byte(jobReq.Request), &jobDetails); err != nil {
		return nil, errors.New(fmt.Sprintf("Unable to unmarshal job request err=%v", err))
	}

	var jobParams JobParameters
	if err := json.Unmarshal([]byte(jobReq.Parameters), &jobParams); err != nil {
		return nil, errors.New(fmt.Sprintf("Unable to unmarshal job parameters err=%v", err))
	}

	// get list of Orchestrators that can do the job if needed
	// (e.g. stop requests don't need new list of orchestrators)
	if !skipOrchSearch {
		searchTimeout, respTimeout := getOrchSearchTimeouts(ctx, orchSearchTimeoutHdr, orchSearchRespTimeoutHdr)
		jobReq.OrchSearchTimeout = searchTimeout
		jobReq.OrchSearchRespTimeout = respTimeout

		//get pool of Orchestrators that can do the job
		orchs, err = getJobOrchestrators(ctx, bsg.node, jobReq.Capability, jobParams, jobReq.OrchSearchTimeout, jobReq.OrchSearchRespTimeout)
		if err != nil {
			monitor.SendQueueEventAsync("job_gateway", map[string]interface{}{
				"type":       "job_orchestrator_discovery_result",
				"capability": jobReq.Capability,
				"success":    false,
				"selected":   0,
				"error":      err.Error(),
			})
			return nil, errors.New(fmt.Sprintf("Unable to find orchestrators for capability %v err=%v", jobReq.Capability, err))
		}

		if len(orchs) == 0 {
			monitor.SendQueueEventAsync("job_gateway", map[string]interface{}{
				"type":       "job_orchestrator_discovery_result",
				"capability": jobReq.Capability,
				"success":    false,
				"selected":   0,
				"error":      "no orchestrators found",
			})
			return nil, errors.New(fmt.Sprintf("No orchestrators found for capability %v", jobReq.Capability))
		}

		monitor.SendQueueEventAsync("job_gateway", map[string]interface{}{
			"type":       "job_orchestrator_discovery_result",
			"capability": jobReq.Capability,
			"success":    true,
			"selected":   len(orchs),
			"error":      nil,
		})
	}

	job := orchJob{Req: jobReq,
		Details: &jobDetails,
		Params:  &jobParams,
	}

	return &gatewayJob{Job: &job, Orchs: orchs, node: bsg.node}, nil
}

func getOrchSearchTimeouts(ctx context.Context, searchTimeoutHdr, respTimeoutHdr string) (time.Duration, time.Duration) {
	timeout := jobOrchSearchTimeoutDefault
	if searchTimeoutHdr != "" {
		timeout, err := time.ParseDuration(searchTimeoutHdr)
		if err != nil || timeout < 0 {
			timeout = jobOrchSearchTimeoutDefault

		}
	}
	respTimeout := jobOrchSearchRespTimeoutDefault
	if respTimeoutHdr != "" {
		respTimeout, err := time.ParseDuration(respTimeoutHdr)
		if err != nil || respTimeout < 0 {
			respTimeout = jobOrchSearchRespTimeoutDefault
		}
	}

	return timeout, respTimeout
}

func (bsg *BYOCGatewayServer) verifyJobCreds(jobCreds string) (*JobRequest, error) {
	//Gateway needs JobRequest parsed and verification of required fields
	jobData, err := parseJobRequest(jobCreds)
	if err != nil {
		glog.Error("Unable to unmarshal ", err)
		return nil, err
	}

	if jobData.Timeout == 0 {
		return nil, errNoTimeoutSet
	}

	return jobData, nil
}

func getJobOrchestrators(ctx context.Context, node *core.LivepeerNode, capability string, params JobParameters, timeout time.Duration, respTimeout time.Duration) ([]JobToken, error) {
	orchs := node.OrchestratorPool.GetInfos()
	//setup the GET request to get the Orchestrator tokens
	reqSender, err := getJobSender(ctx, node)
	if err != nil {
		clog.Errorf(ctx, "Failed to get job sender err=%v", err)
		return nil, err
	}

	getOrchJobToken := func(ctx context.Context, orchUrl *url.URL, reqSender JobSender, respTimeout time.Duration, tokenCh chan JobToken, errCh chan error) {
		start := time.Now()
		tokenReq, err := http.NewRequestWithContext(ctx, "GET", orchUrl.String()+"/process/token", nil)
		if err != nil {
			clog.Errorf(ctx, "Failed to create request for Orchestrator to verify job token request err=%v", err)
			return
		}

		reqSenderStr, _ := json.Marshal(reqSender)
		tokenReq.Header.Set(jobEthAddressHdr, base64.StdEncoding.EncodeToString(reqSenderStr))
		tokenReq.Header.Set(jobCapabilityHdr, capability)

		// Pass the options filter so the orchestrator can return capacity that
		// reflects only runners matching the filter (avoids wasted round-trips).
		if len(params.OptionsFilter) > 0 {
			filterJSON, err := json.Marshal(params.OptionsFilter)
			if err == nil {
				q := tokenReq.URL.Query()
				q.Set("options_filter", string(filterJSON))
				tokenReq.URL.RawQuery = q.Encode()
			}
		}

		resp, err := sendJobReqWithTimeout(tokenReq, respTimeout)
		if err != nil {
			clog.Errorf(ctx, "failed to get token from Orchestrator err=%v", err)
			monitor.SendQueueEventAsync("job_gateway", map[string]interface{}{
				"type":       "job_orchestrator_token_fetch_result",
				"orch_url":   orchUrl.String(),
				"capability": capability,
				"success":    false,
				"latency_ms": time.Since(start).Milliseconds(),
				"error":      err.Error(),
			})
			errCh <- err
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			clog.Errorf(ctx, "Failed to get token from Orchestrator %v err=%v", orchUrl.String(), err)
			fetchErr := fmt.Errorf("failed to get token from Orchestrator status=%d", resp.StatusCode)
			monitor.SendQueueEventAsync("job_gateway", map[string]interface{}{
				"type":        "job_orchestrator_token_fetch_result",
				"orch_url":    orchUrl.String(),
				"capability":  capability,
				"success":     false,
				"latency_ms":  time.Since(start).Milliseconds(),
				"http_status": resp.StatusCode,
				"error":       fetchErr.Error(),
			})
			errCh <- fetchErr
			return
		}

		latency := time.Since(start)
		clog.V(common.DEBUG).Infof(ctx, "Received job token from uri=%v, latency=%v", orchUrl, latency)

		token, err := io.ReadAll(resp.Body)
		if err != nil {
			clog.Errorf(ctx, "Failed to read token from Orchestrator %v err=%v", orchUrl.String(), err)
			monitor.SendQueueEventAsync("job_gateway", map[string]interface{}{
				"type":       "job_orchestrator_token_fetch_result",
				"orch_url":   orchUrl.String(),
				"capability": capability,
				"success":    false,
				"latency_ms": latency.Milliseconds(),
				"error":      err.Error(),
			})
			errCh <- err
			return
		}
		var jobToken JobToken
		err = json.Unmarshal(token, &jobToken)
		if err != nil {
			clog.Errorf(ctx, "Failed to unmarshal token from Orchestrator %v err=%v", orchUrl.String(), err)
			monitor.SendQueueEventAsync("job_gateway", map[string]interface{}{
				"type":       "job_orchestrator_token_fetch_result",
				"orch_url":   orchUrl.String(),
				"capability": capability,
				"success":    false,
				"latency_ms": latency.Milliseconds(),
				"error":      err.Error(),
			})
			errCh <- err
			return
		}

		monitor.SendQueueEventAsync("job_gateway", map[string]interface{}{
			"type":               "job_orchestrator_token_fetch_result",
			"orch_url":           orchUrl.String(),
			"capability":         capability,
			"success":            true,
			"latency_ms":         latency.Milliseconds(),
			"available_capacity": jobToken.AvailableCapacity,
			"error":              nil,
			"orchestrator_info": map[string]interface{}{
				"address": jobToken.Address(),
				"url":     jobToken.ServiceAddr,
			},
		})
		tokenCh <- jobToken
	}

	var jobTokens []JobToken
	nbResp := 0
	numAvailableOrchs := node.OrchestratorPool.Size()
	tokenCh := make(chan JobToken, numAvailableOrchs)
	errCh := make(chan error, numAvailableOrchs)

	tokensCtx, cancel := context.WithTimeout(clog.Clone(context.Background(), ctx), timeout)
	defer cancel()
	// Shuffle and get job tokens
	for _, i := range rand.Perm(len(orchs)) {
		//do not send to excluded Orchestrators
		if slices.Contains(params.Orchestrators.Exclude, orchs[i].URL.String()) {
			numAvailableOrchs--
			continue
		}
		//if include is set, only send to those Orchestrators
		if len(params.Orchestrators.Include) > 0 && !slices.Contains(params.Orchestrators.Include, orchs[i].URL.String()) {
			numAvailableOrchs--
			continue
		}

		go getOrchJobToken(ctx, orchs[i].URL, *reqSender, respTimeout, tokenCh, errCh)
	}

	for nbResp < numAvailableOrchs && len(jobTokens) < numAvailableOrchs {
		select {
		case token := <-tokenCh:
			if token.AvailableCapacity > 0 {
				if core.AnyOptionsMatch(params.OptionsFilter, token.WorkerOptions) {
					if clog.V(common.VERBOSE) {
						filterJSON, _ := json.Marshal(params.OptionsFilter)
						optsJSON, _ := json.Marshal(token.WorkerOptions)
						clog.V(common.VERBOSE).Infof(ctx, "job selection orch=%v accepted filter=%v all_options=%v", token.ServiceAddr, string(filterJSON), string(optsJSON))
					}
					jobTokens = append(jobTokens, token)
				} else {
					if clog.V(common.VERBOSE) {
						filterJSON, _ := json.Marshal(params.OptionsFilter)
						optsJSON, _ := json.Marshal(token.WorkerOptions)
						clog.V(common.VERBOSE).Infof(ctx, "job selection orch=%v rejected filter=%v worker_options=%v", token.ServiceAddr, string(filterJSON), string(optsJSON))
					}
				}
			} else {
				clog.V(common.VERBOSE).Infof(ctx, "job selection orch=%v skipped no_capacity", token.ServiceAddr)
			}
			nbResp++
		case <-errCh:
			nbResp++
		case <-tokensCtx.Done():
			//searchTimeout reached, return tokens received
			clog.V(common.VERBOSE).Infof(ctx, "job selection timeout reached selected=%v", len(jobTokens))
			return jobTokens, nil
		}
	}

	clog.V(common.VERBOSE).Infof(ctx, "job selection selected=%v from=%v orchs", len(jobTokens), nbResp)
	// received enough tokens or all responses arrived
	return jobTokens, nil
}

func getJobSender(ctx context.Context, node *core.LivepeerNode) (*JobSender, error) {
	gateway := node.OrchestratorPool.Broadcaster()
	orchReq, err := genOrchestratorReq(gateway)
	if err != nil {
		clog.Errorf(ctx, "Failed to generate request for Orchestrator to verify to request job token err=%v", err)
		return nil, err
	}
	addr := ethcommon.BytesToAddress(orchReq.Address)
	jobSender := &JobSender{
		Addr: addr.Hex(),
		Sig:  "0x" + hex.EncodeToString(orchReq.Sig),
	}

	return jobSender, nil
}

func genOrchestratorReq(b common.Broadcaster) (*net.OrchestratorRequest, error) {
	sig, err := b.Sign([]byte(fmt.Sprintf("%v", b.Address().Hex())))
	if err != nil {
		return nil, err
	}
	return &net.OrchestratorRequest{Address: b.Address().Bytes(), Sig: sig}, nil
}

// getToken fetches a job token from a specific orchestrator URL with exponential
// backoff retry. It is used during stream reconnect / orchestrator failover where
// a brief retry is acceptable. For fan-out discovery use getOrchJobToken instead,
// which has no retry so that slow orchestrators don't stall the whole selection.
func getToken(ctx context.Context, respTimeout time.Duration, orchUrl, capability, sender, senderSig string) (*JobToken, error) {
	start := time.Now()
	tokenReq, err := http.NewRequestWithContext(ctx, "GET", orchUrl+"/process/token", nil)
	jobSender := JobSender{Addr: sender, Sig: senderSig}

	reqSenderStr, _ := json.Marshal(jobSender)
	tokenReq.Header.Set(jobEthAddressHdr, base64.StdEncoding.EncodeToString(reqSenderStr))
	tokenReq.Header.Set(jobCapabilityHdr, capability)
	if err != nil {
		clog.Errorf(ctx, "Failed to create request for Orchestrator to verify job token request err=%v", err)
		return nil, err
	}

	var resp *http.Response
	var jobToken JobToken
	var attempt int
	var backoff time.Duration = 100 * time.Millisecond
	deadline := time.Now().Add(respTimeout)

	for attempt = 0; attempt < 3; attempt++ {
		resp, err = sendJobReqWithTimeout(tokenReq, respTimeout)
		if err != nil {
			clog.Errorf(ctx, "failed to get token from Orchestrator (attempt %d) err=%v", attempt+1, err)
			continue
		}
		respBody, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			clog.Errorf(ctx, "Failed to read token response from Orchestrator %v err=%v", orchUrl, err)
		}

		if resp.StatusCode != http.StatusOK {
			clog.Errorf(ctx, "Failed to get token from Orchestrator %v status=%v (attempt %d)", orchUrl, resp.StatusCode, attempt+1)
		} else {
			latency := time.Since(start)
			clog.V(common.DEBUG).Infof(ctx, "Received job token from uri=%v, latency=%v", orchUrl, latency)
			err = json.Unmarshal(respBody, &jobToken)
			if err != nil {
				clog.Errorf(ctx, "Failed to unmarshal token from Orchestrator %v err=%v", orchUrl, err)
			} else {
				return &jobToken, nil
			}
		}
		// If not last attempt and time remains, backoff
		if time.Now().Add(backoff).Before(deadline) && attempt < 2 {
			time.Sleep(backoff)
			backoff *= 2
		} else {
			break
		}
	}
	// All attempts failed
	if err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("failed to get token from Orchestrator after %d attempts", attempt)
}

// FetchWorkerOptions fans out GET /process/options to each orchestrator URL,
// merges the results, and returns the deduplicated union. timeout controls
// how long to wait for all responses.
// FetchCapabilityOptions calls GET /process/options on a single orchestrator URL
// and returns the per-capability options map. Returns nil on any error.
func FetchCapabilityOptions(ctx context.Context, orchURL string, timeout time.Duration) map[string][]map[string]interface{} {
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, strings.TrimRight(orchURL, "/")+"/process/options", nil)
	if err != nil {
		clog.Errorf(ctx, "FetchCapabilityOptions orch=%v failed to create request err=%v", orchURL, err)
		return nil
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		clog.V(common.VERBOSE).Infof(ctx, "FetchCapabilityOptions orch=%v request failed err=%v", orchURL, err)
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		clog.V(common.VERBOSE).Infof(ctx, "FetchCapabilityOptions orch=%v non-200 status=%v", orchURL, resp.StatusCode)
		return nil
	}
	var opts map[string][]map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&opts); err != nil {
		clog.Errorf(ctx, "FetchCapabilityOptions orch=%v failed to decode response err=%v", orchURL, err)
		return nil
	}
	if clog.V(common.VERBOSE) {
		optsJSON, _ := json.Marshal(opts)
		clog.Infof(ctx, "FetchCapabilityOptions orch=%v received options=%v", orchURL, string(optsJSON))
	}
	return opts
}

// FetchWorkerOptions fans out GET /process/options to each orchestrator URL,
// merges the results, and returns the deduplicated union as a flat list.
// Used by the gateway's /process/options aggregator for model discovery.
func FetchWorkerOptions(ctx context.Context, orchs []common.OrchestratorLocalInfo, timeout time.Duration) []map[string]interface{} {
	type orchResult struct {
		capOpts map[string][]map[string]interface{}
	}
	resultCh := make(chan orchResult, len(orchs))

	orchURLs := make([]string, len(orchs))
	for i, o := range orchs {
		orchURLs[i] = o.URL.String()
	}
	clog.Infof(ctx, "FetchWorkerOptions querying num_orchs=%v urls=%v", len(orchs), orchURLs)

	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	for _, orch := range orchs {
		go func(orchURL string) {
			resultCh <- orchResult{capOpts: FetchCapabilityOptions(reqCtx, orchURL, timeout)}
		}(orch.URL.String())
	}

	// Collect and flatten all per-capability options; deduplicate by JSON fingerprint.
	seen := make(map[string]struct{})
	all := make([]map[string]interface{}, 0)
	for range orchs {
		res := <-resultCh
		for _, opts := range res.capOpts {
			for _, opt := range opts {
				key, _ := json.Marshal(opt)
				if _, dup := seen[string(key)]; !dup {
					seen[string(key)] = struct{}{}
					all = append(all, opt)
				}
			}
		}
	}
	clog.Infof(ctx, "FetchWorkerOptions total_unique=%v", len(all))
	return all
}

// GetWorkerOptions fans out GET /process/options to every Orchestrator in the
// pool, merges the results, and returns the deduplicated union as a JSON array.
// This is the endpoint called by the gateway-proxy's /v1/models handler.
func (bsg *BYOCGatewayServer) GetWorkerOptions() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		orchs := bsg.node.OrchestratorPool.GetInfos()
		all := FetchWorkerOptions(r.Context(), orchs, 2*time.Second)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(all)
	})
}
