package server

//based on segment_rpc.go

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/livepeer/go-livepeer/clog"
	"github.com/livepeer/go-livepeer/common"
	"github.com/livepeer/go-livepeer/core"
	"github.com/livepeer/go-livepeer/net"

	ethcommon "github.com/ethereum/go-ethereum/common"
	lpcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/golang/glog"
)

const jobRequestHdr = "Livepeer-Job"
const jobSigHdr = "Livepeer-Job-Sig"
const jobEthAddressHdr = "Livepeer-Job-Eth-Address"
const jobCapabilityHdr = "Livepeer-Job-Capability"
const jobPaymentHdr = "Livepeer-Job-Payment"
const jobRegisterCapabilityHdr = "Livepeer-Job-Register-Capability"

type JobSender struct {
	Addr string `json:"addr"`
	Msg  string `json:"msg"`
	Sig  string `json:"sig"`
}

type JobToken struct {
	Token         *net.AuthToken    `json:"token"`
	JobId         string            `json:"jobId"`
	Capability    string            `json:"capability"`
	Expiration    int64             `json:"expiration"`
	SenderAddress *JobSender        `json:"senderAddress,omitempty"`
	TicketParams  *net.TicketParams `json:"ticketParams,omitempty"`
	Price         *net.PriceInfo    `json:"priceInfo"`
}

type JobRequest struct {
	ID            string         `json:"id"`
	Prompt        string         `json:"prompt"`
	Parameters    string         `json:"parameters"`
	Capability    string         `json:"capability"`
	CapabilityUrl string         `json:"capabilityUrl"` //this is set when verified orch has capability
	Token         *net.AuthToken `json:"token"`         //send back token provided
	Sender        string         `json:"sender"`
	ReqHash       string         `json:"reqHash"`
	DataHash      string         `json:"dataHash"`
	Timeout       int            `json:"timeoutSeconds"`
}

type JobSig struct {
	Hash string `json:"hash"`
	Sig  string `json:"sig"`
}

func (h *lphttp) RegisterCapability(w http.ResponseWriter, r *http.Request) {
	enableCors(&w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	orch := h.orchestrator
	auth := r.Header.Get("Authorization")
	if auth != orch.TranscoderSecret() {
		http.Error(w, "invalid authorization", http.StatusBadRequest)
	}

	extCapHdr := r.Header.Get(jobRegisterCapabilityHdr)
	remoteAddr := getRemoteAddr(r)

	extCap, err := orch.RegisterExternalCapability(extCapHdr)

	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		w.WriteHeader(http.StatusNoContent)
		w.Write([]byte("error: " + err.Error()))
		clog.Infof(context.TODO(), "registered capability failed err=%v", err.Error())
	} else {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
		clog.Infof(context.TODO(), "registered capability remoteAddr=%v capability=%v url=%v", remoteAddr, extCap.Name, extCap.Url)
	}

}

func (h *lphttp) GetJobToken(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		enableCors(&w)
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	enableCors(&w)

	remoteAddr := getRemoteAddr(r)
	var jobToken JobToken
	orch := h.orchestrator
	jobEthAddrHdr := r.Header.Get(jobEthAddressHdr)
	if jobEthAddrHdr == "" {
		glog.Infof("generate token failed, invalid request remoteAddr=%v", remoteAddr)
		http.Error(w, fmt.Sprintf("Must have eth address, signature and msg in Livepeer-Job-Eth-Address header"), http.StatusBadRequest)
		return
	}

	var jobSenderAddr JobSender
	err := json.Unmarshal([]byte(jobEthAddrHdr), &jobSenderAddr)
	if err != nil {
		glog.Infof("generate token failed, invalid request remoteAddr=%v err=%v", remoteAddr, err.Error())
		http.Error(w, fmt.Sprintf("Invalid eth address header must include 'addr', 'sig' or 'msg' fields"), http.StatusBadRequest)
		return
	}

	if !ethcommon.IsHexAddress(jobSenderAddr.Addr) {
		glog.Infof("generate token failed, invalid eth address remoteAddr=%v", remoteAddr)
		http.Error(w, fmt.Sprintf("Eth address invalid, must have valid eth address in %v header", jobEthAddrHdr), http.StatusBadRequest)
		return
	}

	if !orch.VerifyPersonalSig(jobSenderAddr.Addr, jobSenderAddr.Sig, jobSenderAddr.Msg) {
		glog.Infof("generate token failed, eth address signature failed remoteAddr=%v", remoteAddr)
		http.Error(w, "eth address request signature could not be verified", http.StatusBadRequest)
		return
	}

	jobCapsHdr := r.Header.Get(jobCapabilityHdr)
	if jobCapsHdr == "" {
		glog.Infof("generate token failed, invalid request, no capabilities included remoteAddr=%v", remoteAddr)
		http.Error(w, fmt.Sprintf("Job capabilities not provided, must provide comma separated capabilities in Livepeer-Job-Capability header"), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	if !orch.ExternalCapabilities().CompatibleWith(jobCapsHdr) {
		w.WriteHeader(http.StatusNoContent)
		jobToken = JobToken{JobId: "", Token: nil, Expiration: 0, SenderAddress: nil, TicketParams: nil}
	} else {
		senderAddr := ethcommon.HexToAddress(jobSenderAddr.Addr)
		jobId := NewJobId()

		token := orch.AuthToken(string(jobId), time.Now().Add(authTokenValidPeriod).Unix())
		jobPrice, err := orch.JobPriceInfo(senderAddr, core.RandomManifestID(), jobCapsHdr)
		//glog.Infof("%v", jobCapsHdr)
		//glog.Infof("%+v", jobPrice)
		if err != nil {
			glog.Errorf("could not get price err=%v", err.Error())
			http.Error(w, fmt.Sprintf("Could not get price err=%v", err.Error()), http.StatusBadRequest)
			return
		}

		ticketParams, err := orch.TicketParams(senderAddr, jobPrice)
		if err != nil {
			glog.Errorf("could not get ticket params err=%v", err.Error())
			http.Error(w, fmt.Sprintf("Could not get ticket params err=%v", err.Error()), http.StatusExpectationFailed)
			return
		}

		jobToken = JobToken{Token: token,
			JobId:         token.SessionId,
			Expiration:    token.Expiration,
			SenderAddress: &jobSenderAddr,
			TicketParams:  ticketParams,
			Price:         jobPrice,
		}

		//send response
		w.WriteHeader(http.StatusOK)
	}

	json.NewEncoder(w).Encode(jobToken)
}

func (h *lphttp) ProcessJob(w http.ResponseWriter, r *http.Request) {
	enableCors(&w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.ContentLength > int64(common.MaxSegSize) {
		http.Error(w, "request size too large", http.StatusBadRequest)
		return
	}
	remoteAddr := getRemoteAddr(r)
	ctx := clog.AddVal(r.Context(), clog.ClientIP, remoteAddr)
	clog.Infof(ctx, "Received job request")

	orch := h.orchestrator

	payment, err := getJobPayment(r.Header.Get(jobPaymentHdr))
	if err != nil {
		clog.Errorf(ctx, "Could not parse payment: %v", err.Error())
		http.Error(w, err.Error(), http.StatusPaymentRequired)
		return
	}

	sender := getPaymentSender(*payment)
	ctx = clog.AddVal(ctx, "sender", sender.Hex())

	sig := r.Header.Get(jobSigHdr)
	if sig == "" {
		clog.Errorf(ctx, "sig not included in request")
		http.Error(w, "signature on job request not included, must include Livepeer-Job-Sig header with signature over Livepeer-Job header", http.StatusBadRequest)
	}
	jobSig, err := getJobSig(sig)
	if err != nil {
		clog.Errorf(ctx, "error parsing sig")
		http.Error(w, "signature not parsed, please format correctly with 'hash' and 'sig' field", http.StatusBadRequest)
	}

	r.Body = http.MaxBytesReader(w, r.Body, int64(common.MaxSegSize))

	body, err := io.ReadAll(r.Body)
	if err != nil {
		glog.Errorf("error reading body")
		http.Error(w, err.Error(), http.StatusBadRequest)

		return
	}

	job := r.Header.Get(jobRequestHdr)

	jobReq, ctx, err := verifyJobCreds(ctx, orch, job, jobSig, sender)
	if err != nil {
		if err == errZeroCapacity {
			clog.Errorf(ctx, "No capacity available for capability err=%q", err)
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
		} else {
			clog.Errorf(ctx, "Could not verify job creds err=%q", err)
			http.Error(w, err.Error(), http.StatusForbidden)
		}

		return
	}

	if err := orch.ProcessPayment(ctx, *payment, core.ManifestID(jobReq.ID)); err != nil {
		clog.Errorf(ctx, "error processing payment: %v", err)

		orch.FreeExternalCapacity(jobReq.Capability)

		http.Error(w, err.Error(), http.StatusBadRequest)

		return
	}

	clog.V(common.SHORT).Infof(ctx, "Received job, sending for processing id=%v sender=%v ip=%v", jobReq.ID, sender.Hex(), remoteAddr)

	req, err := http.NewRequestWithContext(ctx, "POST", jobReq.CapabilityUrl, bytes.NewReader(body))
	req.Header.Add("Content-Type", r.Header.Get("Content-Type"))
	reqHdr := make(map[string]string)
	reqHdr["id"] = jobReq.ID
	reqHdr["prompt"] = jobReq.Prompt
	reqHdr["parameters"] = jobReq.Parameters
	reqHdr["capability"] = jobReq.Capability
	reqHdrStr, _ := json.Marshal(reqHdr)
	req.Header.Add("Livepeer-Job", string(reqHdrStr))

	resp, err := sendReqWithTimeout(req, time.Duration(jobReq.Timeout)*time.Second)
	orch.FreeExternalCapacity(jobReq.Capability)
	if err != nil {
		clog.Errorf(ctx, "job not able to be processed err=%v, external_capabilitites=%v", err.Error(), jobReq.Capability)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	}

	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if resp.StatusCode > 399 {
		clog.Infof(ctx, "job request processing failed: %v", string(data))
		http.Error(w, string(data), http.StatusInternalServerError)
	}

	clog.V(common.SHORT).Infof(ctx, "Job proccessing complete, sending result id=%v sender=%v ip=%v", jobReq.ID, sender.Hex(), remoteAddr)
	//add headers from response to pass through
	for k, val := range resp.Header {
		for _, v := range val {
			w.Header().Add(k, v)
		}
	}

	w.Write(data)

}

func getJobSig(header string) (*JobSig, error) {
	buf, err := base64.StdEncoding.DecodeString(header)
	if err != nil {
		return nil, errors.New("base64 decode error: " + err.Error())
	}

	var sig JobSig
	if err := json.Unmarshal(buf, &sig); err != nil {
		return nil, errors.New("json unmarshal error: " + err.Error())
	}

	return &sig, nil
}

func getJobPayment(header string) (*net.Payment, error) {
	buf, err := base64.StdEncoding.DecodeString(header)
	if err != nil {
		return nil, errors.New("base64 decode error: " + err.Error())
	}
	var payment net.Payment
	if err := json.Unmarshal(buf, &payment); err != nil {
		return nil, errors.New("json unmarshal error: " + err.Error())
	}

	return &payment, nil
}

func verifyJobCreds(ctx context.Context, orch Orchestrator, jobCreds string, jobSig *JobSig, requestedBy ethcommon.Address) (*JobRequest, context.Context, error) {
	buf, err := base64.StdEncoding.DecodeString(jobCreds)
	if err != nil {
		glog.Error("Unable to base64-decode ", err)
		return nil, ctx, errSegEncoding
	}

	var jobData JobRequest
	err = json.Unmarshal(buf, &jobData)
	if err != nil {
		glog.Error("Unable to unmarshal ", err)
		return nil, ctx, err
	}

	ctx = clog.AddVal(ctx, "job_id", jobData.ID)

	credsHash := lpcrypto.Keccak256Hash([]byte(jobCreds))
	if credsHash.Hex() != jobSig.Hash {
		return nil, ctx, errors.New("hash of request does not match")
	}

	if !orch.VerifyPersonalSig(requestedBy.Hex(), jobSig.Sig, jobSig.Hash) {
		clog.Errorf(ctx, "Sig check failed")
		return nil, ctx, errSegSig
	}

	// Check that auth token is valid and not expired
	if jobData.Token == nil {
		return nil, ctx, errors.New("missing auth token")
	}

	verifyToken := orch.AuthToken(jobData.ID, jobData.Token.Expiration)
	if !bytes.Equal(verifyToken.Token, jobData.Token.Token) {
		return nil, ctx, errors.New("invalid auth token")
	}
	ctx = clog.AddOrchSessionID(ctx, jobData.ID)

	expiration := time.Unix(jobData.Token.Expiration, 0)
	if time.Now().After(expiration) {
		return nil, ctx, errors.New("expired auth token")
	}

	orchCaps := orch.ExternalCapabilities()
	if !orchCaps.CompatibleWith(jobData.Capability) {
		clog.Errorf(ctx, "Capability check failed")
		return nil, ctx, errCapCompat
	}

	if err := orch.CheckExternalCapacity(jobData.Capability); err != nil {
		clog.Errorf(ctx, "Cannot process job err=%q", err)
		return nil, ctx, errZeroCapacity
	}

	jobData.CapabilityUrl = orch.GetUrlForCapability(jobData.Capability)

	return &jobData, ctx, nil
}

func (j *JobRequest) DataForSig() string {

	paramsStr, _ := json.Marshal(j.Parameters)

	return j.ID + j.Prompt + string(paramsStr) + j.DataHash
}

func NewJobId() string {
	return string(core.RandomManifestID())
}

func enableCors(w *http.ResponseWriter) {
	lpHdrs := []string{"Content-Type", "Authorization", jobRequestHdr, jobSigHdr, jobEthAddressHdr, jobCapabilityHdr, jobPaymentHdr, jobRegisterCapabilityHdr}
	resHdrs := []string{"Content-Disposition", "Content-Length", "Id", "Date", "Etag", "Last-Modified"}
	(*w).Header().Set("Access-Control-Allow-Origin", "*")
	(*w).Header().Set("Access-Control-Allow-Methods", "GET,POST")
	(*w).Header().Set("Access-Control-Allow-Headers", strings.Join(lpHdrs[:], ","))
	(*w).Header().Set("Access-Control-Expose-Headers", strings.Join(resHdrs[:], ","))
}
