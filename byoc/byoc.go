package byoc

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	"github.com/golang/glog"
	"github.com/livepeer/go-livepeer/core"
	"github.com/livepeer/go-livepeer/media"
	"github.com/livepeer/go-livepeer/trickle"
)

// BYOCServer orchestrates the BYOC handlers and registers routes

type BYOCOrchestratorServer struct {
	node            *core.LivepeerNode
	orch            Orchestrator
	trickleSrv      *trickle.Server
	trickleBasePath string

	httpMux *http.ServeMux
}

type BYOCGatewayServer struct {
	node       *core.LivepeerNode
	httpMux    *http.ServeMux
	whipServer *media.WHIPServer
	whepServer *media.WHEPServer

	statusStore     StatusStore
	slowOrchChecker SlowOrchChecker

	LivePipelines map[string]*BYOCLivePipeline
	mu            *sync.RWMutex
}

// NewBYOCServer creates a new BYOC server instance
func NewBYOCGatewayServer(node *core.LivepeerNode, statusStore StatusStore, slowOrchChecker SlowOrchChecker, whipServer *media.WHIPServer, whepServer *media.WHEPServer, mux *http.ServeMux) *BYOCGatewayServer {
	bsg := &BYOCGatewayServer{
		node:            node,
		httpMux:         mux,
		statusStore:     statusStore,
		slowOrchChecker: slowOrchChecker,
		whipServer:      whipServer,
		whepServer:      whepServer,
		mu:              &sync.RWMutex{},
	}

	bsg.LivePipelines = make(map[string]*BYOCLivePipeline)

	bsg.registerRoutes()
	return bsg
}

func NewBYOCOrchestratorServer(node *core.LivepeerNode, orch Orchestrator, trickleSrv *trickle.Server, trickleBasePath string, mux *http.ServeMux) *BYOCOrchestratorServer {
	bso := &BYOCOrchestratorServer{
		node:            node,
		orch:            orch,
		trickleSrv:      trickleSrv,
		trickleBasePath: trickleBasePath,
		httpMux:         mux,
	}

	bso.registerRoutes()
	return bso
}

func (bsg *BYOCGatewayServer) newLivePipeline(requestID, streamID, pipeline string, streamParams byocAIRequestParams, streamRequest []byte) *BYOCLivePipeline {
	streamCtx, streamCancel := context.WithCancelCause(context.Background())
	bsg.mu.Lock()
	defer bsg.mu.Unlock()

	//ensure streamRequest is not nil or empty to avoid json unmarshal issues on Orchestrator failover
	//sends the request bytes to next Orchestrator
	if streamRequest == nil || len(streamRequest) == 0 {
		streamRequest = []byte("{}")
	}

	bsg.LivePipelines[streamID] = &BYOCLivePipeline{
		RequestID:     requestID,
		StreamID:      streamID,
		Pipeline:      pipeline,
		streamCtx:     streamCtx,
		streamParams:  streamParams,
		streamCancel:  streamCancel,
		streamRequest: streamRequest,
		OutCond:       sync.NewCond(bsg.mu),
	}
	return bsg.LivePipelines[streamID]
}

func (bsg *BYOCGatewayServer) livePipeline(streamId string) (*BYOCLivePipeline, error) {
	bsg.mu.Lock()
	defer bsg.mu.Unlock()
	p, exists := bsg.LivePipelines[streamId]
	if !exists {
		return nil, fmt.Errorf("BYOC Live pipeline %s not found", streamId)
	}
	return p, nil
}

func (bsg *BYOCGatewayServer) livePipelineExists(streamId string) bool {
	bsg.mu.Lock()
	defer bsg.mu.Unlock()
	_, exists := bsg.LivePipelines[streamId]
	return exists
}

func (bsg *BYOCGatewayServer) stopLivePipeline(streamId string, err error) {
	p, err := bsg.livePipeline(streamId)
	if err == nil {
		glog.Info("found pipeline, stopping")
		p.OutCond.Broadcast()
		if p.ControlPub != nil {
			if err := p.ControlPub.Close(); err != nil {
				glog.Errorf("Error closing trickle publisher", err)
			}
			if p.StopControl != nil {
				p.StopControl()
			}
		}
		glog.Info("canceling stream")
		p.streamCancel(err)
		p.Closed = true
	}
}

func (bsg *BYOCGatewayServer) removeLivePipeline(streamId string) {
	bsg.mu.Lock()
	defer bsg.mu.Unlock()
	delete(bsg.LivePipelines, streamId)
}

func (bsg *BYOCGatewayServer) livePipelineParams(streamId string) (byocAIRequestParams, error) {
	bsg.mu.Lock()
	defer bsg.mu.Unlock()
	p, exists := bsg.LivePipelines[streamId]
	if !exists {
		return byocAIRequestParams{}, fmt.Errorf("BYOC Live pipeline %s not found", streamId)
	}
	return p.streamParams, nil
}

func (bsg *BYOCGatewayServer) updateLivePipelineParams(streamId string, newParams byocAIRequestParams) {
	bsg.mu.Lock()
	defer bsg.mu.Unlock()
	p, exists := bsg.LivePipelines[streamId]
	if exists {
		p.streamParams = newParams
	}
}

func (bsg *BYOCGatewayServer) livePipelineContext(streamId string) context.Context {
	bsg.mu.Lock()
	defer bsg.mu.Unlock()
	if p, exists := bsg.LivePipelines[streamId]; exists {
		return p.streamCtx
	}
	return nil
}

func (bsg *BYOCGatewayServer) livePipelineRequest(streamId string) []byte {
	bsg.mu.Lock()
	defer bsg.mu.Unlock()
	p, exists := bsg.LivePipelines[streamId]
	if exists {
		return p.streamRequest
	}

	return nil
}

// registerRoutes registers all BYOC related routes
func (bsg *BYOCGatewayServer) registerRoutes() {
	// CORS preflight
	bsg.httpMux.Handle("OPTIONS /ai/stream/", bsg.withCORS(http.StatusNoContent))

	// Stream routes
	bsg.httpMux.Handle("POST /ai/stream/start", bsg.StartStream())
	bsg.httpMux.Handle("POST /ai/stream/{streamId}/update", bsg.UpdateStream())
	bsg.httpMux.Handle("GET /ai/stream/{streamId}/status", bsg.StreamStatus())
	bsg.httpMux.Handle("POST /ai/stream/{streamId}/stop", bsg.StopStream())
	bsg.httpMux.Handle("GET /ai/stream/{streamId}/data", bsg.StreamData())
	bsg.httpMux.Handle("POST /ai/stream/{streamId}/rtmp", bsg.StartStreamRTMPIngest())
	if bsg.whipServer != nil {
		bsg.httpMux.Handle("POST /ai/stream/{streamId}/whip", bsg.StartStreamWhipIngest(bsg.whipServer))
	}

	//TODO: add WHEP support

	// Job submission routes
	bsg.httpMux.Handle("/process/request/", bsg.SubmitJob())
}

// withCORS adds CORS headers to responses
func (bs *BYOCGatewayServer) withCORS(statusCode int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		corsHeaders(w, r.Method)
		w.WriteHeader(statusCode)
	})
}

func (bso *BYOCOrchestratorServer) registerRoutes() {
	// Job submission routes
	bso.httpMux.Handle("/process/request/", bso.ProcessJob())
	bso.httpMux.Handle("/process/token", bso.GetJobToken())
	bso.httpMux.Handle("/capability/register", bso.RegisterCapability())
	bso.httpMux.Handle("/capability/unregister", bso.UnregisterCapability())
	// Stream routes
	bso.httpMux.Handle("/ai/stream/start", bso.StartStream())
	bso.httpMux.Handle("/ai/stream/stop", bso.StopStream())
	bso.httpMux.Handle("/ai/stream/update", bso.UpdateStream())
	bso.httpMux.Handle("/ai/stream/payment", bso.ProcessStreamPayment())
}
