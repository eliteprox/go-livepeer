package server

import (
	"context"
	"errors"
	"fmt"
	gonet "net"

	//"net/http"
	//"crypto/tls"
	"encoding/json"
	"io/ioutil"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/golang/glog"
	"github.com/livepeer/go-livepeer/clog"
	lpcrypto "github.com/livepeer/go-livepeer/crypto"
	"github.com/livepeer/go-livepeer/net"
	probing "github.com/prometheus-community/pro-bing"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/peer"
)

const getOrchestratorTimeout = 2 * time.Second

var errNoOrchestrators = errors.New("no orchestrators")

type Router struct {
	uris []*url.URL
	srv  *grpc.Server
}

func (r *Router) EndTranscodingSession(ctx context.Context, request *net.EndTranscodingSessionRequest) (*net.EndTranscodingSessionResponse, error) {
	// shouldn't ever be called on Router
	return &net.EndTranscodingSessionResponse{}, nil
}

func NewRouter(uris []*url.URL) *Router {
	return &Router{uris: uris}
}

func (r *Router) Start(uri *url.URL, serviceURI *url.URL, workDir string) error {
	listener, err := gonet.Listen("tcp", uri.Host)
	if err != nil {
		return err
	}
	defer listener.Close()

	certFile, keyFile, err := getCert(serviceURI, workDir)
	if err != nil {
		return err
	}

	creds, err := credentials.NewServerTLSFromFile(certFile, keyFile)
	if err != nil {
		return err
	}

	s := grpc.NewServer(grpc.Creds(creds))
	r.srv = s

	net.RegisterOrchestratorServer(s, r)

	grpc_health_v1.RegisterHealthServer(s, health.NewServer())

	errCh := make(chan error)
	go func() {
		errCh <- s.Serve(listener)
	}()

	time.Sleep(1 * time.Second)

	if err := checkAvailability(context.Background(), serviceURI); err != nil {
		s.Stop()
		return err
	}

	glog.Infof("Started router server at %v", uri)

	return <-errCh
}

func (r *Router) Stop() {
	r.srv.Stop()
}

func (r *Router) GetOrchestrator(ctx context.Context, req *net.OrchestratorRequest) (*net.OrchestratorInfo, error) {
	return getOrchestratorInfo(ctx, r.uris, req)
}

func (r *Router) Ping(ctx context.Context, req *net.PingPong) (*net.PingPong, error) {
	return &net.PingPong{Value: []byte{}}, nil
}

func checkAvailability(ctx context.Context, uri *url.URL) error {
	client, conn, err := startOrchestratorClient(ctx, uri)
	if err != nil {
		return err
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(clog.Clone(context.Background(), ctx), GRPCConnectTimeout)
	defer cancel()

	_, err = client.Ping(ctx, &net.PingPong{Value: []byte{}})
	if err != nil {
		return err
	}

	return nil
}

func getOrchestratorInfo(ctx context.Context, uris []*url.URL, req *net.OrchestratorRequest) (*net.OrchestratorInfo, error) {
	if len(uris) == 0 {
		return nil, errNoOrchestrators
	}

	infoCh := make(chan *net.OrchestratorInfo)
	errCh := make(chan error, len(uris))

	cctx, cancel := context.WithTimeout(ctx, getOrchestratorTimeout)
	defer cancel()

	for _, uri := range uris {
		go func(uri *url.URL) {
			client, conn, err := startOrchestratorClient(ctx, uri)
			if err != nil {
				errCh <- fmt.Errorf("%v err=%q", uri, err)
				return
			}
			defer conn.Close()

			info, err := client.GetOrchestrator(cctx, req)
			if err != nil {
				errCh <- fmt.Errorf("%v err=%q", uri, err)
				return
			}

			select {
			case infoCh <- info:
			default:
			}
		}(uri)
	}

	errCtr := 0
	for {
		select {
		case info := <-infoCh:
			glog.Infof("Forwarding OrchestratorInfo orch=%v", info.Transcoder)
			return info, nil
		case err := <-errCh:
			glog.Error(err)
			errCtr++
			if errCtr >= len(uris) {
				return nil, errNoOrchestrators
			}
		case <-cctx.Done():
			return nil, errors.New("timed out")
		}
	}
}

var errNoClientIp = errors.New("cannot get client ip")
var errParsingClientIp = errors.New("error parsing client ip")

type LatencyRouter struct {
	srv                    *grpc.Server
	testBroadcasterIP      string
	workDir                string
	roundRobin             bool
	cacheTime              time.Duration
	searchTimeout          time.Duration
	pingBroadcasterTimeout time.Duration

	bmu                    sync.RWMutex
	closestOrchestratorToB map[string]LatencyCheckResponse
	orchNodes              map[url.URL]OrchNode

	cmu     sync.RWMutex
	clients map[url.URL]*LatencyClient
}

type OrchNode struct {
	uri       url.URL
	routerUri url.URL
	orchInfo  map[string]net.OrchestratorInfo
	updatedAt time.Time
}

type LatencyCheckResponse struct {
	RespTime    int64
	OrchUri     url.URL
	UpdatedAt   time.Time
	DoNotUpdate bool
}

type RouterUpdated struct {
	b_ip_addr           string
	orch_router_ip_addr string
	updated             bool
}

type LatencyClient struct {
	client net.LatencyCheckClient
	conn   *grpc.ClientConn
	err    error
}

func CreateOrchNode(uri *url.URL, router_uri *url.URL) OrchNode {
	return OrchNode{uri: *uri, routerUri: *router_uri, orchInfo: make(map[string]net.OrchestratorInfo)}
}

func NewLatencyRouter(orch_nodes []OrchNode, test_broadcaster_ip string, cache_time time.Duration, search_timeout time.Duration, ping_broadcaster_timeout time.Duration, round_robin bool) *LatencyRouter {
	router := &LatencyRouter{
		orchNodes:              make(map[url.URL]OrchNode),
		testBroadcasterIP:      test_broadcaster_ip,
		cacheTime:              cache_time,
		searchTimeout:          search_timeout,
		pingBroadcasterTimeout: ping_broadcaster_timeout,
		roundRobin:             round_robin,
		closestOrchestratorToB: make(map[string]LatencyCheckResponse),
		clients:                make(map[url.URL]*LatencyClient),
	}

	for _, orch_node := range orch_nodes {
		router.orchNodes[orch_node.uri] = orch_node
	}

	return router

}

func (r *LatencyRouter) EndTranscodingSession(ctx context.Context, request *net.EndTranscodingSessionRequest) (*net.EndTranscodingSessionResponse, error) {
	// shouldn't ever be called on Router
	glog.Errorf("EndTranscodingSession called, this should never happen...")
	return &net.EndTranscodingSessionResponse{}, nil
}

func (r *LatencyRouter) Ping(ctx context.Context, req *net.PingPong) (*net.PingPong, error) {
	return &net.PingPong{Value: []byte{}}, nil
}

func (r *LatencyRouter) Start(uri *url.URL, serviceURI *url.URL, workDir string) error {
	r.workDir = workDir

	listener, err := gonet.Listen("tcp", uri.Host)
	if err != nil {
		return err
	}
	defer listener.Close()

	certFile, keyFile, err := getCert(serviceURI, workDir)
	if err != nil {
		return err
	}

	creds, err := credentials.NewServerTLSFromFile(certFile, keyFile)
	if err != nil {
		return err
	}

	s := grpc.NewServer(grpc.Creds(creds))
	r.srv = s

	net.RegisterLatencyCheckServer(s, r)
	net.RegisterOrchestratorServer(s, r)                       //to use the GetOrchestrator rpc client
	grpc_health_v1.RegisterHealthServer(s, health.NewServer()) //TODO: why is this included?

	errCh := make(chan error)
	go func() {
		errCh <- s.Serve(listener)
	}()

	time.Sleep(1 * time.Second)

	if err := checkAvailability(context.Background(), serviceURI); err != nil {
		s.Stop()
		return err
	}

	glog.Infof("started router server at %v", uri)

	glog.Infof("loading routing")
	r.LoadRouting()

	glog.Infof("starting router clients")
	r.CreateClients()
	go func() {
		//check if clients are connected every minute, try to connect if not connected
		r.MonitorClients()
	}()

	//if test ips are specified, start testing
	if r.testBroadcasterIP != "" {
		for _, broadcaster_ip := range strings.Split(r.testBroadcasterIP, ",") {
			broadcaster_ip = strings.TrimSpace(broadcaster_ip)
			net_addr, err := gonet.ResolveTCPAddr("tcp", broadcaster_ip+":43674")
			if err == nil {
				ctx, cancel := context.WithTimeout(context.Background(), time.Duration(2*time.Second))
				defer cancel()
				t_ctx := peer.NewContext(ctx, &peer.Peer{Addr: net_addr, AuthInfo: nil})
				r.GetOrchestrator(t_ctx, &net.OrchestratorRequest{})
				<-ctx.Done()
				glog.Infof("test ping completed for ip %s", broadcaster_ip)
			} else {
				glog.Errorf("error testing broadcaster ip: %q", err)
			}
		}
	}

	return <-errCh
}

func (r *LatencyRouter) Stop() {
	for _, client_conn := range r.clients {
		if client_conn.err == nil {
			client_conn.conn.Close()
		}
	}

	r.srv.Stop()
}

func (r *LatencyRouter) SaveRouting() {
	//save routing to load on startup
	file, _ := json.MarshalIndent(r.closestOrchestratorToB, "", " ")
	err := ioutil.WriteFile(filepath.Join(r.workDir, "routing.json"), file, 0644)
	if err != nil {
		glog.Errorf("error saving routing: %v", err.Error())
	}

	return
}

func (r *LatencyRouter) LoadRouting() {
	json_file, err := ioutil.ReadFile(filepath.Join(r.workDir, "routing.json"))
	if err != nil {
		glog.Errorf("error reading routing file: %v", err.Error())
	}

	err = json.Unmarshal([]byte(json_file), &r.closestOrchestratorToB)
	if err != nil {
		glog.Errorf("error loading routing: %v", err.Error())
	}

	return
}

func (r *LatencyRouter) GetOrchestrator(ctx context.Context, req *net.OrchestratorRequest) (*net.OrchestratorInfo, error) {
	st := time.Now()
	//get broadcaster addr
	client_addr, ok := peer.FromContext(ctx)
	if ok {
		glog.Infof("%v  GetOrchestrator request received", client_addr.Addr.String())
	} else {
		return nil, errNoClientIp
	}

	client_ip, _, ip_err := gonet.SplitHostPort(client_addr.Addr.String())
	if ip_err != nil {
		glog.Errorf("%v  error parsing peer address: %q", client_addr.Addr.String(), ip_err)
		return nil, ip_err
	}

	//verify GetOrchestrator request
	b_addr := ethcommon.BytesToAddress(req.GetAddress())
	if r.VerifySig(b_addr.Hex(), req.GetSig()) == false {
		glog.Infof("%v  GetOrchestrator request failed verification", client_addr.Addr.String())
		return nil, errors.New("GetOrchestrator request failed verification")
	}

	//get the closest orchestrator
	orch_info, err := r.getOrchestratorInfoClosestToB(ctx, req, client_ip)
	if err == nil {
		glog.Infof("%v  sending closest orchestrator info in %s  addr 0x%v sig 0x%v", client_ip, time.Since(st), ethcommon.Bytes2Hex(req.GetAddress()), ethcommon.Bytes2Hex(req.GetSig()))
		return orch_info, nil
	} else {
		glog.Errorf("%v  failed to return orchestrator info: %v", client_ip, err.Error())
		glog.Errorf("%v  failed to get orch info for request  time: %v   ctx err: %v   addr 0x%v   sig 0x%v", client_ip, time.Since(st), ctx.Err(), ethcommon.Bytes2Hex(req.GetAddress()), ethcommon.Bytes2Hex(req.GetSig()))
		return nil, err
	}
}

// include GetOrchestrator request verification similar to rpc.go for orchestrator
func (r *LatencyRouter) VerifySig(msg string, sig []byte) bool {
	return lpcrypto.VerifySig(ethcommon.HexToAddress(msg), crypto.Keccak256([]byte(msg)), sig)
}

func (r *LatencyRouter) GetLatency(ctx context.Context, req *net.BroadcasterLatencyReq) (*net.LatencyCheckRes, error) {
	glog.Infof("%v  received latency check request, pinging to provide latency", req.GetUri())

	pingTime := r.SendPing(ctx, req.GetUri())
	glog.Infof("%v  latency check ping completed in %v milliseconds", req.GetUri(), pingTime)
	return &net.LatencyCheckRes{RespTime: pingTime}, nil
}

func (r *LatencyRouter) UpdateRouter(ctx context.Context, req *net.ClosestOrchestratorReq) (*net.ClosestOrchestratorRes, error) {

	b_uri := req.GetBroadcasterUri()
	o_uri, _ := url.Parse(req.GetOrchestratorUri())
	respTime := req.GetRespTime()

	r.SetClosestOrchestrator(b_uri, &LatencyCheckResponse{RespTime: respTime, OrchUri: *o_uri, UpdatedAt: time.Now(), DoNotUpdate: false})
	glog.Infof("%v  router updated to provide orchestrator %v", b_uri, o_uri)
	return &net.ClosestOrchestratorRes{Updated: true}, nil
}

func (r *LatencyRouter) getOrchestratorInfoClosestToB(ctx context.Context, req *net.OrchestratorRequest, client_ip string) (*net.OrchestratorInfo, error) {
	totOrch := len(r.orchNodes)
	if totOrch == 0 {
		return nil, errNoOrchestrators
	}

	//check if in cache period
	cachedOrchResp, err := r.GetClosestOrchestrator(client_ip)
	if err == nil && r.cacheTime > time.Second {
		time_since_cached := time.Now().Sub(cachedOrchResp.UpdatedAt)
		if time_since_cached < r.cacheTime || cachedOrchResp.DoNotUpdate {
			//get fresh OrchestratorInfo each time
			//cached_info := r.GetOrchNodeInfo(client_ip, cachedOrchResp.OrchUri)
			cached_info, err := r.GetOrchestratorInfo(ctx, client_ip, req, cachedOrchResp.OrchUri)
			if err == nil {
				glog.Infof("%v  returning orchestrator info cached %s ago  orch addr: %v priceperunit: %v", client_ip, time_since_cached.Round(time.Second), cached_info.GetTranscoder(), cached_info.PriceInfo.GetPricePerUnit())
				return cached_info, nil
			}
		}
	}

	//send request to each orch node in separate go routine to concurrently process
	// results come into latencyCh and errors come in errCh
	latencyCh := make(chan LatencyCheckResponse, totOrch)
	errCh := make(chan error, totOrch)
	totCh := make(chan int, totOrch)

	errCtr := 0
	respCtr := 0
	totCtr := 0
	var responses []LatencyCheckResponse
	lctx, cancel := context.WithTimeout(ctx, r.searchTimeout)
	defer cancel()

	for _, orch_node := range r.orchNodes {
		go func(b_ip_addr string, orch_node OrchNode) {
			client := r.GetClient(orch_node.uri)
			if client == nil {
				glog.Infof("%v  rpc client is not connected for %v", b_ip_addr, orch_node.routerUri.String())
				errCh <- errors.New("client not available for " + orch_node.uri.String())
				return
			}
			glog.Infof("%v  sending latency check request for to orch at %v", b_ip_addr, orch_node.routerUri.String())
			latencyCheckRes, err := client.GetLatency(lctx, &net.BroadcasterLatencyReq{Uri: b_ip_addr})
			if err != nil {
				errCh <- fmt.Errorf("%v err=%q", orch_node.routerUri, err)
				return
			}

			select {
			case latencyCh <- LatencyCheckResponse{RespTime: latencyCheckRes.GetRespTime(), OrchUri: orch_node.uri, UpdatedAt: time.Now(), DoNotUpdate: false}:
			default:
			}
		}(client_ip, orch_node)
	}

	for {
		select {
		case latencyCheckResp := <-latencyCh:
			responses = append(responses, latencyCheckResp)
			respCtr++

			glog.Infof("%v  received latency check from %v with ping time of %vms", client_ip, latencyCheckResp.OrchUri.String(), latencyCheckResp.RespTime)
			//if want to early return, do it here
			if !r.roundRobin {
				return r.SendOrchInfo(ctx, client_ip, req, responses)
			}
			//update tracking total responses
			totCh <- 1
		case err := <-errCh:
			glog.Error(err.Error())
			errCtr++
			//update tracking total responses
			totCh <- 1
		case <-totCh:
			totCtr++
			if totCtr >= len(r.orchNodes) && r.roundRobin {
				//sort the responses based on ping time
				sort.Slice(responses, func(i, j int) bool {
					return responses[i].RespTime < responses[j].RespTime
				})

				return r.SendOrchInfo(ctx, client_ip, req, responses)
			}
		case <-lctx.Done():
			//when the context time limit is complete, return the closest orchestrator so far
			return r.SendOrchInfo(ctx, client_ip, req, responses)
		}
	}
}

func (r *LatencyRouter) SendOrchInfo(ctx context.Context, client_ip string, req *net.OrchestratorRequest, responses []LatencyCheckResponse) (*net.OrchestratorInfo, error) {
	//get orchestrator info for fastest resp time O
	for idx, _ := range responses {
		//get the response from O
		info, err := r.GetOrchestratorInfo(ctx, client_ip, req, responses[idx].OrchUri)
		if err == nil {
			//cache it
			r.SetClosestOrchestrator(client_ip, &responses[idx])
			//update the other routers
			go r.updateRouters(client_ip, &responses[idx])
			glog.Infof("%v  received all responses, sending orchestrator info for %v  orch addr: %v  priceperunit: %v", client_ip, responses[idx].OrchUri.String(), info.GetTranscoder(), info.PriceInfo.GetPricePerUnit())

			return info, err
		} else {
			glog.Infof("%v  received all responses, orchestrator failed response for %v  error: %v", client_ip, responses[idx].OrchUri.String(), err.Error())
		}
	}
	//none of the Os returns a GetOrchestrator response, return no orchestrators error
	return nil, errNoOrchestrators
}

func (r *LatencyRouter) GetClosestOrchestrator(b_ip_addr string) (LatencyCheckResponse, error) {
	r.bmu.RLock()
	defer r.bmu.RUnlock()
	closestOrchWithResp, client_ip_exists := r.closestOrchestratorToB[b_ip_addr]
	if client_ip_exists {
		return closestOrchWithResp, nil
	} else {
		return LatencyCheckResponse{}, errNoOrchestrators
	}
}

func (r *LatencyRouter) SetClosestOrchestrator(b_ip_addr string, resp *LatencyCheckResponse) {
	r.bmu.Lock()
	defer r.bmu.Unlock()
	//cache the fastest O to the B
	r.closestOrchestratorToB[b_ip_addr] = *resp

	return
}

// TODO: this is not needed if cannot cache the OrchestratorInfo response
func (r *LatencyRouter) GetOrchNodeInfo(b_ip_addr string, orch_uri url.URL) *net.OrchestratorInfo {
	r.bmu.RLock()
	defer r.bmu.RUnlock()
	orch_node, orch_node_exists := r.orchNodes[orch_uri]
	if orch_node_exists {
		orch_info, b_exists := orch_node.orchInfo[b_ip_addr]
		if b_exists {
			return &orch_info
		} else {
			return nil
		}
	} else {
		return nil
	}
}

// TODO: this is not needed if cannot cache the OrchestratorInfo response
func (r *LatencyRouter) SetOrchNodeInfo(b_ip_addr string, orch_uri url.URL, orch_info *net.OrchestratorInfo) {
	r.bmu.Lock()
	defer r.bmu.Unlock()

	//clone the orch info to OrchNode to cache and remove reference to pointer
	glog.Infof("%v  orch info cached for %v at %v", b_ip_addr, orch_uri.String(), time.Now())
	node, ok := r.orchNodes[orch_uri]
	if ok {
		node.orchInfo[b_ip_addr] = *orch_info
		node.updatedAt = time.Now()
	}
	r.orchNodes[orch_uri] = node
}

func (r *LatencyRouter) GetOrchestratorInfo(ctx context.Context, b_ip_addr string, req *net.OrchestratorRequest, orch_uri url.URL) (*net.OrchestratorInfo, error) {
	client, conn, err := startOrchestratorClient(ctx, &orch_uri)
	if err != nil {
		glog.Errorf("%v  could not connect to Orchestrator %v  err: %s", b_ip_addr, orch_uri.String(), err.Error())
		return nil, err
	}
	defer conn.Close()

	cctx, cancel := context.WithTimeout(ctx, getOrchestratorTimeout)
	defer cancel()

	info, err := client.GetOrchestrator(cctx, req)
	if err != nil {
		glog.Errorf("%v  could not get OrchestratorInfo from %v, err: %s", b_ip_addr, orch_uri.String(), err.Error())
		return nil, err
	}

	//new OrchestratorInfo fetched each time a GetOrchestrator request is received
	//r.SetOrchNodeInfo(b_ip_addr, orch_uri, info)
	return info, nil
}

func (r *LatencyRouter) SendPing(ctx context.Context, b_ip_addr string) int64 {
	pinger, err := probing.NewPinger(b_ip_addr)
	if err != nil {
		panic(err)
	}
	pinger.Interval = 1 * time.Millisecond
	pinger.Timeout = r.pingBroadcasterTimeout
	pinger.Count = 2
	pinger.SetPrivileged(true)

	p_err := pinger.Run() // Blocks until finished.
	if p_err != nil {
		panic(p_err)
	}
	stats := pinger.Statistics() // get send/receive/duplicate/rtt stats
	glog.Infof("%v  ping test results:  %vms  %vperc packet loss", b_ip_addr, stats.AvgRtt.Milliseconds(), stats.PacketLoss)
	return stats.AvgRtt.Milliseconds()
}

func (r *LatencyRouter) updateRouters(b_ip_addr string, resp *LatencyCheckResponse) {
	updateCh := make(chan RouterUpdated, len(r.orchNodes))
	errCh := make(chan error, len(r.orchNodes))

	upd_ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for _, orch_node := range r.orchNodes {
		go func(orch_node OrchNode, b_ip_addr string, resp *LatencyCheckResponse) {
			client := r.GetClient(orch_node.uri)
			if client != nil {
				updateRouterRes, _ := client.UpdateRouter(upd_ctx, &net.ClosestOrchestratorReq{BroadcasterUri: b_ip_addr, OrchestratorUri: resp.OrchUri.String(), RespTime: resp.RespTime})
				select {
				case updateCh <- RouterUpdated{b_ip_addr: b_ip_addr, orch_router_ip_addr: orch_node.routerUri.String(), updated: updateRouterRes.GetUpdated()}:
				default:
				}
			}
		}(orch_node, b_ip_addr, resp)
	}

	errCtr := 0
	updateCtr := 0
	for {
		select {
		case routerUpdated := <-updateCh:
			updateCtr++
			glog.Infof("Router updated b_addr=%s status=%v (%v of %v, %v errors)", b_ip_addr, routerUpdated.updated, updateCtr, len(r.orchNodes), errCtr)
		case err := <-errCh:
			errCtr++
			glog.Infof("Failed router update b_addr=%s status=%v (%v of %v, %v errors)", b_ip_addr, false, updateCtr, len(r.orchNodes), errCtr)
			glog.Error(err)
		case <-upd_ctx.Done():
			glog.Infof("Updating routers completed")
			return
		}
	}
}

// TODO: add checks that connection is open
func (r *LatencyRouter) MonitorClients() {
	for {
		//sleep for 5 miinutes and check again
		time.Sleep(1 * time.Minute)
		for _, orch_node := range r.orchNodes {
			if r.clients[orch_node.uri].err != nil {
				client, conn, err := startLatencyRouterClient(context.Background(), orch_node.routerUri)
				r.SetClient(orch_node.uri, LatencyClient{client: client, conn: conn, err: err})
			}
		}
		//save routing json for backup
		r.SaveRouting()
	}
}

func (r *LatencyRouter) CreateClients() {
	for _, orch_node := range r.orchNodes {
		client, conn, err := startLatencyRouterClient(context.Background(), orch_node.routerUri)
		r.SetClient(orch_node.uri, LatencyClient{client: client, conn: conn, err: err})
	}
}

func (r *LatencyRouter) GetClient(orch_uri url.URL) net.LatencyCheckClient {
	r.cmu.RLock()
	defer r.cmu.RUnlock()

	orch_client, orch_client_exists := r.clients[orch_uri]
	if orch_client_exists {
		if orch_client.client != nil {
			return orch_client.client
		} else {
			//check node exists and create the client
			orch_node, orch_exists := r.orchNodes[orch_uri]
			if orch_exists {
				client, conn, err := startLatencyRouterClient(context.Background(), orch_node.routerUri)
				r.SetClient(orch_uri, LatencyClient{client: client, conn: conn, err: err})
				return client
			} else {
				return nil
			}
		}
	} else {
		return nil
	}
}

func (r *LatencyRouter) SetClient(orch_uri url.URL, client LatencyClient) {
	r.cmu.Lock()
	defer r.cmu.Unlock()
	r.clients[orch_uri] = &client
}

func startLatencyRouterClient(ctx context.Context, router_uri url.URL) (net.LatencyCheckClient, *grpc.ClientConn, error) {
	glog.Infof("Connecting RPC to uri=%v", router_uri.String())
	conn, err := grpc.Dial(router_uri.Host,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
		grpc.WithBlock(),
		grpc.WithTimeout(GRPCConnectTimeout))
	if err != nil {
		glog.Errorf("Did not connect to orch=%v error=%v", router_uri.String(), err.Error())
		return nil, nil, err

	}
	c := net.NewLatencyCheckClient(conn)

	return c, conn, nil
}
