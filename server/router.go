package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	gonet "net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
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

type ClientInfo struct {
	addr string
	ip   string
	port string
}

type LatencyRouter struct {
	srv                    *grpc.Server
	testBroadcasterIP      string
	workDir                string
	roundRobin             bool
	cacheTime              time.Duration
	searchTimeout          time.Duration
	pingBroadcasterTimeout time.Duration
	secret                 string

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

func (r *LatencyRouter) Start(uri *url.URL, serviceURI *url.URL, dataPort string, workDir string, secret string, backgroundUpdate bool) error {
	r.workDir = workDir
	r.secret = secret

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

	go func() {
		dataURI := &url.URL{
			Scheme: serviceURI.Scheme,
			Host:   serviceURI.Hostname() + ":" + dataPort,
			Path:   serviceURI.Path,
		}
		tlsConfig := &tls.Config{
			MinVersion: tls.VersionTLS12, // Minimum TLS version supported
			// You can further configure TLS settings here if needed
		}

		srv := &http.Server{Addr: dataURI.Host, TLSConfig: tlsConfig}
		mux := http.DefaultServeMux
		http.DefaultServeMux = http.NewServeMux()

		mux.Handle("/routingdata/", r.basicAuth(r.handleGetRoutingData))

		mux.Handle("/updateroutingdata", r.basicAuth(r.handleUpdateRoutingData))

		mux.Handle("/api/health", r.basicAuth(r.handleNodeGraphHealth))

		mux.Handle("/api/graph/fields", r.basicAuth(r.handleNodeGraphFields))

		mux.Handle("/api/graph/data", r.basicAuth(r.handleNodeGraphData))
		srv.Handler = mux

		glog.Infof("started router data server at %v", dataURI)
		err = srv.ListenAndServeTLS(certFile, keyFile)
		if err != nil {
			glog.Fatal(err)
		}

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

	if backgroundUpdate {
		go func() {
			//check if ping should be updated
			r.MonitorBroadcasters()
		}()
	}

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
	r.SaveRoutingJson(file)

	return
}

func (r *LatencyRouter) SaveRoutingJson(json_data []byte) {
	r.bmu.Lock()
	defer r.bmu.Unlock()
	err := ioutil.WriteFile(filepath.Join(r.workDir, "routing.json"), json_data, 0644)
	if err != nil {
		glog.Errorf("error saving routing: %v", err.Error())
	}
}

func (r *LatencyRouter) LoadRouting() {
	r.bmu.Lock()
	defer r.bmu.Unlock()
	routing_file := filepath.Join(r.workDir, "routing.json")
	if _, err := os.Stat(routing_file); err == nil {
		json_file, err := ioutil.ReadFile(routing_file)
		if err != nil {
			glog.Errorf("error reading routing file: %v", err.Error())
		}

		err = json.Unmarshal([]byte(json_file), &r.closestOrchestratorToB)
		if err != nil {
			glog.Errorf("error loading routing: %v", err.Error())
		}
	} else {
		glog.Errorf("no routing file exists")
	}
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

	//verify GetOrchestrator request
	b_addr := ethcommon.BytesToAddress(req.GetAddress())
	if r.VerifySig(b_addr.Hex(), req.GetSig()) == false {
		glog.Infof("%v  GetOrchestrator request failed verification", client_addr.Addr.String())
		return nil, errors.New("GetOrchestrator request failed verification")
	}

	//get the closest orchestrator
	orch_info, err := r.getOrchestratorInfoClosestToB(context.Background(), req, client_addr.Addr.String())
	if orch_info != nil && err == nil {
		glog.Infof("%v  sending closest orchestrator info in %s  addr %v", client_addr.Addr.String(), time.Since(st), b_addr.Hex())
		return orch_info, nil
	} else {
		if errors.Is(err, context.Canceled) == false {
			glog.Errorf("%v  failed to return orchestrator info: %v", client_addr.Addr.String(), err.Error())
			glog.Errorf("%v  failed to get orch info for request  time: %v   ctx err: %v   addr %v", client_addr.Addr.String(), time.Since(st), ctx.Err(), b_addr.Hex())
		} else {
			glog.Errorf("%v  request canceled by Broadcaster in %v ", client_addr.Addr.String())
		}

		return nil, err
	}
}

// include GetOrchestrator request verification similar to rpc.go for orchestrator
func (r *LatencyRouter) VerifySig(msg string, sig []byte) bool {
	return lpcrypto.VerifySig(ethcommon.HexToAddress(msg), crypto.Keccak256([]byte(msg)), sig)
}

func (r *LatencyRouter) getOrchestratorInfoClosestToB(ctx context.Context, req *net.OrchestratorRequest, client_addr string) (*net.OrchestratorInfo, error) {
	totOrch := len(r.orchNodes)
	if totOrch == 0 {
		return nil, errNoOrchestrators
	}

	client_ip, client_port, ip_err := gonet.SplitHostPort(client_addr)
	if ip_err != nil {
		glog.Errorf("%v  error parsing peer address: %q", client_addr, ip_err)
		return nil, ip_err
	}

	client_info := ClientInfo{addr: client_addr, ip: client_ip, port: client_port}

	//check if in cache period
	//skip if no cached orchestrator, cacheTime not set or the OrchestratorRequest is nil
	cachedOrchResp, err := r.GetClosestOrchestrator(client_info)
	if err == nil && r.cacheTime > time.Second && req != nil {
		time_since_cached := time.Now().Sub(cachedOrchResp.UpdatedAt)
		if time_since_cached < r.cacheTime || cachedOrchResp.DoNotUpdate {
			//get fresh OrchestratorInfo each time
			cached_info, err := r.GetOrchestratorInfo(ctx, client_info, req, cachedOrchResp.OrchUri)
			if err == nil {
				glog.Infof("%v  returning orchestrator cached %s ago  orch addr: %v priceperunit: %v", client_addr, time_since_cached.Round(time.Second), cached_info.GetTranscoder(), cached_info.PriceInfo.GetPricePerUnit())
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
		go func(b_info ClientInfo, orch_node OrchNode) {
			client := r.GetClient(orch_node.uri)
			if client == nil {
				glog.Infof("%v  rpc client is not connected for %v", b_info.addr, orch_node.routerUri.String())
				errCh <- errors.New("client not available for " + orch_node.uri.String())
				return
			}
			glog.Infof("%v  sending latency check request to orch at %v", b_info.addr, orch_node.routerUri.String())
			latencyCheckRes, err := client.GetLatency(lctx, &net.BroadcasterLatencyReq{Uri: b_info.addr})
			if err != nil {
				errCh <- fmt.Errorf("%v err=%q", orch_node.routerUri, err)
				return
			}

			select {
			case latencyCh <- LatencyCheckResponse{RespTime: latencyCheckRes.GetRespTime(), OrchUri: orch_node.uri, UpdatedAt: time.Now(), DoNotUpdate: false}:
			default:
			}
		}(client_info, orch_node)
	}

	for {
		select {
		case latencyCheckResp := <-latencyCh:
			responses = append(responses, latencyCheckResp)
			respCtr++

			glog.Infof("%v  received latency check from %v with ping time of %vms", client_addr, latencyCheckResp.OrchUri.String(), latencyCheckResp.RespTime)
			//if want to early return, do it here
			if !r.roundRobin {
				return r.SendOrchInfo(ctx, client_info, req, responses)
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
				return r.SendOrchInfo(ctx, client_info, req, responses)
			}
		case <-lctx.Done():
			//when the context time limit is complete, return the closest orchestrator so far
			glog.Infof("%v  searchTimeout expired, sending OrchestratorInfo for responses received (%v of %v)", client_addr, totCtr, len(r.orchNodes))
			return r.SendOrchInfo(ctx, client_info, req, responses)
		}
	}
}

func (r *LatencyRouter) SendOrchInfo(ctx context.Context, client_info ClientInfo, req *net.OrchestratorRequest, responses []LatencyCheckResponse) (*net.OrchestratorInfo, error) {
	//sort the responses based on ping time
	sort.Slice(responses, func(i, j int) bool {
		return responses[i].RespTime < responses[j].RespTime
	})
	//if req is nil we are updating ping tests only, no OrchestratorInfo to send back
	if req == nil {
		for idx, _ := range responses {
			glog.Infof("%v  pinging Orchestrator to confirm status", client_info.addr)
			//rpc ping orch to check its up
			ping_test, err := r.PingOrchestrator(ctx, client_info.addr, responses[idx].OrchUri)
			if err != nil {
				glog.Infof("%v  rpc ping failed %v", client_info.addr, err.Error())
			}
			if ping_test {
				//cache it
				r.SetClosestOrchestrator(client_info, &responses[idx])
				//update the other routers
				go r.updateRouters(client_info.ip, &responses[idx])
				//return nil because we are just updating ping tests
				glog.Infof("%v  updated cached orchestrator to %v", client_info.addr, responses[idx].OrchUri.String())
				return nil, nil
			}

		}
		//if rpc ping does not work on any of the Orch nodes update latency check response so background process does not run again
		r.SetClosestOrchestrator(client_info, &responses[0])
		return nil, nil
	} else {
		//get orchestrator info for fastest resp time O
		for idx, _ := range responses {
			//get the response from O
			info, err := r.GetOrchestratorInfo(ctx, client_info, req, responses[idx].OrchUri)
			if err == nil {
				//cache it
				r.SetClosestOrchestrator(client_info, &responses[idx])
				//update the other routers
				go r.updateRouters(client_info.ip, &responses[idx])
				glog.Infof("%v  received all responses, sending orchestrator info for %v  orch addr: %v  priceperunit: %v", client_info.addr, responses[idx].OrchUri.String(), info.GetTranscoder(), info.PriceInfo.GetPricePerUnit())

				return info, err
			} else {
				glog.Infof("%v  received all responses, orchestrator failed response for %v  error: %v", client_info.addr, responses[idx].OrchUri.String(), err.Error())
			}
		}

		//none of the Os returns a GetOrchestrator response, return no orchestrators error
		//   when the router cannot connect to an O the searchTimeout will flush to here and return no orchestrators
		//   connections to O waits 3 seconds.
		return nil, errNoOrchestrators
	}
}

func (r *LatencyRouter) GetClosestOrchestrator(b_ip_addr ClientInfo) (LatencyCheckResponse, error) {
	r.bmu.RLock()
	defer r.bmu.RUnlock()
	closestOrchWithResp, client_ip_exists := r.closestOrchestratorToB[b_ip_addr.ip]
	if client_ip_exists {
		return closestOrchWithResp, nil
	} else {
		return LatencyCheckResponse{}, errNoOrchestrators
	}
}

func (r *LatencyRouter) SetClosestOrchestrator(b_ip_addr ClientInfo, resp *LatencyCheckResponse) {
	if resp.RespTime == 0 {
		resp.DoNotUpdate = true
	}

	r.bmu.Lock()
	defer r.bmu.Unlock()
	//cache the fastest O to the B
	r.closestOrchestratorToB[b_ip_addr.ip] = *resp

}

func (r *LatencyRouter) PingOrchestrator(ctx context.Context, broadcaster_ip string, orch_uri url.URL) (bool, error) {
	client, conn, err := startOrchestratorClient(ctx, &orch_uri)
	if err != nil {
		glog.Errorf("%v  could not connect to Orchestrator %v  err: %s", broadcaster_ip, orch_uri.String(), err.Error())
		return false, err
	}
	defer conn.Close()

	cctx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	_, ping_err := client.Ping(cctx, &net.PingPong{Value: []byte("are you there")})
	if ping_err == nil {
		return true, nil
	} else {
		return false, ping_err
	}
}

func (r *LatencyRouter) GetOrchestratorInfo(ctx context.Context, client_info ClientInfo, req *net.OrchestratorRequest, orch_uri url.URL) (*net.OrchestratorInfo, error) {
	client, conn, err := startOrchestratorClient(ctx, &orch_uri)
	if err != nil {
		glog.Errorf("%v  could not connect to Orchestrator %v  err: %s", client_info.addr, orch_uri.String(), err.Error())
		return nil, err
	}
	defer conn.Close()

	cctx, cancel := context.WithTimeout(ctx, getOrchestratorTimeout)
	defer cancel()

	info, err := client.GetOrchestrator(cctx, req)
	if err != nil {
		glog.Errorf("%v  could not get OrchestratorInfo from %v, err: %s", client_info.addr, orch_uri.String(), err.Error())
		return nil, err
	}

	return info, nil
}

func (r *LatencyRouter) MonitorBroadcasters() {
	glog.Infof("background process started to monitor and update pings to broadcasters, first check is in 1 minute")
	for {
		time.Sleep(1 * time.Minute)
		for broadcaster_ip, lat_chk_resp := range r.closestOrchestratorToB {
			if lat_chk_resp.DoNotUpdate == false && lat_chk_resp.UpdatedAt.Add(r.cacheTime).Before(time.Now().Add(10*time.Minute)) {
				glog.Infof("%v  updating ping times for broadcaster ip that will expire in %s", broadcaster_ip, lat_chk_resp.UpdatedAt.Add(r.cacheTime).Sub(time.Now()))
				go r.getOrchestratorInfoClosestToB(context.Background(), nil, broadcaster_ip+":80") //add port so can parse ip addr
			}
		}
	}
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

	r.SetClosestOrchestrator(ClientInfo{ip: b_uri}, &LatencyCheckResponse{RespTime: respTime, OrchUri: *o_uri, UpdatedAt: time.Now(), DoNotUpdate: false})
	glog.Infof("%v  router updated to provide orchestrator %v", b_uri, o_uri)
	return &net.ClosestOrchestratorRes{Updated: true}, nil
}

func (r *LatencyRouter) SendPing(ctx context.Context, b_ip_addr string) int64 {

	addr_split := strings.Split(b_ip_addr, ":")

	pinger, err := probing.NewPinger(addr_split[0])
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
	glog.Infof("%v  ping test results:  %vms  %v%% packet loss", b_ip_addr, stats.AvgRtt.Milliseconds(), stats.PacketLoss)
	if stats.PacketLoss != 100 {
		return stats.AvgRtt.Milliseconds()
	} else {
		start := time.Now()
		took := int64(0)
		client := http.Client{
			Timeout: r.pingBroadcasterTimeout,
		}
		resp, err := client.Head("https://" + addr_split[0] + ":8935")
		if err != nil {
			took = time.Since(start).Milliseconds()
		} else {
			defer resp.Body.Close()
			took = time.Since(start).Milliseconds()
		}
		glog.Infof("%v  icmp ping failed, using backup ping test results:  %vms  error: %s", b_ip_addr, took, err.Error())
		return time.Since(start).Milliseconds()
	}
}

func (r *LatencyRouter) updateRouters(b_ip_addr string, resp *LatencyCheckResponse) {
	//do not update if RespTime is 0 because the ping failed
	if resp.RespTime == 0 {
		return
	}
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

// update and reporting endpoints
// ===========================================================================================
func (r *LatencyRouter) handleGetRoutingData(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Disposition", "attachment; filename=routing.json")
	w.Header().Set("Content-Type", req.Header.Get("Content-Type"))

	if reader, err := os.Open(filepath.Join(r.workDir, "routing.json")); err == nil {
		defer reader.Close()
		io.Copy(w, reader)
	} else {
		respond500(w, "file not available")
	}
}

func (r *LatencyRouter) handleUpdateRoutingData(w http.ResponseWriter, req *http.Request) {
	// Check if the request method is POST
	if req.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Parse the incoming file from the request
	file, header, err := req.FormFile("file")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer file.Close()

	glog.Infof("received json data %v : %v", header.Filename, header.Size)
	buf := bytes.NewBuffer(nil)
	if _, err := io.Copy(buf, file); err != nil {
		respond400(w, "could not read json file")
	}

	//save routing to load on startup
	//json_data, _ := json.MarshalIndent(buf, "", " ")
	r.SaveRoutingJson(buf.Bytes())
	r.LoadRouting()
	glog.Infof("routing data saved from webserver")
	respondOk(w, nil)
}

func (r *LatencyRouter) handleNodeGraphHealth(w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(200)
}

func (r *LatencyRouter) handleNodeGraphFields(w http.ResponseWriter, req *http.Request) {
	type EdgeField struct {
		FieldName string `json:"field_name"`
		FieldType string `json:"type"`
	}
	type NodeField struct {
		FieldName  string `json:"field_name"`
		FieldType  string `json:"type"`
		FieldColor string `json:"color,omitempty"`
	}
	type Fields struct {
		EdgeFields []EdgeField `json:"edges_fields"`
		NodeFields []NodeField `json:"nodes_fields"`
	}
	fields := Fields{}
	fields.EdgeFields = append(fields.EdgeFields, EdgeField{FieldName: "id", FieldType: "string"})
	fields.EdgeFields = append(fields.EdgeFields, EdgeField{FieldName: "source", FieldType: "string"})
	fields.EdgeFields = append(fields.EdgeFields, EdgeField{FieldName: "target", FieldType: "string"})
	fields.EdgeFields = append(fields.EdgeFields, EdgeField{FieldName: "mainStat", FieldType: "number"})

	fields.NodeFields = append(fields.NodeFields, NodeField{FieldName: "id", FieldType: "string"})
	fields.NodeFields = append(fields.NodeFields, NodeField{FieldName: "title", FieldType: "string"})
	fields.NodeFields = append(fields.NodeFields, NodeField{FieldName: "mainStat", FieldType: "string"})
	fields.NodeFields = append(fields.NodeFields, NodeField{FieldName: "secondaryStat", FieldType: "string"})

	respondJson(w, fields)

}

func (r *LatencyRouter) handleNodeGraphData(w http.ResponseWriter, req *http.Request) {

	type Node struct {
		Id            string `json:"id"`
		Title         string `json:"title"`
		Mainstat      string `json:"mainStat,omitempty"`
		Secondarystat string `json:"secondaryStat,omitempty"`
	}
	type NodeEdge struct {
		Id            string `json:"id"`
		Source        string `json:"source"`
		Target        string `json:"target"`
		Mainstat      string `json:"mainStat,omitempty"`
		Secondarystat string `json:"secondaryStat,omitempty"`
	}
	type NodeData struct {
		NodeEdgeData []NodeEdge `json:"edges"`
		NodeData     []Node     `json:"nodes"`
	}

	orchs := make(map[string]bool)
	data := NodeData{}

	edge_id := 1
	for broadcaster_ip, lat_chk_resp := range r.closestOrchestratorToB {
		new_edge := NodeEdge{Id: strconv.Itoa(edge_id), Source: broadcaster_ip, Target: lat_chk_resp.OrchUri.Host, Mainstat: strconv.FormatInt(lat_chk_resp.RespTime, 10)}
		data.NodeEdgeData = append(data.NodeEdgeData, new_edge)
		edge_id++

		new_node := Node{Id: broadcaster_ip, Title: broadcaster_ip, Mainstat: lat_chk_resp.UpdatedAt.Format("2006-01-02 15:04:05"), Secondarystat: strconv.FormatInt(lat_chk_resp.RespTime, 10)}
		orchs[lat_chk_resp.OrchUri.Host] = true
		data.NodeData = append(data.NodeData, new_node)
	}
	for orch, _ := range orchs {
		new_node := Node{Id: orch, Title: orch}
		data.NodeData = append(data.NodeData, new_node)
	}

	respondJson(w, data)
}

func (r *LatencyRouter) basicAuth(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		username, password, ok := req.BasicAuth()
		if ok {
			usernameHash := sha256.Sum256([]byte(username))
			passwordHash := sha256.Sum256([]byte(password))
			expectedUsernameHash := sha256.Sum256([]byte("routeradmin"))
			expectedPasswordHash := sha256.Sum256([]byte(r.secret))

			usernameMatch := (subtle.ConstantTimeCompare(usernameHash[:], expectedUsernameHash[:]) == 1)
			passwordMatch := (subtle.ConstantTimeCompare(passwordHash[:], expectedPasswordHash[:]) == 1)

			if usernameMatch && passwordMatch {
				next.ServeHTTP(w, req)
				return
			}
		}

		w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	})
}
