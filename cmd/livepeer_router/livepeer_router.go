package main

import (
	"flag"
	"net/url"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/golang/glog"
	"github.com/livepeer/go-livepeer/server"
)

func defaultAddr(addr, defaultHost, defaultPort string) string {
	if addr == "" {
		return defaultHost + ":" + defaultPort
	}
	if addr[0] == ':' {
		return defaultHost + addr
	}
	// not IPv6 safe
	if !strings.Contains(addr, ":") {
		return addr + ":" + defaultPort
	}
	return addr
}

func main() {
	flag.Set("logtostderr", "true")
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	datadir := flag.String("datadir", "", "Directory that data is stored in")
	httpAddr := flag.String("httpAddr", "", "Address (IP:port) to bind to for HTTP")
	serviceAddr := flag.String("serviceAddr", "", "Publicly accessible URI (IP:port or hostname) to receive requests at. All routers need to run on this port.")
	orchAddr := flag.String("orchAddr", "", "Comma delimited list of orchestrator URIs (IP:port or hostname) to use")
	useLatencyToB := flag.Bool("useLatencyToB", false, "select orchestrator based on latency to broadcaster")
	searchTimeout := flag.Duration("searchTimeout", 2500*time.Millisecond, "time to wait for orchestrators response.  Default is 2.5 seconds. Needs to be under 3 seconds to stay in B discovery loop. (seconds = 1s, milliseconds = 1000ms)")
	pingBroadcasterTimeout := flag.Duration("pingBroadcasterTimeout", 500*time.Millisecond, "time to wait for orchestrators response.  Default is 500 milliseconds. Response needs to be under 4 seconds to stay in B discovery loop. (seconds = 1s, milliseconds = 1000ms)")
	cacheTime := flag.Duration("cacheTime", 5*time.Minute, "input time to cache closest orch (minutes = 5m, seconds = 45s, default is 5 minutes)")
	roundRobin := flag.Bool("roundRobin", true, "ping all orchestrators to get closest orch, returns first orch to respond if set to false")
	testBroadcasterIP := flag.String("testBroadcasterIP", "", "input known broadcaster IP address for testing (comma delimited)")

	flag.Parse()

	usr, err := user.Current()
	if err != nil {
		glog.Fatalf("Cannot find current user: %v", err)
	}

	if *datadir == "" {
		homedir := os.Getenv("HOME")
		if homedir == "" {
			homedir = usr.HomeDir
		}
		*datadir = filepath.Join(homedir, ".lpRouterData")
	}

	if _, err := os.Stat(*datadir); os.IsNotExist(err) {
		glog.Infof("Creating datadir: %v", *datadir)
		if err = os.MkdirAll(*datadir, 0755); err != nil {
			glog.Fatalf("Error creating datadir: %v", err)
		}
	}

	if *serviceAddr == "" {
		glog.Fatal("Missing -serviceAddr")
	}

	serviceURI, err := url.ParseRequestURI("https://" + *serviceAddr)
	if err != nil {
		glog.Fatalf("Could not parse -serviceAddr: %v", err)
	}

	*httpAddr = defaultAddr(*httpAddr, "0.0.0.0", serviceURI.Port())
	uri, err := url.ParseRequestURI("https://" + *httpAddr)
	if err != nil {
		glog.Fatalf("Could not parse -httpAddr: %v", err)
	}

	var uris []*url.URL
	var orch_nodes []server.OrchNode
	if len(*orchAddr) > 0 {
		for _, addr := range strings.Split(*orchAddr, ",") {
			addr = strings.TrimSpace(addr)
			if !strings.HasPrefix(addr, "http") {
				addr = "https://" + addr
			}

			orchUri, err := url.ParseRequestURI(addr)
			if err != nil {
				glog.Fatalf("Could not parse orchestrator URI: %v", err)
			}
			uris = append(uris, orchUri)

			if *useLatencyToB {
				routerUri, err := url.ParseRequestURI("https://" + orchUri.Hostname() + ":" + serviceURI.Port())
				if err != nil {
					glog.Fatalf("Could not parse orchestrator router URI: %v", err)
				}
				node := server.CreateOrchNode(orchUri, routerUri)
				orch_nodes = append(orch_nodes, node)
			}

		}
	}

	errCh := make(chan error)
	if *useLatencyToB {
		srv := server.NewLatencyRouter(orch_nodes, *testBroadcasterIP, *cacheTime, *searchTimeout, *pingBroadcasterTimeout, *roundRobin)
		go func() {
			errCh <- srv.Start(uri, serviceURI, *datadir)
		}()
		c := make(chan os.Signal)
		signal.Notify(c, os.Interrupt)
		select {
		case <-c:
			glog.Infof("Shutting down router server")
			srv.Stop()
		case err := <-errCh:
			if err != nil {
				glog.Errorf("Router server error: %v", err)
			}
		}
	} else {
		srv := server.NewRouter(uris)
		go func() {
			errCh <- srv.Start(uri, serviceURI, *datadir)
		}()

		c := make(chan os.Signal)
		signal.Notify(c, os.Interrupt)
		select {
		case <-c:
			glog.Infof("Shutting down router server")
			srv.Stop()
		case err := <-errCh:
			if err != nil {
				glog.Errorf("Router server error: %v", err)
			}
		}
	}

}
