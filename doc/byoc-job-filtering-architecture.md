# Technical Specification: BYOC Options-Based Filtering & Evaluation Engine

## 1. Overview

This specification details a mechanism for dynamic, capability-based routing in the Bring Your Own Compute (BYOC) network. By decoupling domain-specific worker capabilities from the core Orchestrator and Gateway routing logic, BYOC workers can self-report their configuration (`options`), and clients can define strict requirements (`filters`). The Gateway evaluates these filters using a lightweight matching engine to determine Orchestrator eligibility.

## 2. Data Structures

To facilitate capability matching, both the client's job request payload and the Orchestrator's returned token must be extended to include schema-less JSON objects.

### 2.1. Client Job Request (`JobParameters`)

The client defines its requirements inside the existing `JobParameters` struct. The filter values are always passed as strings to accommodate operator prefixes.

```go
type JobParameters struct {
    // Existing fields...
    
    // Key-value map of required capabilities and their constraints
    // Example: {"model": "llama-3", "vram_gb": ">=16", "cuda_enabled": "true"}
    OptionsFilter map[string]string `json:"options_filter,omitempty"`
}

```

### 2.2. Orchestrator Job Token (`JobToken`)

The Orchestrator caches and returns the specific worker's self-reported capabilities.

```go
type JobToken struct {
    // Existing fields...
    
    // Key-value map of the worker's self-reported capabilities
    // Example: {"model": "llama-3", "vram_gb": 24.0, "cuda_enabled": true}
    WorkerOptions map[string]interface{} `json:"worker_options,omitempty"`
}

```

## 3. The Evaluation Engine (v1)

The Gateway implements a localized evaluation engine that compares the client's `OptionsFilter` against the `JobToken`'s `WorkerOptions`.

### 3.1. Supported Operators

To prevent performance bottlenecks and security risks (e.g., ReDoS), the evaluation engine is strictly limited to the following operations:

* **Exact String Match:** Implicitly evaluated if no operator is present (e.g., `"model": "llama-3"`).
* **Boolean Check:** Evaluated as an exact match for `"true"` or `"false"` (e.g., `"cuda_enabled": "true"`).
* **Simple Math:** Supported via prefixes on numerical values:
* `<` (Less than)
* `>` (Greater than)
* `<=` (Less than or equal to)
* `>=` (Greater than or equal to)



### 3.2. Evaluation Logic & Rules

The engine processes the filter iteratively. For a token to pass, **all** keys present in the `OptionsFilter` must be successfully evaluated against `WorkerOptions`.

1. **Key Existence:** If an `OptionsFilter` key does not exist in `WorkerOptions`, the evaluation immediately fails (returns `false`).
2. **Type Inference & Parsing:** * The engine inspects the prefix of the `OptionsFilter` value string.
* If a math operator (`<, >, <=, >=`) is detected, the engine attempts to cast the corresponding `WorkerOptions` value to a `float64`. It then parses the remaining string in the `OptionsFilter` as a `float64`. If either parsing fails, the evaluation fails.


3. **Strict Evaluation:**
* If no math operator is present, the engine converts both the filter value and the option value to strings and performs a case-insensitive exact match.
* If a math operator is present, the engine performs the requested mathematical comparison on the parsed floats.



## 4. Architecture & Data Flow

To avoid synchronous delays during job requests, Orchestrators handle option retrieval asynchronously.

1. **Worker Registration & Polling:** When a BYOC worker registers with an Orchestrator, the Orchestrator periodically polls the worker's `/options` endpoint (e.g., every 30 seconds) and caches the resulting JSON.
2. **Job Request Initialization:** A client sends a job to the Gateway, including an `OptionsFilter` in the `JobParameters`.
3. **Token Gathering:** The Gateway requests job tokens from available Orchestrators. The Orchestrators immediately respond with their cached `WorkerOptions` injected into the `JobToken`.
4. **Gateway Evaluation:** The Gateway passes each `JobToken` through the Evaluation Engine.
5. **Execution:** The Gateway drops any tokens that fail the evaluation and routes the job to the optimal remaining Orchestrator.

---

## 5. Future Enhancements

To maintain a stable v1 release, several advanced routing and telemetry features have been deferred to future iterations.

* **Trustless Performance Routing (Gateway-Observed Metrics):** While workers self-report static *capabilities* (`options`), relying on workers to self-report dynamic *performance* metrics (latency, queue depth) introduces trust vulnerabilities. Future iterations will introduce a `MetricsFilter`, which the Gateway will evaluate against its own historically observed and locally tracked performance data for each Orchestrator/Worker pair.
* **Fleet-Wide State Sharing (Redis Integration):**
  Currently, each Gateway node must discover Orchestrator capabilities and track performance independently. Implementing a centralized state store (like Redis) will allow a fleet of Gateway nodes to share a unified pool of cached worker options and real-time failure metrics, drastically reducing job routing latency.
* **Regular Expression (Regex) Matching:**
  Future versions of the evaluation engine may support a `~=` operator for Regex matching to allow clients more flexibility in capability targeting. This will require strict implementation safeguards, including execution timeouts and regex sanitization, to protect the Gateway from ReDoS attacks.
* **Nested JSON Evaluation:**
  Expanding the evaluation engine to traverse deep JSON structures (e.g., `{"hardware": {"gpu": {"vram": ">=16"}}}`) using dot-notation string parsing.

---

### Core Evaluation Logic

This code handles type inference for the math operators, gracefully falls back to string formatting for exact matches, and safely handles the `interface{}` types coming from the JSON unmarshaling.

```go
package byoc

import (
	"fmt"
	"strconv"
	"strings"
)

// EvaluateOptions checks if a JobToken's options satisfy a JobRequest's filter.
func EvaluateOptions(filter map[string]string, options map[string]interface{}) bool {
	// If no filter is provided, the token implicitly passes.
	if len(filter) == 0 {
		return true
	}

	for key, filterVal := range filter {
		workerVal, exists := options[key]
		if !exists {
			return false // Fail immediately if the required capability is missing
		}

		filterVal = strings.TrimSpace(filterVal)

		// Route to math evaluation if a supported prefix is found
		if strings.HasPrefix(filterVal, ">=") {
			if !evaluateMath(filterVal[2:], workerVal, ">=") { return false }
		} else if strings.HasPrefix(filterVal, "<=") {
			if !evaluateMath(filterVal[2:], workerVal, "<=") { return false }
		} else if strings.HasPrefix(filterVal, ">") {
			if !evaluateMath(filterVal[1:], workerVal, ">") { return false }
		} else if strings.HasPrefix(filterVal, "<") {
			if !evaluateMath(filterVal[1:], workerVal, "<") { return false }
		} else {
			// Fallback to exact string/boolean match (case-insensitive)
			workerStr := fmt.Sprintf("%v", workerVal)
			if strings.ToLower(filterVal) != strings.ToLower(strings.TrimSpace(workerStr)) {
				return false
			}
		}
	}
	
	return true
}

// evaluateMath safely attempts to cast interface values to float64 and evaluates the operator.
func evaluateMath(expectedStr string, workerVal interface{}, operator string) bool {
	expectedFloat, err := strconv.ParseFloat(strings.TrimSpace(expectedStr), 64)
	if err != nil {
		return false // Filter format is invalid (e.g., ">=abc")
	}

	var workerFloat float64
	switch v := workerVal.(type) {
	case float64:
		workerFloat = v
	case float32:
		workerFloat = float64(v)
	case int:
		workerFloat = float64(v)
	case int64:
		workerFloat = float64(v)
	case string:
		parsed, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
		if err != nil {
			return false // Worker value cannot be evaluated mathematically
		}
		workerFloat = parsed
	default:
		return false // Unsupported type for math operations
	}

	// Apply the operator
	switch operator {
	case ">=": return workerFloat >= expectedFloat
	case "<=": return workerFloat <= expectedFloat
	case ">":  return workerFloat > expectedFloat
	case "<":  return workerFloat < expectedFloat
	}
	
	return false
}

```

---

### Example Test Cases

Here is a quick unit test structure to validate the logic against the scenarios you mentioned:

```go
package byoc

import (
	"testing"
)

func TestEvaluateOptions(t *testing.T) {
	// Simulated worker options returned from the Orchestrator
	workerOptions := map[string]interface{}{
		"model":        "llama-3",
		"vram_gb":      24.0,   // Unmarshaled from JSON number
		"cuda_enabled": true,   // Unmarshaled from JSON boolean
		"rtt_ms":       "1200", // Edge case: numbers stored as strings
	}

	tests := []struct {
		name     string
		filter   map[string]string
		expected bool
	}{
		{
			name:     "Exact string match passes",
			filter:   map[string]string{"model": "llama-3"},
			expected: true,
		},
		{
			name:     "Boolean evaluation as string passes",
			filter:   map[string]string{"cuda_enabled": "true"},
			expected: true,
		},
		{
			name:     "Math operator less-than passes",
			filter:   map[string]string{"rtt_ms": "<1500"},
			expected: true,
		},
		{
			name:     "Math operator greater-than-or-equal passes",
			filter:   map[string]string{"vram_gb": ">=16"},
			expected: true,
		},
		{
			name:     "Missing key fails",
			filter:   map[string]string{"gpu_temp": "<80"},
			expected: false,
		},
		{
			name:     "Math operator fails condition",
			filter:   map[string]string{"vram_gb": ">32"},
			expected: false,
		},
		{
			name:     "Combined filters pass",
			filter:   map[string]string{"model": "llama-3", "vram_gb": ">=16", "rtt_ms": "<1500"},
			expected: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := EvaluateOptions(tc.filter, workerOptions)
			if result != tc.expected {
				t.Errorf("Expected %v but got %v for filter %v", tc.expected, result, tc.filter)
			}
		})
	}
}

```

--- 

## How to use in job_gateway.go

The best place to intercept and filter the orchestrators is **during the token collection phase**, before the Gateway even attempts to route the job. By filtering the tokens as they arrive from the Orchestrators over the channel, you prevent invalid orchestrators from ever entering the `gatewayJob.Orchs` retry loop in `submitJob`.

Here is the step-by-step injection:

### Step 1: Update the Shared Structs

Make sure your request and token structs (likely in your `core` or `net` packages) have the new fields.

```go
// Inside the package where JobToken is defined
type JobToken struct {
	// ... existing fields ...
	AvailableCapacity int                    `json:"availableCapacity"`
	WorkerOptions     map[string]interface{} `json:"worker_options,omitempty"` // Add this
}

// Inside the package where JobParameters is defined
type JobParameters struct {
	// ... existing fields ...
	OptionsFilter map[string]string `json:"options_filter,omitempty"` // Add this
}

```

### Step 2: Inject the Filter into `job_gateway.go`

Locate the token gathering loop in `job_gateway.go` (around line 170-190 in the snippet you shared earlier). You want to wrap the `append` operation with your new `EvaluateOptions` check.

Here is the modified block:

```go
// ... existing code in job_gateway.go ...

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

// THE INJECTION POINT: Filter tokens as they are received
for nbResp < numAvailableOrchs && len(jobTokens) < numAvailableOrchs {
	select {
	case token := <-tokenCh:
		// 1. Check if Orchestrator has capacity
		if token.AvailableCapacity > 0 {
			
			// 2. NEW: Evaluate the BYOC Worker Options against the client's filter
			// Assuming 'params' is the JobParameters struct available in this scope
			if EvaluateOptions(params.OptionsFilter, token.WorkerOptions) {
				jobTokens = append(jobTokens, token)
			} else {
				clog.V(common.DEBUG).Infof(ctx, "Orchestrator %v rejected: failed options filter", token.ServiceAddr)
			}
			
		}
		nbResp++
	case <-errCh:
		nbResp++
	case <-tokensCtx.Done():
		//searchTimeout reached, return tokens received
		return jobTokens, nil
	}
}

// received enough tokens or all responses arrived
return jobTokens, nil

// ... rest of the file ...

```

### Why this approach works best:

1. **Fails Fast:** The Gateway doesn't waste time signing payloads or initiating HTTP requests to Orchestrators that don't have the right hardware/models.
2. **Keeps `submitJob` Clean:** The main retry loop in `submitJob` remains completely untouched. It just receives a pre-vetted list of `gatewayJob.Orchs` and loops through them exactly as it did before.
3. **No Extra Latency:** Because the Orchestrator is returning its cached `WorkerOptions` directly inside the `/process/token` response payload, evaluating the filter locally adds virtually zero milliseconds to the Gateway's routing overhead.

---


## Orchestrator-side code changes

To complete the loop, we need to set up the Orchestrator so it can seamlessly pass these options down to the Gateway.

Because the Gateway's token request (`/process/token`) is in the "hot path" of job routing, the Orchestrator cannot afford to make a synchronous HTTP request to the BYOC worker to ask for its options. If the worker is slow to respond, the Gateway's token request times out, and the job fails to route.

The solution is an **asynchronous polling loop** with a thread-safe cache. The Orchestrator constantly asks the worker for its options in the background and stores them in memory. When the Gateway asks for a token, the Orchestrator instantly attaches the cached data.

Here is how to wire up the Orchestrator side:

### Step 1: Thread-Safe State on the Orchestrator

We need a place to store the options on the Orchestrator's internal representation of the BYOC worker. Because a background thread will be writing to this cache while multiple HTTP request threads might be reading from it, we must use a `sync.RWMutex` to prevent race conditions.

```go
package byoc

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"
	"github.com/livepeer/go-livepeer/clog"
)

// WorkerClient represents the Orchestrator's connection to a BYOC worker.
type WorkerClient struct {
	URL string // The address of the BYOC worker container

	// Thread-safe cache for worker options
	mu            sync.RWMutex
	cachedOptions map[string]interface{}
}

```

### Step 2: The Background Polling Loop

When the worker registers with the Orchestrator (or when the Orchestrator initializes), it should spin up a background Goroutine that polls the worker's `/options` endpoint on a set interval (e.g., every 30 seconds).

```go
// StartOptionPolling begins the background loop to fetch worker capabilities.
func (wc *WorkerClient) StartOptionPolling(ctx context.Context) {
	// Fetch immediately on startup so we don't have to wait for the first tick
	wc.fetchAndUpdateOptions(ctx)

	ticker := time.NewTicker(30 * time.Second)
	
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return // Stop polling if the Orchestrator shuts down or worker disconnects
			case <-ticker.C:
				wc.fetchAndUpdateOptions(ctx)
			}
		}
	}()
}

func (wc *WorkerClient) fetchAndUpdateOptions(ctx context.Context) {
	// Send a GET request to the worker's capabilities endpoint
	resp, err := http.Get(wc.URL + "/options")
	if err != nil {
		clog.Errorf(ctx, "Failed to poll options from worker %s: %v", wc.URL, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		clog.Errorf(ctx, "Worker %s returned status %d for /options", wc.URL, resp.StatusCode)
		return
	}

	var newOptions map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&newOptions); err != nil {
		clog.Errorf(ctx, "Failed to decode options from worker %s: %v", wc.URL, err)
		return
	}

	// Safely update the cache
	wc.mu.Lock()
	wc.cachedOptions = newOptions
	wc.mu.Unlock()
	
	clog.V(5).Infof(ctx, "Successfully refreshed options for worker %s", wc.URL)
}

```

### Step 3: Injecting the Cache into the Token Request

Finally, locate the HTTP handler on the Orchestrator that serves the `/process/token` endpoint. When constructing the `JobToken` to send back to the Gateway, safely read from the cache.

```go
// Inside the Orchestrator's HTTP handler for /process/token
func (s *OrchestratorServer) handleProcessToken(w http.ResponseWriter, r *http.Request) {
	// ... existing token generation logic (verifying signatures, capacity, etc.) ...
	
	// Assuming 'workerClient' is the instance managing the specific BYOC worker
	workerClient := s.getWorkerClientForJob(r) 

	// Safely read the cached options
	workerClient.mu.RLock()
	// Create a shallow copy to prevent the Gateway struct from holding a reference to the internal map
	optionsCopy := make(map[string]interface{}, len(workerClient.cachedOptions))
	for k, v := range workerClient.cachedOptions {
		optionsCopy[k] = v
	}
	workerClient.mu.RUnlock()

	// Construct the response
	jobToken := JobToken{
		// ... existing fields (Token, ServiceAddr, AvailableCapacity) ...
		WorkerOptions: optionsCopy, // Inject the copied cache
	}

	// Send the JSON response back to the Gateway
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jobToken)
}

```

--- 

## Worker Code Changes 

Let’s dive into the supply side: the BYOC worker.

To make this concrete, let's assume this worker is running an AI video generation pipeline. The goal is to build a lightweight HTTP server inside the container that serves a JSON representation of its hardware and loaded software stack.

Here is how you would structure the worker to expose its capabilities.

### 1. The Strategy: Static vs. Dynamic Discovery

When the worker container boots up, it should assemble its "resume" by combining two types of data:

* **Static Configuration:** Things defined by the container image or startup environment variables (e.g., the specific model loaded, the AI framework).
* **Dynamic Hardware Discovery:** Things the container detects from the host machine at runtime (e.g., OS, GPU model, total VRAM).

### 2. The Implementation (Python Example)

Since AI pipelines relying on tools like Diffusers typically run in Python, setting up a fast, lightweight web server using a framework like FastAPI is the standard approach.

Here is what the worker code would look like to serve that `/options` endpoint:

```python
from fastapi import FastAPI
import uvicorn
import subprocess

app = FastAPI()

# 1. Static capabilities defined by the container's purpose
STATIC_OPTIONS = {
    "worker_type": "ai-video-generation",
    "framework": "diffusers",
    "os": "Ubuntu 24.04"
}

def get_vram_gb() -> float:
    # In a real scenario, you might parse nvidia-smi output here:
    # subprocess.check_output(["nvidia-smi", "--query-gpu=memory.total", "--format=csv,noheader,nounits"])
    # For this example, we'll return a known hardware state:
    return 32.0

def get_gpu_model() -> str:
    # Similarly, this could be dynamically probed
    return "NVIDIA GeForce RTX 5090"

@app.get("/options")
def serve_options():
    """
    The endpoint the Livepeer Orchestrator polls asynchronously.
    """
    # Merge static config with dynamic hardware state
    options = STATIC_OPTIONS.copy()
    options["gpu_model"] = get_gpu_model()
    options["vram_gb"] = get_vram_gb()
    options["cuda_enabled"] = True
    
    return options

# The actual BYOC job processing endpoint would go here
@app.post("/process")
def process_job(request: dict):
    # Handle the video generation job...
    pass

if __name__ == "__main__":
    # Run the worker API on port 8080
    uvicorn.run(app, host="0.0.0.0", port=8080)

```

### 3. The Output Payload

When the Orchestrator runs its background polling loop against `http://<worker-ip>:8080/options`, it receives this exact JSON payload:

```json
{
  "worker_type": "ai-video-generation",
  "framework": "diffusers",
  "os": "Ubuntu 24.04",
  "gpu_model": "NVIDIA GeForce RTX 5090",
  "vram_gb": 32.0,
  "cuda_enabled": true
}

```

### Why this design shines

1. **Zero Orchestrator Configuration:** The Orchestrator doesn't need to know *anything* about GPUs, VRAM, or Ubuntu. It just blindly caches this JSON dictionary and hands it to the Gateway.
2. **Worker Autonomy:** If you decide to swap the hardware or update the container to run a different model, you just restart the worker. The `/options` endpoint instantly updates, the Orchestrator caches the new data on its next poll, and the Gateway immediately starts routing jobs based on the new capabilities.
