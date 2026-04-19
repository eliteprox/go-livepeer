package byoc

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/livepeer/go-livepeer/clog"
	"github.com/livepeer/go-livepeer/common"
	"github.com/livepeer/go-livepeer/core"
)

// logPublicMetricsEntry emits the gateway-entry "[Public Metrics]" line used by
// the Loki extractor. The format mirrors server/ai_process.go so a single
// regex parses both AI-subnet and BYOC events. BYOC has no bearer token, so
// token_ID is fixed to N/A; model_ID is taken from the requester's
// OptionsFilter["model"] when present, else N/A.
func logPublicMetricsEntry(ctx context.Context, job *gatewayJob) {
	capability := "N/A"
	if job != nil && job.Job != nil && job.Job.Req != nil && job.Job.Req.Capability != "" {
		capability = job.Job.Req.Capability
	}

	modelID := "N/A"
	if job != nil && job.Job != nil && job.Job.Params != nil {
		if m, ok := job.Job.Params.OptionsFilter["model"]; ok && m != "" {
			modelID = sanitizeOptionValue(m)
		}
	}

	clog.V(common.SHORT).Infof(ctx, "[Public Metrics] model_ID=%v token_ID=N/A pipeline_ID=%v",
		modelID, capability)
}

// logPublicMetricsOrch emits a per-orchestrator "[Public Metrics]" line after
// orchestrator selection, flattening the matching WorkerOption into
// option_<key>=<value> pairs so a generic Loki extractor can pick them up.
// Picks the first WorkerOption that matches the request's OptionsFilter, or
// the first advertised option when no filter is set; no-op when the
// orchestrator advertised no options.
func logPublicMetricsOrch(ctx context.Context, capability string, orchAddr string, filter map[string]string, options []map[string]interface{}) {
	if len(options) == 0 {
		return
	}

	chosen := core.FindMatchingOption(filter, options)
	if chosen == nil {
		chosen = options[0]
	}

	if capability == "" {
		capability = "N/A"
	}
	if orchAddr == "" {
		orchAddr = "N/A"
	}

	clog.V(common.SHORT).Infof(ctx, "[Public Metrics] pipeline_ID=%v orch=%v %s",
		capability, orchAddr, flattenWorkerOption(chosen))
}

// flattenWorkerOption renders a WorkerOption map as space-separated
// option_<key>=<value> pairs, sorted by key for deterministic log output.
// Keys are sanitized to [a-zA-Z0-9_] and values have whitespace collapsed so
// the line stays parseable by a `option_(\w+)=(\S+)` regex.
func flattenWorkerOption(opt map[string]interface{}) string {
	if len(opt) == 0 {
		return ""
	}

	keys := make([]string, 0, len(opt))
	for k := range opt {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		safeKey := sanitizeOptionKey(k)
		if safeKey == "" {
			continue
		}
		parts = append(parts, fmt.Sprintf("option_%s=%s", safeKey, sanitizeOptionValue(fmt.Sprintf("%v", opt[k]))))
	}
	return strings.Join(parts, " ")
}

func sanitizeOptionKey(k string) string {
	var b strings.Builder
	b.Grow(len(k))
	for _, r := range k {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_':
			b.WriteRune(r)
		}
	}
	return b.String()
}

func sanitizeOptionValue(v string) string {
	if v == "" {
		return "N/A"
	}
	var b strings.Builder
	b.Grow(len(v))
	for _, r := range v {
		switch r {
		case ' ', '\t', '\n', '\r':
			b.WriteByte('_')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
