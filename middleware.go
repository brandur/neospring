package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/brandur/neospring/internal/util/stringutil"
	"github.com/sirupsen/logrus"

	"github.com/gorilla/mux"
)

//
// CORSMiddleware
//

type CORSMiddleware struct{}

func (m *CORSMiddleware) Wrapper(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Access-Control-Allow-Methods", "GET, OPTIONS, PUT")
		w.Header().Add("Access-Control-Allow-Origin", "*")
		w.Header().Add("Access-Control-Allow-Headers", "Content-Type, If-Modified-Since, Spring-Signature, Spring-Version")
		w.Header().Add("Access-Control-Expose-Headers", "Content-Type, Last-Modified, Spring-Signature, Spring-Version")
		next.ServeHTTP(w, r)
	})
}

//
// CanonicalLogLineMiddleware
//

type CanonicalLogLineMiddleware struct {
	// A channel over which log data is sent as it's generated, if the channel
	// is set. This is intended for testing purposes so that we can verify log
	// data being generated.
	logDataChan chan map[string]any

	logger *logrus.Logger
}

func (m *CanonicalLogLineMiddleware) Wrapper(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctxContainer := ContextContainerFrom(r.Context())
		requestStart := time.Now()

		next.ServeHTTP(w, r)

		duration := PrettyDuration(time.Since(requestStart))

		var routeStr string
		route := mux.CurrentRoute(r)
		if route != nil {
			pathTemplate, _ := route.GetPathTemplate()
			routeStr = pathTemplate
		}

		routeOrPath := routeStr
		if routeOrPath == "" {
			routeOrPath = r.URL.Path
		}

		logData := map[string]any{
			"content_type": r.Header.Get("Content-Type"),
			"duration":     duration,
			"http_method":  r.Method,
			"http_path":    r.URL.Path,
			"http_route":   routeStr,
			"ip":           m.getIP(r).String(),
			"query_string": stringutil.SampleLong(r.URL.RawQuery),
			"status":       ctxContainer.StatusCode,
			"user_agent":   r.UserAgent(),
		}

		if m.logDataChan != nil {
			m.logDataChan <- logData
		}

		m.logger.WithFields(logrus.Fields(logData)).
			Infof("canonical_log_line %s %s -> %v (%s)", r.Method, routeOrPath, ctxContainer.StatusCode, duration)
	})
}

func (m *CanonicalLogLineMiddleware) getIP(r *http.Request) net.IP {
	if forwardedFor := r.Header.Get("X-Forwarded-For"); forwardedFor != "" {
		// `X-Forwarded-For` may contain a number of IP addresses, with the
		// original client in the leftmost position, and each intermediary proxy
		// following. In these cases, just include the original IP so that we
		// can aggregate on it from logging.
		ips := strings.Split(forwardedFor, ",")
		return net.ParseIP(strings.TrimSpace(ips[0]))
	}

	ipStr, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return nil
	}

	return net.ParseIP(ipStr)
}

// PrettyDuration exists for the simple purpose of making a duration more useful
// when it's emitted to a JSON log or as a string.
//
// A duration will normally produce a string like "42.334µs" which is somewhat
// useful for humans, but not friendly for machine ingestion or aggregation.
// This standardizes the way we spit out durations in the log line to give us a
// normal seconds fraction like "0.000042" instead.
type PrettyDuration time.Duration

func (d PrettyDuration) MarshalJSON() ([]byte, error) {
	return []byte(`"` + d.String() + `"`), nil
}

func (d PrettyDuration) String() string {
	return fmt.Sprintf(`%05fs`, time.Duration(d).Seconds())
}

//
// ContextContainerMiddleware
//

// Internal type so that we can produce a guaranteed unique global context
// value.
type contextContainerContextKey struct{}

// ContextContainer is a type embedded to context that facilitates access to
// various values.
type ContextContainer struct {
	StatusCode int
}

func ContextContainerFrom(ctx context.Context) *ContextContainer {
	return ctx.Value(contextContainerContextKey{}).(*ContextContainer)
}

// ContextContainerMiddleware embeds a context early in the request stack, which
// can be used to set various values along a request's lifecycle that can then
// be introspected by entities including other middleware.
type ContextContainerMiddleware struct{}

func (m *ContextContainerMiddleware) Wrapper(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		ctx = context.WithValue(ctx, contextContainerContextKey{}, &ContextContainer{})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
