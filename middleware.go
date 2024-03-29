package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"golang.org/x/xerrors"

	"github.com/brandur/neospring/internal/util/stringutil"
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

		if inspectableWriter, ok := w.(*InspectableWriter); ok {
			if inspectableWriter.StatusCode >= 400 {
				logData["error_message"] = inspectableWriter.Body.String()
			}
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

func (d PrettyDuration) MarshalJSON() ([]byte, error) { //nolint:unparam
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

//
// InspectableWriterMiddleware
//

// InspectableWriter is a thin wrapper implementing the http.ResponseWriter
// interface. The out-of-the-box writer makes it quite difficult to track
// anything that happened with it after the fact; for example, after you write a
// status code to it there's no way to find out later what that status was from
// a post-response middleware. InspectableWriter solves this problem by tracking
// various aspects of what happened during a request to make this information
// available. This is used by components like CanonicalLogLineMiddleware to log
// response information.
type InspectableWriter struct {
	http.ResponseWriter
	StatusCode int
	Body       bytes.Buffer
}

func (w *InspectableWriter) WriteHeader(status int) {
	w.StatusCode = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *InspectableWriter) Write(b []byte) (int, error) {
	if w.StatusCode == 0 {
		// If no status was written by the time Write is called, ResponseWriter
		// sets it to 200 automatically. Reflect that here too.
		w.StatusCode = http.StatusOK
	}

	_, _ = w.Body.Write(b)

	n, err := w.ResponseWriter.Write(b)
	if err != nil {
		return n, xerrors.Errorf("error writing response body: %w", err)
	}

	return n, nil
}

// InspectableWriterMiddleware injects an instance of InspectableWriter into
// middlewares nested beneath it.
type InspectableWriterMiddleware struct{}

// NewInspectableWriterMiddleware initializes a new middleware instance.
func NewInspectableWriterMiddleware() *InspectableWriterMiddleware {
	return &InspectableWriterMiddleware{}
}

// Wrapper produces an http.HandlerFunc suitable to be placed into a middleware
// stack.
func (m *InspectableWriterMiddleware) Wrapper(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		inspectableWriter := &InspectableWriter{ResponseWriter: w}
		next.ServeHTTP(inspectableWriter, r)
	})
}

//
// TimeoutMiddleware
//

const (
	ErrMessageCanceled = "The request was canceled after %v (maximum request time is %v)."
	ErrMessageTimeout  = "The request timed out after %v (maximum request time is %v)."
)

// TimeoutMiddleware injects a deadline into the request's context. Then in case
// it's exceeded, it responds with a pretty 504 to the user.
//
// Note that in Go, the runtime will never actually kill anything if a deadline
// is exceeded. Instead, low level packages like net/http or pgx are expected to
// check the deadlines in their given contexts, and return an error in case it
// was exceeded. In our stack, this error would then bubble back up to our
// common transport infrastructure, where it'd be logged and emitted to Sentry,
// then eventually make its way back here, where we send an error back.
type TimeoutMiddleware struct {
	timeout time.Duration
}

// NewTimeoutMiddleware initializes a new middleware instance.
func NewTimeoutMiddleware(timeout time.Duration) *TimeoutMiddleware {
	return &TimeoutMiddleware{timeout}
}

// Wrapper produces an http.HandlerFunc suitable to be placed into a middleware
// stack.
func (m *TimeoutMiddleware) Wrapper(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ctx, cancel := context.WithTimeout(r.Context(), m.timeout)
		defer func() {
			// Get error before calling cancel below.
			err := ctx.Err()

			// Cancel should always be called whether the context timed out or
			// not.
			cancel()

			var errMessage string
			switch {
			case errors.Is(err, context.Canceled):
				errMessage = ErrMessageCanceled
			case errors.Is(err, context.DeadlineExceeded):
				errMessage = ErrMessageTimeout
			}

			if errMessage != "" {
				w.WriteHeader(http.StatusGatewayTimeout)
				_, _ = w.Write([]byte(fmt.Sprintf(errMessage, PrettyDuration(time.Since(start)), PrettyDuration(m.timeout))))
			}
		}()

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
