package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func TestCORSMiddleware(t *testing.T) {
	ctx := context.Background()

	router := mux.NewRouter()
	router.Use((&CORSMiddleware{}).Wrapper)
	router.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {})

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, mustNewRequest(ctx, http.MethodGet, "/hello", nil, nil))

	require.Equal(t, http.StatusOK, recorder.Code)
	require.Equal(t, "GET, OPTIONS, PUT", recorder.Header().Get("Access-Control-Allow-Methods"))
	require.Equal(t, "*", recorder.Header().Get("Access-Control-Allow-Origin"))
	require.Equal(t, "Content-Type, If-Modified-Since, Spring-Signature, Spring-Version", recorder.Header().Get("Access-Control-Allow-Headers")) //nolint:lll
	require.Equal(t, "Content-Type, Last-Modified, Spring-Signature, Spring-Version", recorder.Header().Get("Access-Control-Expose-Headers"))    //nolint:lll
}

func TestCanonicalLogLineMiddleware(t *testing.T) {
	ctx := context.Background()
	logDataChan := make(chan map[string]any, 1)

	router := mux.NewRouter()
	router.Use((&ContextContainerMiddleware{}).Wrapper)
	router.Use((&CanonicalLogLineMiddleware{logDataChan: logDataChan, logger: logrus.New()}).Wrapper)
	router.HandleFunc("/hello/{name}", func(w http.ResponseWriter, r *http.Request) {
		ctxContainer := ContextContainerFrom(r.Context())
		ctxContainer.StatusCode = http.StatusCreated
		w.WriteHeader(http.StatusCreated)
	})

	recorder := httptest.NewRecorder()
	r := mustNewRequest(ctx, http.MethodPost, "/hello/dave", nil, nil)
	r.Header.Set("Content-Type", "text/html")
	r.Header.Set("User-Agent", "test-agent")
	router.ServeHTTP(recorder, r)

	logData := <-logDataChan
	require.Equal(t, map[string]any{
		"content_type": "text/html",
		"duration":     logData["duration"], // hard to assert on
		"http_method":  http.MethodPost,
		"http_path":    "/hello/dave",
		"http_route":   "/hello/{name}",
		"ip":           "<nil>",
		"query_string": "",
		"status":       http.StatusCreated,
		"user_agent":   "test-agent",
	}, logData)
}

func TestContextContainerMiddleware(t *testing.T) {
	ctx := context.Background()
	var ctxContainer *ContextContainer

	router := mux.NewRouter()
	router.Use((&ContextContainerMiddleware{}).Wrapper)
	router.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		ctxContainer = ContextContainerFrom(r.Context())
		ctxContainer.StatusCode = http.StatusCreated
		w.WriteHeader(http.StatusCreated)
	})

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, mustNewRequest(ctx, http.MethodGet, "/hello", nil, nil))

	require.Equal(t, http.StatusCreated, ctxContainer.StatusCode)
}
