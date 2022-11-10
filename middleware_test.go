package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
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
