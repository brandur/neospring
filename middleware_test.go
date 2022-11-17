package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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

func TestInspectableWriterMiddlewareWrapper(t *testing.T) {
	var (
		ctx               context.Context
		handler           http.Handler
		inspectableWriter *InspectableWriter
		writeResponse     func(w http.ResponseWriter)
	)

	setup := func(test func(*testing.T)) func(*testing.T) {
		return func(t *testing.T) {
			t.Helper()

			ctx = context.Background()

			writeResponse = func(w http.ResponseWriter) {
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte("hello"))
			}

			handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				inspectableWriter = w.(*InspectableWriter)
				writeResponse(w)
			})
			handler = NewInspectableWriterMiddleware().Wrapper(handler)

			test(t)
		}
	}

	t.Run("TracksStatus", setup(func(t *testing.T) {
		recorder := httptest.NewRecorder()
		req := mustNewRequest(ctx, http.MethodGet, "https://example.com", nil, nil)
		handler.ServeHTTP(recorder, req)

		require.Equal(t, http.StatusCreated, inspectableWriter.StatusCode)
		require.Equal(t, "hello", inspectableWriter.Body.String())
	}))

	t.Run("TracksDefaultStatus", setup(func(t *testing.T) {
		writeResponse = func(w http.ResponseWriter) {
			_, err := w.Write([]byte{})
			require.NoError(t, err)
		}

		recorder := httptest.NewRecorder()
		req := mustNewRequest(ctx, http.MethodGet, "https://example.com", nil, nil)
		handler.ServeHTTP(recorder, req)

		require.Equal(t, http.StatusOK, inspectableWriter.StatusCode)
	}))
}

func TestTimeoutMiddlewareWrapper(t *testing.T) {
	var (
		ctx         context.Context
		handler     http.Handler
		handlerFunc func(w http.ResponseWriter, r *http.Request)
	)

	setup := func(test func(*testing.T)) func(*testing.T) {
		return func(t *testing.T) {
			ctx = context.Background()

			handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if handlerFunc != nil {
					handlerFunc(w, r)
				}
			})
			handler = NewTimeoutMiddleware(50 * time.Millisecond).Wrapper(handler)

			test(t)
		}
	}

	t.Run("DoesNothingWithoutTimeout", setup(func(t *testing.T) {
		handlerFunc = func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusCreated)
		}

		recorder := httptest.NewRecorder()
		req := mustNewRequest(ctx, http.MethodGet, "https://example.com", nil, nil)
		handler.ServeHTTP(recorder, req)

		require.Equal(t, http.StatusCreated, recorder.Result().StatusCode) //nolint:bodyclose
	}))

	t.Run("HandlesCanceled", setup(func(t *testing.T) {
		handlerFunc = func(_ http.ResponseWriter, r *http.Request) {
		}

		cancelCtx, cancel := context.WithCancel(context.Background())
		cancel()

		recorder := httptest.NewRecorder()
		req := mustNewRequest(cancelCtx, http.MethodGet, "https://example.com", nil, nil)
		handler.ServeHTTP(recorder, req)

		require.Equal(t, http.StatusGatewayTimeout, recorder.Result().StatusCode) //nolint:bodyclose
		require.Regexp(t,
			`\AThe request was canceled after 0\.\d+s \(maximum request time is 0\.050000s\).\z`,
			recorder.Body.String())
	}))

	t.Run("HandlesTimeout", setup(func(t *testing.T) {
		handlerFunc = func(_ http.ResponseWriter, r *http.Request) {
			select {
			case <-time.After(5 * time.Second):
				require.Fail(t, "Timed out waiting for cancellation")
			case <-r.Context().Done():
				t.Logf("Context was cancelled: %s", r.Context().Err())
			}
		}

		recorder := httptest.NewRecorder()
		req := mustNewRequest(ctx, http.MethodGet, "https://example.com", nil, nil)
		handler.ServeHTTP(recorder, req)

		require.Equal(t, http.StatusGatewayTimeout, recorder.Result().StatusCode) //nolint:bodyclose
		require.Regexp(t,
			`\AThe request timed out after 0\.\d+s \(maximum request time is 0\.050000s\).\z`,
			recorder.Body.String())
	}))
}
