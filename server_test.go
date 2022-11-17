package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"golang.org/x/xerrors"

	"github.com/brandur/neospring/internal/nskey"
	"github.com/brandur/neospring/internal/nsstore"
	"github.com/brandur/neospring/internal/nsstore/nsmemorystore"
)

const (
	samplePrivateKey = "90ba51828ecc30132d4707d55d24456fbd726514cf56ab4668b62392798e2540"
	samplePublicKey  = "e90e9091b13a6e5194c1fed2728d1fdb6de7df362497d877b8c0b8f0883e1124"
)

var logger = logrus.New()

// Since the various KeyPair parsing functions only take a private key portion,
// this test case is here to make sure that the test/sample public keys we have
// bundled up in this package actually match up with the private keys that they
// claim to.
func TestBundledKeys(t *testing.T) {
	{
		keyPair, err := nskey.ParseKeyPairUnchecked(nskey.TestPrivateKey)
		require.NoError(t, err)
		require.Equal(t, nskey.TestPublicKey, keyPair.PublicKey)
	}

	{
		keyPair, err := nskey.ParseKeyPairUnchecked(samplePrivateKey)
		require.NoError(t, err)
		require.Equal(t, samplePublicKey, keyPair.PublicKey)
	}
}

func TestServerHandleGetKey(t *testing.T) {
	var (
		ctx      context.Context
		denyList *MemoryDenyList
		server   *Server
		store    *nsmemorystore.MemoryStore
	)

	requestForKey := func(key string) *http.Request {
		return mustNewRequest(ctx, http.MethodGet, "/"+key, map[string]string{"key": key}, nil)
	}

	setup := func(test func(*testing.T)) func(*testing.T) {
		return func(t *testing.T) {
			t.Helper()

			ctx = context.Background()
			store = nsmemorystore.NewMemoryStore(logger)
			denyList = NewMemoryDenyList()
			server = NewServer(logger, store, denyList, defaultPort)
			server.timeNow = stableTimeFunc

			test(t)
		}
	}

	storeKeyContent := func(keyPair *nskey.KeyPair, timestamp time.Time, content string) *nsstore.Board {
		board := &nsstore.Board{
			Content:   []byte(content),
			Signature: keyPair.SignHex([]byte(content)),
			Timestamp: timestamp,
		}
		err := store.Put(ctx, keyPair.PublicKey, board)
		require.NoError(t, err)
		return board
	}

	t.Run("Success", setup(func(t *testing.T) {
		keyPair := nskey.MustParseKeyPairUnchecked(samplePrivateKey)
		board := storeKeyContent(keyPair, stableTime, "some board content")

		resp, err := server.handleGetKey(ctx, requestForKey(keyPair.PublicKey))
		require.NoError(t, err)
		requireServerResponse(t, NewServerResponse(http.StatusOK, board.Content, http.Header{
			"Last-Modified":    []string{board.Timestamp.Format(http.TimeFormat)},
			"Spring-Signature": []string{board.Signature},
			"Spring-Version":   []string{"83"},
		}), resp)
	}))

	t.Run("TestKey", setup(func(t *testing.T) {
		keyPair := nskey.MustParseKeyPairUnchecked(nskey.TestPrivateKey)

		resp, err := server.handleGetKey(ctx, requestForKey(nskey.TestPublicKey))
		require.NoError(t, err)

		// Content is randomized, so we don't check the whole thing. Just verify
		// status and that the signature was right.
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.Equal(t, stableTime.Format(http.TimeFormat), resp.Header.Get("Last-Modified"))
		sig, err := hex.DecodeString(resp.Header.Get("Spring-Signature"))
		require.NoError(t, err)
		require.True(t, keyPair.Verify(resp.Body, sig))
	}))

	t.Run("KeyInvalid", setup(func(t *testing.T) {
		_, err := server.handleGetKey(ctx, requestForKey(nskey.TestPrivateKey))
		requireServerError(t, NewServerError(http.StatusForbidden, ErrMessageKeyInvalid), err)
	}))

	t.Run("KeyExpired", setup(func(t *testing.T) {
		_, err := server.handleGetKey(ctx, requestForKey("ab589f4dde9fce4180fcf42c7b05185b0a02a5d682e353fa39177995083e0519"))
		requireServerError(t, NewServerError(http.StatusForbidden, ErrMessageKeyExpired), err)
	}))

	t.Run("KeyNotYetValid", setup(func(t *testing.T) {
		_, err := server.handleGetKey(ctx, requestForKey("ab589f4dde9fce4180fcf42c7b05185b0a02a5d682e353fa39177995083e0525"))
		requireServerError(t, NewServerError(http.StatusForbidden, ErrMessageKeyNotYetValid), err)
	}))

	t.Run("DenyList", setup(func(t *testing.T) {
		_, err := server.handleGetKey(ctx, requestForKey(InfernalPublicKey))
		requireServerError(t, NewServerError(http.StatusForbidden, ErrMessageDeniedKey), err)
	}))

	t.Run("KeyNotFound", setup(func(t *testing.T) {
		_, err := server.handleGetKey(ctx, requestForKey(samplePublicKey))
		requireServerError(t, NewServerError(http.StatusNotFound, (&BoardNotFoundError{samplePublicKey}).Error()), err)
	}))

	t.Run("TimestampOnly", setup(func(t *testing.T) {
		keyPair := nskey.MustParseKeyPairUnchecked(samplePrivateKey)
		_ = storeKeyContent(keyPair, stableTime, timestampTag(stableTime))

		_, err := server.handleGetKey(ctx, requestForKey(samplePublicKey))
		requireServerError(t, NewServerError(http.StatusNotFound, (&BoardNotFoundError{samplePublicKey}).Error()), err)
	}))

	t.Run("IfModifiedSinceParseError", setup(func(t *testing.T) {
		keyPair := nskey.MustParseKeyPairUnchecked(samplePrivateKey)
		_ = storeKeyContent(keyPair, stableTime, "some board content")

		r := requestForKey(keyPair.PublicKey)
		r.Header.Set("If-Modified-Since", "not-a-date")
		_, err := server.handleGetKey(ctx, r)
		requireServerError(t, NewServerError(http.StatusBadRequest, (&IfModifiedSinceParseError{"not-a-date"}).Error()), err)
	}))

	t.Run("IfModifiedSinceAfterTimestamp", setup(func(t *testing.T) {
		keyPair := nskey.MustParseKeyPairUnchecked(samplePrivateKey)
		_ = storeKeyContent(keyPair, stableTime, "some board content")

		r := requestForKey(keyPair.PublicKey)
		r.Header.Set("If-Modified-Since", stableTime.Add(5*time.Second).Format(http.TimeFormat))
		_, err := server.handleGetKey(ctx, r)
		requireServerError(t, NewServerError(http.StatusNotFound, (&BoardNotFoundError{samplePublicKey}).Error()), err)
	}))
}

func TestServerHandlePutKey(t *testing.T) {
	var (
		ctx      context.Context
		denyList *MemoryDenyList
		server   *Server
		store    *nsmemorystore.MemoryStore
	)

	requestForKey := func(key string, content string) *http.Request {
		r := mustNewRequest(ctx, http.MethodPut, "/"+key, map[string]string{"key": key}, bytes.NewReader([]byte(content)))
		r.Header.Set("Spring-Signature", "not valid")
		return r
	}

	signedRequestForKey := func(keyPair *nskey.KeyPair, content string) *http.Request {
		r := mustNewRequest(ctx, http.MethodPut, "/"+keyPair.PublicKey, map[string]string{"key": keyPair.PublicKey}, bytes.NewReader([]byte(content))) //nolint:lll
		r.Header.Set("Spring-Signature", hex.EncodeToString(keyPair.Sign([]byte(content))))
		return r
	}

	setup := func(test func(*testing.T)) func(*testing.T) {
		return func(t *testing.T) {
			t.Helper()

			ctx = context.Background()
			store = nsmemorystore.NewMemoryStore(logger)
			denyList = NewMemoryDenyList()
			server = NewServer(logger, store, denyList, defaultPort)
			server.timeNow = stableTimeFunc

			test(t)
		}
	}

	storeKeyContent := func(keyPair *nskey.KeyPair, timestamp time.Time) *nsstore.Board {
		content := []byte("some test board content")
		board := &nsstore.Board{
			Content:   content,
			Signature: keyPair.SignHex(content),
			Timestamp: timestamp,
		}
		err := store.Put(ctx, keyPair.PublicKey, board)
		require.NoError(t, err)
		return board
	}

	t.Run("Success", setup(func(t *testing.T) {
		keyPair := nskey.MustParseKeyPairUnchecked(samplePrivateKey)

		resp, err := server.handlePutKey(ctx, signedRequestForKey(keyPair, timestampTag(stableTime)+" some other content"))
		require.NoError(t, err)
		requireServerResponse(t, NewServerResponse(http.StatusOK, []byte(MessageKeyUpdated), http.Header{
			"Spring-Version": []string{"83"},
		}), resp)

		// Make sure content was actually persisted.
		_, err = store.Get(ctx, keyPair.PublicKey)
		require.NoError(t, err)
	}))

	t.Run("TestKey", setup(func(t *testing.T) {
		keyPair := nskey.MustParseKeyPairUnchecked(nskey.TestPrivateKey)

		_, err := server.handlePutKey(ctx, signedRequestForKey(keyPair, timestampTag(stableTime)+" some other content"))
		requireServerError(t, NewServerError(http.StatusUnauthorized, ErrMessageTestKey), err)
	}))

	t.Run("KeyInvalid", setup(func(t *testing.T) {
		_, err := server.handlePutKey(ctx, requestForKey(nskey.TestPrivateKey, timestampTag(stableTime)+" some other content")) //nolint:lll
		requireServerError(t, NewServerError(http.StatusForbidden, ErrMessageKeyInvalid), err)
	}))

	t.Run("KeyExpired", setup(func(t *testing.T) {
		_, err := server.handlePutKey(ctx, requestForKey("ab589f4dde9fce4180fcf42c7b05185b0a02a5d682e353fa39177995083e0519", timestampTag(stableTime)+" some other content")) //nolint:lll
		requireServerError(t, NewServerError(http.StatusForbidden, ErrMessageKeyExpired), err)
	}))

	t.Run("KeyNotYetValid", setup(func(t *testing.T) {
		_, err := server.handlePutKey(ctx, requestForKey("ab589f4dde9fce4180fcf42c7b05185b0a02a5d682e353fa39177995083e0525", timestampTag(stableTime)+" some other content")) //nolint:lll
		requireServerError(t, NewServerError(http.StatusForbidden, ErrMessageKeyNotYetValid), err)
	}))

	t.Run("DenyList", setup(func(t *testing.T) {
		_, err := server.handlePutKey(ctx, requestForKey(InfernalPublicKey, timestampTag(stableTime)+" some other content"))
		requireServerError(t, NewServerError(http.StatusForbidden, ErrMessageDeniedKey), err)
	}))

	t.Run("ContentTooLarge", setup(func(t *testing.T) {
		keyPair := nskey.MustParseKeyPairUnchecked(samplePrivateKey)

		var sb strings.Builder
		for {
			sb.WriteString(" here's some string content that'll keep being concatenated until we hit max length")

			if sb.Len() > MaxContentSize {
				break
			}
		}

		_, err := server.handlePutKey(ctx, signedRequestForKey(keyPair, timestampTag(stableTime)+sb.String()))
		requireServerError(t, NewServerError(http.StatusRequestEntityTooLarge, ErrMessageContentTooLarge), err)
	}))

	t.Run("SignatureMissing", setup(func(t *testing.T) {
		r := requestForKey(samplePublicKey, timestampTag(stableTime)+" some other content")
		r.Header.Set("Spring-Signature", "")

		_, err := server.handlePutKey(ctx, r)
		requireServerError(t, NewServerError(http.StatusBadRequest, ErrMessageSignatureMissing), err)
	}))

	t.Run("SignatureUnparseable", setup(func(t *testing.T) {
		r := requestForKey(samplePublicKey, timestampTag(stableTime)+" some other content")
		r.Header.Set("Spring-Signature", "zxt")

		_, err := server.handlePutKey(ctx, r)
		requireServerError(t, NewServerError(http.StatusBadRequest, ErrMessageSignatureUnparseable), err)
	}))

	t.Run("SignatureBadLength", setup(func(t *testing.T) {
		r := requestForKey(samplePublicKey, timestampTag(stableTime)+" some other content")
		r.Header.Set("Spring-Signature", "abcd")

		_, err := server.handlePutKey(ctx, r)
		requireServerError(t, NewServerError(http.StatusBadRequest, ErrMessageSignatureBadLength), err)
	}))

	t.Run("SignatureInvalid", setup(func(t *testing.T) {
		keyPair := nskey.MustParseKeyPairUnchecked(samplePrivateKey)

		r := requestForKey(samplePublicKey, timestampTag(stableTime)+" some other content")
		r.Header.Set("Spring-Signature", hex.EncodeToString(keyPair.Sign([]byte("other content"))))

		_, err := server.handlePutKey(ctx, r)
		requireServerError(t, NewServerError(http.StatusUnauthorized, ErrMessageSignatureInvalid), err)
	}))

	t.Run("TimestampMissing", setup(func(t *testing.T) {
		keyPair := nskey.MustParseKeyPairUnchecked(samplePrivateKey)

		_, err := server.handlePutKey(ctx, signedRequestForKey(keyPair, "some content without timestamp"))
		requireServerError(t, NewServerError(http.StatusBadRequest, ErrMessageTimestampMissing), err)
	}))

	t.Run("TimestampUnparseable", setup(func(t *testing.T) {
		keyPair := nskey.MustParseKeyPairUnchecked(samplePrivateKey)

		_, err := server.handlePutKey(ctx, signedRequestForKey(keyPair, `<time datetime="2022-11-09T10:11:79Z"> some other content`)) //nolint:lll
		requireServerError(t, NewServerError(http.StatusBadRequest, ErrMessageTimestampUnparseable), err)
	}))

	t.Run("TimestampInFuture", setup(func(t *testing.T) {
		keyPair := nskey.MustParseKeyPairUnchecked(samplePrivateKey)

		_, err := server.handlePutKey(ctx, signedRequestForKey(keyPair, timestampTag(stableTime.Add(3*time.Hour))+" some other content")) //nolint:lll
		requireServerError(t, NewServerError(http.StatusBadRequest, ErrMessageTimestampInFuture), err)
	}))

	t.Run("TimestampTooOld", setup(func(t *testing.T) {
		keyPair := nskey.MustParseKeyPairUnchecked(samplePrivateKey)

		_, err := server.handlePutKey(ctx, signedRequestForKey(keyPair, timestampTag(stableTime.Add(-nsstore.MaxContentAge).Add(-3*time.Hour))+" some other content")) //nolint:lll
		requireServerError(t, NewServerError(http.StatusBadRequest, ErrMessageTimestampTooOld), err)
	}))

	t.Run("TimestampOlderThanCurrent", setup(func(t *testing.T) {
		keyPair := nskey.MustParseKeyPairUnchecked(samplePrivateKey)
		_ = storeKeyContent(keyPair, stableTime)

		_, err := server.handlePutKey(ctx, signedRequestForKey(keyPair, timestampTag(stableTime.Add(-5*time.Minute))+" some other content")) //nolint:lll
		requireServerError(t, NewServerError(http.StatusConflict, ErrMessageTimestampOlderThanCurrent), err)
	}))
}

func TestParseTemplates(t *testing.T) {
	server := NewServer(logger, nil, nil, defaultPort)
	err := server.parseTemplates()
	require.NoError(t, err)
}

// High-level integration tests that exercise the entire stack including
// middleware. Each route should only get one assertion -- the bulk of logic
// testing should go into specific handler tests above.
func TestServerRouter(t *testing.T) {
	ctx := context.Background()
	denyList := NewMemoryDenyList()
	keyPair := nskey.MustParseKeyPairUnchecked(samplePrivateKey)
	store := nsmemorystore.NewMemoryStore(logger)

	server := NewServer(logger, store, denyList, defaultPort)
	server.timeNow = stableTimeFunc

	serveReq := func(ctx context.Context, method, path string, header http.Header, body []byte) {
		var bodyReader io.Reader
		if body != nil {
			bodyReader = bytes.NewReader(body)
		}

		r, _ := http.NewRequestWithContext(ctx, method, "http://spring83.example.com"+path, bodyReader)
		r.Header = header

		recorder := httptest.NewRecorder()
		server.router.ServeHTTP(recorder, r)

		res := recorder.Result()   //nolint:bodyclose
		if res.StatusCode >= 400 { //nolint:usestdlibvars
			require.Failf(t, "Request failure", "Expected non-error status code, was %d with body: %s",
				res.StatusCode,
				recorder.Body.String(),
			)
		}
	}

	content := []byte(timestampTag(stableTime) + " some content")

	serveReq(ctx, http.MethodGet, "/", nil, nil)
	serveReq(ctx, http.MethodPut, "/"+keyPair.PublicKey, http.Header{"Spring-Signature": []string{keyPair.SignHex(content)}}, content) //nolint:lll
	serveReq(ctx, http.MethodGet, "/"+keyPair.PublicKey, nil, nil)
}

func TestServerWrapEndpoint(t *testing.T) {
	var (
		ctx          context.Context
		ctxContainer *ContextContainer
		recorder     *httptest.ResponseRecorder
		server       *Server
	)

	setup := func(test func(*testing.T)) func(*testing.T) {
		return func(t *testing.T) {
			t.Helper()

			ctx = context.Background()
			ctxContainer = &ContextContainer{}
			ctx = context.WithValue(ctx, contextContainerContextKey{}, ctxContainer)
			recorder = httptest.NewRecorder()
			server = NewServer(logger, nil, nil, defaultPort)

			test(t)
		}
	}

	t.Run("ServerResponse", setup(func(t *testing.T) {
		handler := server.wrapEndpoint(func(ctx context.Context, r *http.Request) (*ServerResponse, error) {
			return NewServerResponse(http.StatusCreated, []byte("a body"), http.Header{"Spring-Version": []string{"83"}}), nil
		})

		handler.ServeHTTP(recorder, mustNewRequest(ctx, http.MethodGet, "/", nil, nil))

		require.Equal(t, http.StatusCreated, recorder.Code)
		require.Equal(t, "a body", recorder.Body.String())
		require.Equal(t, "text/html;charset=utf-8", recorder.Header().Get("Content-Type"))
		require.Equal(t, "83", recorder.Header().Get("Spring-Version"))

		require.Equal(t, http.StatusCreated, ctxContainer.StatusCode)
	}))

	t.Run("ServerError", setup(func(t *testing.T) {
		handler := server.wrapEndpoint(func(ctx context.Context, r *http.Request) (*ServerResponse, error) {
			return nil, NewServerError(http.StatusBadRequest, "an error")
		})

		handler.ServeHTTP(recorder, mustNewRequest(ctx, http.MethodGet, "/", nil, nil))

		require.Equal(t, http.StatusBadRequest, recorder.Code)
		require.Equal(t, "an error", recorder.Body.String())
		require.Equal(t, "text/html;charset=utf-8", recorder.Header().Get("Content-Type"))

		require.Equal(t, http.StatusBadRequest, ctxContainer.StatusCode)
	}))

	t.Run("InternalError", setup(func(t *testing.T) {
		handler := server.wrapEndpoint(func(ctx context.Context, r *http.Request) (*ServerResponse, error) {
			return nil, xerrors.Errorf("internal error")
		})

		handler.ServeHTTP(recorder, mustNewRequest(ctx, http.MethodGet, "/", nil, nil))

		require.Equal(t, http.StatusInternalServerError, recorder.Code)
		require.Equal(t, ErrMessageInternalError, recorder.Body.String())
		require.Equal(t, "text/html;charset=utf-8", recorder.Header().Get("Content-Type"))

		require.Equal(t, http.StatusInternalServerError, ctxContainer.StatusCode)
	}))
}

func TestIsTimestampOnly(t *testing.T) {
	timestampStr := `<time datetime="2006-01-02T15:04:05Z">`

	require.False(t, isTimestampOnly(timestampStr+" some other content"))
	require.True(t, isTimestampOnly(timestampStr))
	require.True(t, isTimestampOnly("    "+timestampStr+"    "))
}

func mustNewRequest(ctx context.Context, method, path string, muxVars map[string]string, body io.Reader) *http.Request {
	r, _ := http.NewRequestWithContext(ctx, method, "http://spring83.example.com"+path, body)
	r = mux.SetURLVars(r, muxVars) //nolint:contextcheck
	return r
}

func requireServerError(t *testing.T, expectedErr *ServerError, err error) {
	t.Helper()
	require.Equal(t, expectedErr, err)
}

func requireServerResponse(t *testing.T, expectedResp, resp *ServerResponse) {
	t.Helper()
	require.Equal(t, expectedResp, resp)
}

var stableTime = time.Date(2022, 11, 9, 10, 11, 12, 0, time.UTC)

// For injecting a stable time into a server because eventually the sample key
// we're using will expire, and if we were using `time.Now()`, that would start
// failing all the tests.
func stableTimeFunc() time.Time {
	return stableTime
}

func timestampTag(timestamp time.Time) string {
	return fmt.Sprintf(`<time datetime="%s">`, timestamp.Format(timestampFormat))
}
