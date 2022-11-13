package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"golang.org/x/xerrors"

	"github.com/brandur/neospring/internal/nskey"
	"github.com/brandur/neospring/internal/nsstore"
)

const (
	// Maximum size in bytes that any board post is allowed to be, as per for
	// the Spring '83 specification. This magic number in particular was chosen
	// because the internet's first ever web page was 2217 bytes in size.
	MaxContentSize = 2217

	// When calculating whether a post is expired to not yet valid, the amount
	// of tolerance to add to the calculation to allow for clock skew. This will
	// make the most difference as brand new posts are pushed to other servers
	// whose clock might be a little behind.
	TimestampTolerance = 5 * time.Minute
)

// Error messages returned by various server errors.
//
//nolint:lll
var (
	ErrMessageContentTooLarge           = fmt.Sprintf("Content is larger than the maximum allowed size of %d bytes.", MaxContentSize)
	ErrMessageDeniedKey                 = "This key is denied."
	ErrMessageInternalError             = "An internal error has occurred. Please report this to the server operator."
	ErrMessageKeyExpired                = "The given key is expired. The last four digits `MMYY` represent a month and year number which is now allowed to exceed the current month and year."
	ErrMessageKeyInvalid                = "The given key is invalid. It should be exactly 64 characters in length and be suffixed with `83eMMYY` where `MM` is a valid month number and `YY` are the last two digits of a year."
	ErrMessageKeyNotYetValid            = "The given key is not yet valid. The last four digits `MMYY` represent a month and year number which must be within two years of the current month and year."
	ErrMessageTestKey                   = "This request was made with Spring '83's test key, which is always rejected according to the specification."
	ErrMessageSignatureBadLength        = fmt.Sprintf("Signature in the `Spring-Signature` header should be exactly %d bytes long.", ed25519.SignatureSize)
	ErrMessageSignatureInvalid          = "Payload contents could not be verified against the signature in the `Spring-Signature` header."
	ErrMessageSignatureMissing          = "Missing `Spring-Signature` header which should contain a signature for the payload."
	ErrMessageSignatureUnparseable      = "Signature in the `Spring-Signature` header could not be decoded from hex to binary."
	ErrMessageTimestampInFuture         = "Content <time> timestamp should not be in the future."
	ErrMessageTimestampMissing          = "Expected content to contain a timestamp tag like `<time datetime=\"YYYY-MM-DDTHH:MM:SSZ\">`."
	ErrMessageTimestampOlderThanCurrent = "Content <time> timestamp is older than the timestamp already registered under the given key."
	ErrMessageTimestampTooOld           = "Content <time> timestamp should not be more than 22 days old."
	ErrMessageTimestampUnparseable      = "Could not parse timestamp tag. Tag should in standard format and UTC like `<time datetime=\"YYYY-MM-DDTHH:MM:SSZ\">`."
)

const (
	MessageKeyUpdated = "Content for the given key has been updated successfully."
)

type BoardNotFoundError struct {
	key string
}

func (e *BoardNotFoundError) Error() string { return fmt.Sprintf("Board not found: %q.", e.key) }

type IfModifiedSinceParseError struct {
	val string
}

func (e *IfModifiedSinceParseError) Error() string {
	return fmt.Sprintf("Error parsing `If-Modified-Since` header value: %q.", e.val)
}

type Server struct {
	boardStore  nsstore.BoardStore
	denyList    DenyList
	httpServer  *http.Server
	logger      *logrus.Logger
	router      *mux.Router
	testKeyPair *nskey.KeyPair
	timeNow     func() time.Time
}

func NewServer(logger *logrus.Logger, boardStore nsstore.BoardStore, denyList DenyList, port int) *Server {
	server := &Server{
		boardStore:  boardStore,
		denyList:    denyList,
		logger:      logger,
		testKeyPair: nskey.MustParseKeyPairUnchecked(nskey.TestPrivateKey),
		timeNow:     time.Now,
	}

	router := mux.NewRouter()

	router.Use((&ContextContainerMiddleware{}).Wrapper)
	router.Use((&CanonicalLogLineMiddleware{logger: server.logger}).Wrapper)
	router.Use((&CORSMiddleware{}).Wrapper)

	router.Handle("/", server.wrapEndpoint(server.handleIndex)).Methods(http.MethodGet)
	router.Handle("/{key}", server.wrapEndpoint(server.handleGetKey)).Methods(http.MethodGet)
	router.Handle("/{key}", server.wrapEndpoint(server.handlePutKey)).Methods(http.MethodPut)

	server.httpServer = &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: router,

		// Specified to prevent the "Slowloris" DOS attack, in which an attacker
		// sends many partial requests to exhaust a target server's connections.
		//
		// https://en.wikipedia.org/wiki/Slowloris_(computer_security)
		ReadHeaderTimeout: 5 * time.Second,
	}
	server.router = router

	return server
}

func (s *Server) Start(ctx context.Context) error {
	s.logger.Infof("Listening on %s\n", s.httpServer.Addr)

	// On SIGTERM, try to shut the server down gracefully: stop accepting new
	// connections, and wait for existing ones to finish.
	//
	// Among other things, this is useful for Heroku, which will send a SIGTERM
	// on a deploy or periodic dyno restart to give us a chance to wind down
	// safely before we're forced to exit.
	idleConnsClosed := make(chan struct{})
	go func() {
		sigterm := make(chan os.Signal, 1)
		signal.Notify(sigterm, syscall.SIGTERM)
		<-sigterm

		s.logger.Infof("Performing graceful shutdown")
		if err := s.httpServer.Shutdown(ctx); err != nil {
			// Error from closing listeners, or context timeout
			s.logger.Errorf("Server shutdown error: %v", err)
		}

		close(idleConnsClosed)
	}()

	if err := s.httpServer.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return xerrors.Errorf("error listening on %s: %w", s.httpServer.Addr, err)
	}

	<-idleConnsClosed

	return nil
}

func (s *Server) handleGetKey(ctx context.Context, r *http.Request) (*ServerResponse, error) {
	var (
		board *nsstore.Board
		err   error
		key   = mux.Vars(r)["key"]
	)

	// Shortcut to help guarantee that all not found errors look the same, as
	// recommended by the specification.
	notFoundError := func() error {
		return NewServerError(http.StatusNotFound, (&BoardNotFoundError{key}).Error())
	}

	// Spring '83 defines a test key that can be requested to help with client
	// integrations. We check this right at the top because we'd like for it to
	// be able to bypass the standard key checks as within the next couple of
	// years it will technically expire.
	//
	// The specification suggests returning fresh content for the test key every
	// time, so generate something random. Also has the effect of bumping the
	// timestamp so that it's never stale.
	if key == s.testKeyPair.PublicKey {
		board, err = s.randomizeTestKeyBoard(ctx)
		if err != nil {
			return nil, xerrors.Errorf("error randomizing test board: %w", err)
		}
		goto respond
	}

	_, err = nskey.ParseKey(key, s.timeNow())
	if err != nil {
		switch {
		case errors.Is(err, nskey.ErrKeyExpired):
			return nil, NewServerError(http.StatusForbidden, ErrMessageKeyExpired)
		case errors.Is(err, nskey.ErrKeyInvalid):
			return nil, NewServerError(http.StatusForbidden, ErrMessageKeyInvalid)
		case errors.Is(err, nskey.ErrKeyNotYetValid):
			return nil, NewServerError(http.StatusForbidden, ErrMessageKeyNotYetValid)
		}

		return nil, xerrors.Errorf("error parsing key: %w", err)
	}

	if s.denyList.Contains(key) {
		return nil, NewServerError(http.StatusForbidden, ErrMessageDeniedKey)
	}

	board, err = s.boardStore.Get(ctx, key)
	if err != nil {
		if errors.Is(err, nsstore.ErrKeyNotFound) {
			return nil, notFoundError()
		}

		return nil, xerrors.Errorf("error getting key %q from store: %w", key, err)
	}

	// The Spring '83 spec stipulates that boards are never deleted, but can be
	// effectively removed by sending a last update to them that contains only a
	// timestamp, but no other content. If storing such a board, a server should
	// respond as if the board doesn't exist.
	if isTimestampOnly(string(board.Content)) {
		return nil, notFoundError()
	}

	if ifModifiedSinceStr := r.Header.Get("If-Modified-Since"); ifModifiedSinceStr != "" {
		ifModifiedSince, err := time.Parse(http.TimeFormat, ifModifiedSinceStr)
		if err != nil {
			return nil, NewServerError(http.StatusBadRequest, (&IfModifiedSinceParseError{ifModifiedSinceStr}).Error())
		}

		if ifModifiedSince.After(board.Timestamp) {
			return nil, notFoundError()
		}
	}

respond:
	return NewServerResponse(http.StatusOK, board.Content, http.Header{
		"Last-Modified":    []string{board.Timestamp.Format(http.TimeFormat)},
		"Spring-Signature": []string{board.Signature},
		"Spring-Version":   []string{"83"},
	}), nil
}

func (s *Server) handlePutKey(ctx context.Context, r *http.Request) (*ServerResponse, error) {
	key := mux.Vars(r)["key"]

	if key == s.testKeyPair.PublicKey {
		return nil, NewServerError(http.StatusUnauthorized, ErrMessageTestKey)
	}

	keyObj, err := nskey.ParseKey(key, s.timeNow())
	if err != nil {
		switch {
		case errors.Is(err, nskey.ErrKeyExpired):
			return nil, NewServerError(http.StatusForbidden, ErrMessageKeyExpired)
		case errors.Is(err, nskey.ErrKeyInvalid):
			return nil, NewServerError(http.StatusForbidden, ErrMessageKeyInvalid)
		case errors.Is(err, nskey.ErrKeyNotYetValid):
			return nil, NewServerError(http.StatusForbidden, ErrMessageKeyNotYetValid)
		}

		return nil, xerrors.Errorf("error parsing key: %w", err)
	}

	if s.denyList.Contains(key) {
		return nil, NewServerError(http.StatusForbidden, ErrMessageDeniedKey)
	}

	content, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, xerrors.Errorf("error reading request body: %v", err)
	}

	// Spring '83 dictates a maximum content size of 2217 bytes.
	if len(content) > MaxContentSize {
		return nil, NewServerError(http.StatusRequestEntityTooLarge, ErrMessageContentTooLarge)
	}

	sigStr := r.Header.Get("Spring-Signature")
	if sigStr == "" {
		return nil, NewServerError(http.StatusBadRequest, ErrMessageSignatureMissing)
	}

	sig, err := hex.DecodeString(sigStr)
	if err != nil {
		return nil, NewServerError(http.StatusBadRequest, ErrMessageSignatureUnparseable)
	}

	if len(sig) != ed25519.SignatureSize {
		return nil, NewServerError(http.StatusBadRequest, ErrMessageSignatureBadLength)
	}

	// Verify the signature early because it might prevent against other types
	// of bad requests that might be more expensive to check.
	if !keyObj.Verify(content, sig) {
		return nil, NewServerError(http.StatusUnauthorized, ErrMessageSignatureInvalid)
	}

	match := timestampRE.FindStringSubmatch(string(content))
	if match == nil {
		return nil, NewServerError(http.StatusBadRequest, ErrMessageTimestampMissing)
	}

	timestamp, err := time.Parse(timestampFormat, match[1])
	if err != nil {
		return nil, NewServerError(http.StatusBadRequest, ErrMessageTimestampUnparseable)
	}

	if timestamp.Add(-TimestampTolerance).After(s.timeNow()) {
		return nil, NewServerError(http.StatusBadRequest, ErrMessageTimestampInFuture)
	}

	if timestamp.Add(TimestampTolerance).Before(s.timeNow().Add(-nsstore.MaxContentAge)) {
		return nil, NewServerError(http.StatusBadRequest, ErrMessageTimestampTooOld)
	}

	// If we have a board with a timestamp newer than the given one, we're meant
	// to return a 409 conflict to the requesting user indicating so.
	board, err := s.boardStore.Get(ctx, key)
	if err == nil {
		if board.Timestamp.After(timestamp) {
			return nil, NewServerError(http.StatusConflict, ErrMessageTimestampOlderThanCurrent)
		}
	}

	return NewServerResponse(http.StatusOK, []byte(MessageKeyUpdated), http.Header{
		"Spring-Version": []string{"83"},
	}), nil
}

func (s *Server) handleIndex(ctx context.Context, r *http.Request) (*ServerResponse, error) {
	return NewServerResponse(http.StatusOK, []byte("hello"), nil), nil
}

// Randomizes board contents for the test key, as recommended by the Spring '83
// while fulfilling test key requests.
func (s *Server) randomizeTestKeyBoard(ctx context.Context) (*nsstore.Board, error) {
	content := getRandomQuote()

	board := &nsstore.Board{
		Content:   []byte(content),
		Signature: s.testKeyPair.SignHex([]byte(content)),
		Timestamp: s.timeNow(),
	}

	if err := s.boardStore.Put(ctx, s.testKeyPair.PublicKey, board); err != nil {
		return nil, xerrors.Errorf("error storing test board: %w", err)
	}

	return board, nil
}

// Provides a wrapper around endpoints that makes them more testable by allowing
// them to return response and error structs instead of writing to RAW HTTP
// primitives. Also implements returning a 500 internal server when an unhandled
// error is encountered.
func (s *Server) wrapEndpoint(h func(ctx context.Context, r *http.Request) (*ServerResponse, error)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctxContainer := ContextContainerFrom(r.Context())

		writeStatus := func(statusCode int) {
			ctxContainer.StatusCode = statusCode
			w.WriteHeader(statusCode)
		}

		w.Header().Set("Content-Type", "text/html;charset=utf-8")

		resp, err := h(r.Context(), r)
		if err != nil {
			var serverErr *ServerError
			if errors.As(err, &serverErr) {
				s.logger.Infof("User error [status %d]: %v", serverErr.StatusCode, serverErr)
				writeStatus(serverErr.StatusCode)
				_, _ = w.Write([]byte(serverErr.Error()))
				return
			}

			s.logger.Errorf("Internal server error: %v", err)
			writeStatus(http.StatusInternalServerError)
			_, _ = w.Write([]byte(ErrMessageInternalError))
			return
		}

		if len(resp.Header) > 0 {
			for k, vs := range resp.Header {
				for _, v := range vs {
					w.Header().Add(k, v)
				}
			}
		}

		if resp.StatusCode != 0 {
			writeStatus(resp.StatusCode)
		}

		_, _ = w.Write(resp.Body)
	})
}

// Implements the error interface and provides an easy way to return a
// particular status code and error message that's interpreted by `wrapEndpoint`
// and written back to an `http.ResponseWriter`.
type ServerError struct {
	Message    string
	StatusCode int
}

func NewServerError(statusCode int, message string) *ServerError {
	return &ServerError{StatusCode: statusCode, Message: message}
}

func (e *ServerError) Error() string {
	return e.Message
}

// Wraps up an HTTP status code, headers, and body and which can be returned by
// handlers as a more testable alternative to a HTTP response. Interpreted by
// `wrapEndpoint` and written back to an `http.ResponseWriter`.
type ServerResponse struct {
	Body       []byte
	Header     http.Header
	StatusCode int
}

func NewServerResponse(statusCode int, body []byte, header http.Header) *ServerResponse {
	return &ServerResponse{Body: body, Header: header, StatusCode: statusCode}
}

// From spec: <time datetime="YYYY-MM-DDTHH:MM:SSZ">.
const timestampFormat = "2006-01-02T15:04:05Z"

// The specification strictly states that parsing is allowed to be very strict,
// so we don't bother with generous allowances normally tolerated for HTML.
var timestampRE = regexp.MustCompile(`<time datetime="([1-9]\d{3}-(0[1-9]|1[0-2])-\d\dT\d\d:\d\d:\d\dZ)">`)

// Checks to see if some content is only a timestamp tag, which is akin to a
// deleted board which will respond with a 404.
func isTimestampOnly(content string) bool {
	match := timestampRE.FindStringSubmatch(content)
	if match == nil {
		return false
	}

	return strings.TrimSpace(strings.Replace(content, match[0], "", 1)) == ""
}
