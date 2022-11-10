package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"golang.org/x/xerrors"
)

const (
	MaxContentSize     = 2217
	TimestampTolerance = 5 * time.Minute
)

const (
	MessageKeyUpdated = "Content for the given key has been updated successfully."
)

const (
	TestPrivateKey = "3371f8b011f51632fea33ed0a3688c26a45498205c6097c352bd4d079d224419"
	TestPublicKey  = "ab589f4dde9fce4180fcf42c7b05185b0a02a5d682e353fa39177995083e0583"
)

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
	boardStore  BoardStore
	denyList    DenyList
	httpServer  *http.Server
	router      *mux.Router
	testKeyPair *KeyPair
	timeNow     func() time.Time
}

func NewServer(boardStore BoardStore, denyList DenyList, port int) *Server {
	server := &Server{
		boardStore:  boardStore,
		denyList:    denyList,
		testKeyPair: MustParseKeyPair(TestPrivateKey, TestPublicKey),
		timeNow:     time.Now,
	}

	router := mux.NewRouter()
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

func (s *Server) Start() error {
	fmt.Printf("Listening on %s\n", s.httpServer.Addr)

	if err := s.httpServer.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return xerrors.Errorf("error listening on %s: %w", s.httpServer.Addr, err)
	}

	return nil
}

func (s *Server) handleGetKey(ctx context.Context, r *http.Request) (*ServerResponse, error) {
	var (
		board *MemoryBoard
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

	_, err = parseKey(key, s.timeNow())
	if err != nil {
		switch {
		case errors.Is(err, ErrKeyExpired):
			return nil, NewServerError(http.StatusForbidden, ErrMessageKeyExpired)
		case errors.Is(err, ErrKeyInvalid):
			return nil, NewServerError(http.StatusForbidden, ErrMessageKeyInvalid)
		case errors.Is(err, ErrKeyNotYetValid):
			return nil, NewServerError(http.StatusForbidden, ErrMessageKeyNotYetValid)
		}

		return nil, xerrors.Errorf("error parsing key: %w", err)
	}

	if s.denyList.Contains(key) {
		return nil, NewServerError(http.StatusForbidden, ErrMessageDeniedKey)
	}

	board, err = s.boardStore.Get(ctx, key)
	if err != nil {
		if errors.Is(err, ErrKeyNotFound) {
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

	keyBytes, err := parseKey(key, s.timeNow())
	if err != nil {
		switch {
		case errors.Is(err, ErrKeyExpired):
			return nil, NewServerError(http.StatusForbidden, ErrMessageKeyExpired)
		case errors.Is(err, ErrKeyInvalid):
			return nil, NewServerError(http.StatusForbidden, ErrMessageKeyInvalid)
		case errors.Is(err, ErrKeyNotYetValid):
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

	signatureStr := r.Header.Get("Spring-Signature")
	if signatureStr == "" {
		return nil, NewServerError(http.StatusBadRequest, ErrMessageSignatureMissing)
	}

	signature, err := hex.DecodeString(signatureStr)
	if err != nil {
		return nil, NewServerError(http.StatusBadRequest, ErrMessageSignatureUnparseable)
	}

	if len(signature) != ed25519.SignatureSize {
		return nil, NewServerError(http.StatusBadRequest, ErrMessageSignatureBadLength)
	}

	// Verify the signature early because it might prevent against other types
	// of bad requests that might be more expensive to check.
	if !ed25519.Verify(keyBytes, content, signature) {
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

	if timestamp.Add(TimestampTolerance).Before(s.timeNow().Add(-MaxContentAge)) {
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
func (s *Server) randomizeTestKeyBoard(ctx context.Context) (*MemoryBoard, error) {
	content := generateContent()

	board := &MemoryBoard{
		Content:   []byte(content),
		Signature: s.testKeyPair.SignHex([]byte(content)),
		Timestamp: s.timeNow(),
	}

	if err := s.boardStore.Put(ctx, s.testKeyPair.PublicKey, board); err != nil {
		return nil, xerrors.Errorf("error storing test board: %w", err)
	}

	return board, nil
}

type ServerResponse struct {
	Body       []byte
	Header     http.Header
	StatusCode int
}

func NewServerResponse(statusCode int, body []byte, header http.Header) *ServerResponse {
	return &ServerResponse{Body: body, Header: header, StatusCode: statusCode}
}

func (s *Server) wrapEndpoint(h func(ctx context.Context, r *http.Request) (*ServerResponse, error)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")

		resp, err := h(r.Context(), r)
		if err != nil {
			var serverErr *ServerError
			if errors.As(err, &serverErr) {
				w.WriteHeader(serverErr.StatusCode)
				_, _ = w.Write([]byte(err.Error()))
				return
			}

			w.WriteHeader(http.StatusInternalServerError)
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
			w.WriteHeader(resp.StatusCode)
		}

		_, _ = w.Write(resp.Body)
	})
}

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

func generateContent() string {
	return "this is some test content and it should probably be expanded upon"
}

// From spec: <time datetime="YYYY-MM-DDTHH:MM:SSZ">.
const timestampFormat = "2006-01-02T15:04:05Z"

// The specification strictly states that parsing is allowed to be very strict,
// so we don't bother with generous allowances normally tolerated for HTML.
var timestampRE = regexp.MustCompile(`<time datetime="([1-9]\d{3}-(0[1-9]|1[0-2])-\d\dT\d\d:\d\d:\d\dZ)">`)

func isTimestampOnly(content string) bool {
	match := timestampRE.FindStringSubmatch(content)
	if match == nil {
		return false
	}

	return strings.TrimSpace(strings.Replace(content, match[0], "", 1)) == ""
}
