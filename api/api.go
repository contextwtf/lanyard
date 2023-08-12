package api

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/contextwtf/lanyard/api/tracing"
	"github.com/ethereum/go-ethereum/common"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/rs/cors"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/hlog"
	"github.com/rs/zerolog/log"
	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace/ext"
)

type Server struct {
	db   *pgxpool.Pool
	tlru *lru.Cache[common.Hash, cachedTree]
}

func New(db *pgxpool.Pool) *Server {
	l, err := lru.New[common.Hash, cachedTree](1000)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to create lru cache")
	}
	return &Server{
		db:   db,
		tlru: l,
	}
}

func (s *Server) Handler(env, gitSha string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/tree", s.TreeHandler)
	mux.HandleFunc("/api/v1/tree/pin", s.PinTree)
	mux.HandleFunc("/api/v1/proof", s.GetProof)
	mux.HandleFunc("/api/v1/root", s.GetRoot)
	mux.HandleFunc("/api/v1/roots", s.GetRoot)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, gitSha)
	})

	h := http.Handler(mux)
	h = versionHandler(h, gitSha)
	h = hlog.UserAgentHandler("user_agent")(h)
	h = hlog.RefererHandler("referer")(h)
	h = hlog.RequestIDHandler("req_id", "Request-Id")(h)
	h = hlog.URLHandler("path")(h)
	h = hlog.MethodHandler("method")(h)
	h = tracingHandler(os.Getenv("DD_ENV"), os.Getenv("DD_SERVICE"), gitSha, h)
	h = RemoteAddrHandler("ip")(h)
	h = hlog.NewHandler(log.Logger)(h) // needs to be last for log values to correctly be passed to context

	if env == "production" {
		return h
	}

	c := cors.New(cors.Options{
		AllowedOrigins:     []string{"*"},
		AllowCredentials:   false,
		OptionsPassthrough: false,
	})

	h = c.Handler(h)

	return h
}

func ipFromRequest(r *http.Request) string {
	if r.Header.Get("fastly-client-ip") != "" {
		return r.Header.Get("fastly-client-ip")
	}

	if r.Header.Get("x-forwarded-for") != "" {
		group := strings.Split(r.Header.Get("x-forwarded-for"), ", ")
		if len(group) > 0 {
			return group[len(group)-1]
		}
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}

	return ""
}

func RemoteAddrHandler(fieldKey string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := ipFromRequest(r)
			if ip != "" {
				log := zerolog.Ctx(r.Context())
				log.UpdateContext(func(c zerolog.Context) zerolog.Context {
					return c.Str("ip", ip)
				})
			}

			next.ServeHTTP(w, r.WithContext(r.Context()))
		})
	}
}

func versionHandler(h http.Handler, sha string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("server-version", sha)
		h.ServeHTTP(w, r)
	})
}

func tracingHandler(env, service, sha string, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			h.ServeHTTP(w, r)
			return
		}

		span, ctx := tracing.SpanFromContext(r.Context(), "http.request")

		defer span.Finish()
		log := zerolog.Ctx(ctx)

		if env != "" {
			log.UpdateContext(func(c zerolog.Context) zerolog.Context {
				return c.Uint64("dd.trace_id", span.Context().TraceID()).
					Str("dd.service", service).
					Str("dd.env", env).
					Str("dd.version", sha)
			})
		}

		span.SetTag(ext.ResourceName, r.URL.Path)
		span.SetTag(ext.SpanType, ext.SpanTypeWeb)
		span.SetTag(ext.HTTPMethod, r.Method)

		sc := &statusCapture{ResponseWriter: w}

		requestStart := time.Now()
		h.ServeHTTP(sc, r.WithContext(ctx))

		// log every request
		log.Info().
			Int("status", sc.status).
			Dur("duration", time.Since(requestStart)).
			Msg("")

		span.SetTag(ext.HTTPCode, sc.status)
	})
}

type statusCapture struct {
	http.ResponseWriter
	wroteHeader bool
	status      int
}

func (s *statusCapture) WriteHeader(c int) {
	s.status = c
	s.wroteHeader = true
	s.ResponseWriter.WriteHeader(c)
}

func (s *statusCapture) Write(b []byte) (int, error) {
	if !s.wroteHeader {
		s.WriteHeader(http.StatusOK)
	}
	return s.ResponseWriter.Write(b)
}

func (s *Server) sendJSON(r *http.Request, w http.ResponseWriter, response any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func (s *Server) sendJSONError(
	r *http.Request,
	w http.ResponseWriter,
	err error,
	code int,
	customMessage string,
) {
	w.Header().Set("Content-Type", "application/json")
	if code == http.StatusNotFound && w.Header().Get("Cache-Control") == "" {
		w.Header().Set("Cache-Control", "no-cache, max-age=0, must-revalidate")
	}

	// all headers need to be set before this line
	w.WriteHeader(code)

	if err != nil {
		log.Ctx(r.Context()).Err(err).Send()
	}

	message := http.StatusText(code)
	if customMessage != "" {
		message = customMessage
	}

	json.NewEncoder(w).Encode(map[string]any{
		"error":   true,
		"message": message,
	})
}
