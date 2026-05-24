package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"go.uber.org/zap"

	"github.com/Alexmaster12345/netforge-api/internal/api/handlers"
	"github.com/Alexmaster12345/netforge-api/internal/api/middleware"
	"github.com/Alexmaster12345/netforge-api/internal/netfilter"
	"github.com/Alexmaster12345/netforge-api/internal/store"
)

func NewRouter(s *store.Store, nft *netfilter.NFTService, ct *netfilter.ConntrackService, tokens []string, log *zap.Logger) http.Handler {
	r := chi.NewRouter()

	// Global middleware
	r.Use(chimw.RealIP)
	r.Use(chimw.RequestID)
	r.Use(middleware.Recoverer(log))
	r.Use(middleware.RequestLogger(log))

	// Unauthenticated
	r.Get("/api/v1/health", handlers.Health)

	// Authenticated routes
	r.Group(func(r chi.Router) {
		r.Use(middleware.BearerAuth(tokens))

		rules := handlers.NewRulesHandler(s, nft, log)
		r.Post("/api/v1/firewall/rules", rules.Create)
		r.Get("/api/v1/firewall/rules", rules.List)
		r.Get("/api/v1/firewall/rules/{id}", rules.Get)
		r.Delete("/api/v1/firewall/rules/{id}", rules.Delete)

		bl := handlers.NewBlacklistHandler(s, nft, log)
		r.Post("/api/v1/firewall/blacklist", bl.Add)
		r.Get("/api/v1/firewall/blacklist", bl.List)
		r.Delete("/api/v1/firewall/blacklist/{ip}", bl.Remove)

		conns := handlers.NewConnectionsHandler(ct, log)
		r.Get("/api/v1/connections", conns.List)
	})

	return r
}
