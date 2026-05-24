package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/Alexmaster12345/netforge-api/internal/api/response"
	"github.com/Alexmaster12345/netforge-api/internal/models"
	"github.com/Alexmaster12345/netforge-api/internal/netfilter"
	"github.com/Alexmaster12345/netforge-api/internal/store"
)

type RulesHandler struct {
	store *store.Store
	nft   *netfilter.NFTService
	log   *zap.Logger
}

func NewRulesHandler(s *store.Store, nft *netfilter.NFTService, log *zap.Logger) *RulesHandler {
	return &RulesHandler{store: s, nft: nft, log: log}
}

// POST /api/v1/firewall/rules
func (h *RulesHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req models.CreateRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if msg := req.Validate(); msg != "" {
		response.Error(w, http.StatusUnprocessableEntity, msg)
		return
	}

	rule := &models.Rule{
		ID:              uuid.NewString(),
		Direction:       req.Direction,
		SourceIP:        req.SourceIP,
		DestinationPort: req.DestinationPort,
		Protocol:        req.Protocol,
		Action:          req.Action,
		Comment:         req.Comment,
		CreatedAt:       time.Now().UTC(),
	}

	if err := h.nft.AddRule(rule); err != nil {
		h.log.Error("nft AddRule failed", zap.Error(err))
		response.Error(w, http.StatusInternalServerError, "kernel error: "+err.Error())
		return
	}
	h.store.AddRule(rule)

	h.log.Info("rule created",
		zap.String("id", rule.ID),
		zap.String("action", rule.Action),
		zap.String("source_ip", rule.SourceIP),
		zap.Int("dest_port", rule.DestinationPort))

	response.JSON(w, http.StatusCreated, rule)
}

// GET /api/v1/firewall/rules
func (h *RulesHandler) List(w http.ResponseWriter, r *http.Request) {
	rules := h.store.ListRules()
	response.JSON(w, http.StatusOK, map[string]any{
		"rules": rules,
		"total": len(rules),
	})
}

// GET /api/v1/firewall/rules/{id}
func (h *RulesHandler) Get(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	rule, ok := h.store.GetRule(id)
	if !ok {
		response.Error(w, http.StatusNotFound, "rule not found")
		return
	}
	response.JSON(w, http.StatusOK, rule)
}

// DELETE /api/v1/firewall/rules/{id}
func (h *RulesHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	rule, ok := h.store.GetRule(id)
	if !ok {
		response.Error(w, http.StatusNotFound, "rule not found")
		return
	}

	if err := h.nft.DeleteRule(rule); err != nil {
		h.log.Error("nft DeleteRule failed", zap.String("id", id), zap.Error(err))
		response.Error(w, http.StatusInternalServerError, "kernel error: "+err.Error())
		return
	}
	h.store.DeleteRule(id)

	h.log.Info("rule deleted", zap.String("id", id))
	response.JSON(w, http.StatusOK, map[string]string{"deleted": id})
}
