package handlers

import (
	"encoding/json"
	"net"
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

type BlacklistHandler struct {
	store *store.Store
	nft   *netfilter.NFTService
	log   *zap.Logger
}

func NewBlacklistHandler(s *store.Store, nft *netfilter.NFTService, log *zap.Logger) *BlacklistHandler {
	return &BlacklistHandler{store: s, nft: nft, log: log}
}

// POST /api/v1/firewall/blacklist
func (h *BlacklistHandler) Add(w http.ResponseWriter, r *http.Request) {
	var req models.AddBlacklistRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if net.ParseIP(req.IP) == nil {
		response.Error(w, http.StatusUnprocessableEntity, "invalid IP address")
		return
	}

	if err := h.store.AddBlacklist(&models.BlacklistEntry{IP: req.IP}); err != nil {
		response.Error(w, http.StatusConflict, err.Error())
		return
	}

	// Create the underlying drop-all rule.
	rule := &models.Rule{
		ID:        uuid.NewString(),
		Direction: models.DirectionIngress,
		SourceIP:  req.IP,
		Action:    models.ActionDrop,
		Comment:   "blacklist: " + req.Comment,
		CreatedAt: time.Now().UTC(),
	}
	if err := h.nft.AddRule(rule); err != nil {
		h.store.DeleteBlacklist(req.IP)
		h.log.Error("nft AddRule for blacklist failed", zap.Error(err))
		response.Error(w, http.StatusInternalServerError, "kernel error: "+err.Error())
		return
	}
	h.store.AddRule(rule)

	entry := &models.BlacklistEntry{
		IP:      req.IP,
		Comment: req.Comment,
		RuleID:  rule.ID,
	}
	h.store.DeleteBlacklist(req.IP) // remove placeholder
	if err := h.store.AddBlacklist(entry); err != nil {
		response.Error(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.log.Info("IP blacklisted", zap.String("ip", req.IP), zap.String("rule_id", rule.ID))
	response.JSON(w, http.StatusCreated, entry)
}

// GET /api/v1/firewall/blacklist
func (h *BlacklistHandler) List(w http.ResponseWriter, r *http.Request) {
	entries := h.store.ListBlacklist()
	response.JSON(w, http.StatusOK, map[string]any{
		"blacklist": entries,
		"total":     len(entries),
	})
}

// DELETE /api/v1/firewall/blacklist/{ip}
func (h *BlacklistHandler) Remove(w http.ResponseWriter, r *http.Request) {
	ip := chi.URLParam(r, "ip")
	entry, ok := h.store.GetBlacklist(ip)
	if !ok {
		response.Error(w, http.StatusNotFound, "IP not in blacklist")
		return
	}

	// Remove the underlying rule.
	if rule, ok := h.store.GetRule(entry.RuleID); ok {
		if err := h.nft.DeleteRule(rule); err != nil {
			h.log.Error("nft DeleteRule for blacklist failed", zap.Error(err))
		}
		h.store.DeleteRule(entry.RuleID)
	}
	h.store.DeleteBlacklist(ip)

	h.log.Info("IP removed from blacklist", zap.String("ip", ip))
	response.JSON(w, http.StatusOK, map[string]string{"removed": ip})
}
