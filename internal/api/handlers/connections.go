package handlers

import (
	"net/http"

	"go.uber.org/zap"

	"github.com/Alexmaster12345/netforge-api/internal/api/response"
	"github.com/Alexmaster12345/netforge-api/internal/netfilter"
)

type ConnectionsHandler struct {
	ct  *netfilter.ConntrackService
	log *zap.Logger
}

func NewConnectionsHandler(ct *netfilter.ConntrackService, log *zap.Logger) *ConnectionsHandler {
	return &ConnectionsHandler{ct: ct, log: log}
}

// GET /api/v1/connections
func (h *ConnectionsHandler) List(w http.ResponseWriter, r *http.Request) {
	conns, err := h.ct.ListConnections()
	if err != nil {
		h.log.Error("conntrack list failed", zap.Error(err))
		response.Error(w, http.StatusInternalServerError, "conntrack error: "+err.Error())
		return
	}
	response.JSON(w, http.StatusOK, map[string]any{
		"connections": conns,
		"total":       len(conns),
	})
}
