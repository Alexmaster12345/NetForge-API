package handlers

import (
	"net/http"
	"runtime"
	"time"

	"github.com/Alexmaster12345/netforge-api/internal/api/response"
)

var startTime = time.Now()

func Health(w http.ResponseWriter, r *http.Request) {
	response.JSON(w, http.StatusOK, map[string]any{
		"status":   "ok",
		"uptime":   time.Since(startTime).String(),
		"go":       runtime.Version(),
		"platform": runtime.GOOS + "/" + runtime.GOARCH,
	})
}
