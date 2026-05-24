package middleware

import (
	"net/http"
	"strings"

	"github.com/Alexmaster12345/netforge-api/internal/api/response"
)

// BearerAuth returns a middleware that validates Authorization: Bearer <token>.
func BearerAuth(validTokens []string) func(http.Handler) http.Handler {
	set := make(map[string]struct{}, len(validTokens))
	for _, t := range validTokens {
		set[t] = struct{}{}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			header := r.Header.Get("Authorization")
			if header == "" {
				response.Error(w, http.StatusUnauthorized, "missing Authorization header")
				return
			}
			parts := strings.SplitN(header, " ", 2)
			if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
				response.Error(w, http.StatusUnauthorized, "invalid Authorization format — use: Bearer <token>")
				return
			}
			token := strings.TrimSpace(parts[1])
			if _, ok := set[token]; !ok {
				response.Error(w, http.StatusForbidden, "invalid or revoked API token")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
