package config

import (
	"os"
	"strings"
)

type Config struct {
	ListenAddr  string
	APITokens   []string // comma-separated bearer tokens
	NFTTable    string
	LogLevel    string
	DryRun      bool // skip kernel calls, log only
}

func Load() *Config {
	return &Config{
		ListenAddr: getEnv("NETFORGE_ADDR", ":8090"),
		APITokens:  splitTokens(getEnv("NETFORGE_API_TOKENS", "changeme")),
		NFTTable:   getEnv("NETFORGE_NFT_TABLE", "netforge"),
		LogLevel:   getEnv("NETFORGE_LOG_LEVEL", "info"),
		DryRun:     getEnv("NETFORGE_DRY_RUN", "false") == "true",
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func splitTokens(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}
