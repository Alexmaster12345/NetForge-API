package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/joho/godotenv"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/Alexmaster12345/netforge-api/internal/api"
	"github.com/Alexmaster12345/netforge-api/internal/config"
	"github.com/Alexmaster12345/netforge-api/internal/netfilter"
	"github.com/Alexmaster12345/netforge-api/internal/store"
)

func main() {
	_ = godotenv.Load() // optional .env file

	cfg := config.Load()
	log := buildLogger(cfg.LogLevel)
	defer log.Sync() //nolint:errcheck

	log.Info("NetForge API starting",
		zap.String("addr", cfg.ListenAddr),
		zap.String("table", cfg.NFTTable),
		zap.Bool("dry_run", cfg.DryRun),
	)

	s := store.New()

	nft, err := netfilter.NewNFTService(log, cfg.NFTTable, cfg.DryRun)
	if err != nil {
		log.Fatal("failed to initialise NFTService", zap.Error(err))
	}

	ct := netfilter.NewConntrackService(log, cfg.DryRun)

	router := api.NewRouter(s, nft, ct, cfg.APITokens, log)

	srv := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		log.Info("listening", zap.String("addr", cfg.ListenAddr))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal("server error", zap.Error(err))
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info("shutting down gracefully…")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Error("graceful shutdown failed", zap.Error(err))
	}
	log.Info("stopped")
}

func buildLogger(level string) *zap.Logger {
	lvl := zapcore.InfoLevel
	_ = lvl.UnmarshalText([]byte(level))

	cfg := zap.NewProductionConfig()
	cfg.Level = zap.NewAtomicLevelAt(lvl)
	cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	l, err := cfg.Build()
	if err != nil {
		panic(err)
	}
	return l
}
