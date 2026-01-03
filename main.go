package main

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/rueidis"
	"github.com/rs/cors"

	"github.com/otakakot/new-year-2026/internal/core"
	"github.com/otakakot/new-year-2026/internal/handler"
	"github.com/otakakot/new-year-2026/pkg/api"
	"github.com/otakakot/new-year-2026/pkg/schema"
)

func main() {
	port := cmp.Or(os.Getenv("PORT"), "8080")

	dsn := cmp.Or(
		os.Getenv("DSN"),
		"postgres://postgres:postgres@postgres:5432/postgres?sslmode=disable",
	)

	conn, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		panic(err)
	}

	pool, err := pgxpool.NewWithConfig(context.Background(), conn)
	if err != nil {
		panic(err)
	}
	defer pool.Close()

	if err := pool.Ping(context.Background()); err != nil {
		panic(err)
	}

	if _, err := schema.New(pool).InsertJwkSet(
		context.Background(),
		core.GenerateDERPrivateKey(),
	); err != nil {
		panic(err)
	}

	redis, _ := rueidis.NewClient(rueidis.ClientOption{
		InitAddress: []string{cmp.Or(os.Getenv("REDIS_URL"), "redis:6379")},
	})
	defer redis.Close()

	origin := cmp.Or(os.Getenv("ORIGIN"), "http://localhost:"+port)

	rpid := strings.Split(strings.Split(origin, "://")[1], ":")[0]

	wa, err := webauthn.New(&webauthn.Config{
		RPID:          rpid,
		RPDisplayName: "otakakotid",
		RPOrigins:     []string{origin},
	})
	if err != nil {
		panic(err)
	}

	hdl := api.HandlerFromMux(
		handler.New(pool, redis, wa, origin),
		http.NewServeMux(),
	)

	cs := cors.New(cors.Options{
		AllowedOrigins:   []string{"http://localhost:5500"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Authorization", "Content-Type"},
		AllowCredentials: true,
	})

	srv := &http.Server{
		Addr:              fmt.Sprintf(":%s", port),
		Handler:           cs.Handler(hdl),
		ReadHeaderTimeout: 30 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)

	defer stop()

	go func() {
		slog.Info("start server listen")

		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			panic(err)
		}
	}()

	<-ctx.Done()

	slog.Info("start server shutdown")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)

	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		panic(err)
	}

	slog.Info("done server shutdown")
}
