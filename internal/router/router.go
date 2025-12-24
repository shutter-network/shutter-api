package router

import (
	"context"
	"net/http"
	"time"

	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/shutter-network/shutter-api/common"
	"github.com/shutter-network/shutter-api/docs"
	"github.com/shutter-network/shutter-api/internal/middleware"
	"github.com/shutter-network/shutter-api/internal/service"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

func NewRouter(
	ctx context.Context,
	db *pgxpool.Pool,
	contract *common.Contract,
	ethClient *ethclient.Client,
	config *common.Config,
) *gin.Engine {
	router := gin.New()
	router.Use(gin.Logger())
	router.Use(gin.Recovery())
	router.Use(cors.Default())
	router.Use(middleware.ErrorHandler())

	cryptoService := service.NewCryptoService(db, contract, ethClient, config)
	docs.SwaggerInfo.BasePath = "/api"
	api := router.Group("/api")
	{
		api.GET("/get_decryption_key", cryptoService.GetDecryptionKey)
		api.GET("/get_data_for_encryption", cryptoService.GetDataForEncryption)
		api.POST("/register_identity", cryptoService.RegisterIdentity)
		api.POST("/compile_event_trigger_definition", cryptoService.CompileEventTriggerDefinition)
		api.GET("/decrypt_commitment", cryptoService.DecryptCommitment)
		api.POST("/register_event_identity", cryptoService.RegisterEventIdentity)
		api.GET("/get_event_trigger_ttl", cryptoService.GetEventIdentityRegistrationTTL)
	}
	router.GET("/docs/*any", ginSwagger.WrapHandler(swaggerFiles.Handler, func(c *ginSwagger.Config) {
		c.Title = "Shutter-API"
	}))
	return router
}

// RunWithContext starts the server and handles graceful shutdown when context is cancelled.
func RunWithContext(ctx context.Context, cancel context.CancelFunc, router *gin.Engine, addr string) error {
	srv := &http.Server{
		Addr:    addr,
		Handler: router,
	}

	// Start server in a goroutine
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			cancel()
		}
	}()

	// Wait for context cancellation
	<-ctx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		return err
	}

	return nil
}
