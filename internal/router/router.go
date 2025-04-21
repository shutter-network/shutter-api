package router

import (
	"fmt"
	"os"
	"strconv"

	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/shutter-network/shutter-api/common"
	"github.com/shutter-network/shutter-api/docs"
	"github.com/shutter-network/shutter-api/internal/ipratelimiter.go"
	"github.com/shutter-network/shutter-api/internal/middleware"
	"github.com/shutter-network/shutter-api/internal/service"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

func NewRouter(
	db *pgxpool.Pool,
	contract *common.Contract,
	ethClient *ethclient.Client,
	config *common.Config,
) (*gin.Engine, *ipratelimiter.IPEndpointLimiter) {

	defaultRateLimitStr := os.Getenv("DEFAULT_RATE_LIMIT")
	defaultRateLimit, err := strconv.ParseInt(defaultRateLimitStr, 10, 0)
	if err != nil {
		panic(fmt.Errorf("failed to convert DEFAULT_RATE_LIMIT to int: %w", err))
	}

	// Create limiter with default settings
	limiter := ipratelimiter.NewIPEndpointLimiter(int(defaultRateLimit))

	registerRateLimitStr := os.Getenv("REGISTER_IDENTITY_RATE_LIMIT")
	registerRateLimit, err := strconv.ParseInt(registerRateLimitStr, 10, 0)
	if err != nil {
		panic(fmt.Errorf("failed to convert REGISTER_IDENTITY_RATE_LIMIT to int: %w", err))
	}

	// Configure endpoint-specific monthly limits
	limiter.SetLimit("/api/register_identity", int(registerRateLimit))

	router := gin.New()
	router.Use(gin.Logger())
	router.Use(gin.Recovery())
	router.Use(cors.Default())
	router.Use(middleware.ErrorHandler())

	// Apply rate limiting to all routes
	router.Use(limiter.RateLimitMiddleware())

	cryptoService := service.NewCryptoService(db, contract, ethClient, config)
	docs.SwaggerInfo.BasePath = "/api"
	api := router.Group("/api")
	{
		api.GET("/get_decryption_key", cryptoService.GetDecryptionKey)
		api.GET("/get_data_for_encryption", cryptoService.GetDataForEncryption)
		api.POST("/register_identity", cryptoService.RegisterIdentity)
		api.GET("/decrypt_commitment", cryptoService.DecryptCommitment)
	}
	router.GET("/docs/*any", ginSwagger.WrapHandler(swaggerFiles.Handler, func(c *ginSwagger.Config) {
		c.Title = "Shutter-API"
	}))
	return router, limiter
}
