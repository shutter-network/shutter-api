package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/shutter-network/shutter-api/common"
	sherror "github.com/shutter-network/shutter-api/internal/error"
)

// EventAPIGuard returns 501 Not Implemented when EventAPIEnabled is false.
// When enabled, requests proceed to the event handlers.
func EventAPIGuard(config *common.Config) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		if config.DisableEventAPI {
			err := sherror.NewHttpError(
				"Service is unavailable.",
				"Service is unavailable.",
				http.StatusNotImplemented,
			)
			ctx.Error(err)
			ctx.Abort()
			return
		}
		ctx.Next()
	}
}
