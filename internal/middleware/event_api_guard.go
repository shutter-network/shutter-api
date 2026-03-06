package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/shutter-network/shutter-api/common"
	sherror "github.com/shutter-network/shutter-api/internal/error"
)

// EventAPIGuard returns 501 Not Implemented when DisableEventAPI is true
// (i.e., when SHUTTER_EVENT_REGISTRY_CONTRACT_ADDRESS is not configured).
// When enabled, requests proceed to the event handlers.
func EventAPIGuard(config *common.Config) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		if config.DisableEventAPI {
			err := sherror.NewHttpError(
				"Event API is disabled on this deployment",
				"Event API is disabled on this deployment",
				http.StatusNotImplemented,
			)
			ctx.Error(err)
			ctx.Abort()
			return
		}
		ctx.Next()
	}
}
