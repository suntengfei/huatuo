package middleware

import (
    "net/http"

    "huatuo-bamai/internal/conf"

    "github.com/gin-gonic/gin"
)

func BasicAuth() gin.HandlerFunc {
    return func(c *gin.Context) {
        cfg := conf.Get()
        if cfg == nil {
            c.AbortWithStatus(http.StatusInternalServerError)
            return
        }

        auth := cfg.APIServer.Auth

        // 没启用认证，直接放行
        if !auth.Enable {
            c.Next()
            return
        }

        user, pass, ok := c.Request.BasicAuth()
        if !ok {
            c.Header("WWW-Authenticate", `Basic realm="huatuo-bamai"`)
            c.AbortWithStatus(http.StatusUnauthorized)
            return
        }

        if user != auth.Username || pass != auth.Password {
            c.AbortWithStatus(http.StatusUnauthorized)
            return
        }

        c.Next()
    }
}