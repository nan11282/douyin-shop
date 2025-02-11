// main.go
package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	pb "douyin-shop/path" // 请替换为实际的proto生成路径

	"github.com/casbin/casbin/v2"
	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/app/server"
	"github.com/golang-jwt/jwt/v4"
	consulapi "github.com/hashicorp/consul/api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

type authService struct {
	pb.UnimplementedAuthServiceServer
}
type CustomClaims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

func parseToken(tokenStr string) (*CustomClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte("your-secret-key"), nil
	})

	if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
		return claims, nil
	} else {
		return nil, err
	}
}
func (s *authService) DeliverTokenByRPC(ctx context.Context, req *pb.DeliverTokenReq) (*pb.DeliveryResp, error) {
	token := "generated_token_for_" + req.UserId
	return &pb.DeliveryResp{Token: token}, nil
}

func (s *authService) VerifyTokenByRPC(ctx context.Context, req *pb.VerifyTokenReq) (*pb.VerifyResp, error) {
	valid := req.Token != "" && req.Token[:19] == "generated_token_for_"
	return &pb.VerifyResp{Res: valid}, nil
}

func initCasbin() (*casbin.Enforcer, error) {
	enforcer, err := casbin.NewEnforcer("C:/Users/Lenovo/Desktop/b/douyin-shop/model.conf", "C:/Users/Lenovo/Desktop/b/douyin-shop/policy.csv")
	if err != nil {
		return nil, fmt.Errorf("failed to initialize CasBin: %v", err)
	}
	log.Println("CasBin initialized successfully")
	return enforcer, nil
}

func initAuthServiceClient() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(
		ctx,
		authServiceAddr,
		grpc.WithInsecure(),
		grpc.WithBlock(),
	)
	if err != nil {
		log.Fatalf("连接gRPC服务失败: %v", err)
	}
	authServiceClient = pb.NewAuthServiceClient(conn)
	log.Println("gRPC客户端初始化成功")
}

func verifyToken(token string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	resp, err := authServiceClient.VerifyTokenByRPC(ctx, &pb.VerifyTokenReq{Token: token})
	if err != nil {
		return false, err
	}
	return resp.Res, nil
}

func authMiddleware(e *casbin.Enforcer) app.HandlerFunc {
	return func(c context.Context, ctx *app.RequestContext) {
		token := ctx.Request.Header.Get("Authorization")
		if token == "" {
			ctx.JSON(http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
			return
		}

		if len(token) > 7 && token[:7] == "Bearer " {
			token = token[7:]
		}

		claims, err := parseToken(token)
		if err != nil {
			if err == jwt.ErrSignatureInvalid {
				// Token无效的情况
				ctx.JSON(http.StatusForbidden, map[string]string{"error": "禁止访问"})
				return
			}

			// 其他类型错误视为服务器问题
			log.Printf("Token解析错误: %v", err)
			ctx.JSON(http.StatusInternalServerError, map[string]string{"error": "服务器内部错误"})
			return
		}

		sub := claims.Username // 或 sub := claims.Subject，根据你的JWT配置

		if sub == "" {
			ctx.JSON(http.StatusForbidden, map[string]string{"error": "令牌中缺少用户信息"})
			return
		}
		obj := ctx.Request.URI().Path()
		act := ctx.Request.Method()

		if ok, err := e.Enforce(sub, obj, act); err != nil {
			log.Printf("权限验证错误: %v", err)
			ctx.JSON(http.StatusInternalServerError, map[string]string{"error": "服务器内部错误"})
			return
		} else if !ok {
			ctx.JSON(http.StatusForbidden, map[string]string{"error": "禁止访问"})
			return
		}

		ctx.Next(c)
	}
}

func helloHandler(c context.Context, ctx *app.RequestContext) {
	ctx.String(http.StatusOK, "Hello, World!")
}

func adminHandler(c context.Context, ctx *app.RequestContext) {
	ctx.String(http.StatusOK, "Admin Page")
}

func registerService(consulClient *consulapi.Client, serviceName string, serviceID string, servicePort int) error {
	registration := &consulapi.AgentServiceRegistration{
		ID:      serviceID,
		Name:    serviceName,
		Port:    servicePort,
		Address: "127.0.0.1",
		Tags:    []string{"primary"},
		Check: &consulapi.AgentServiceCheck{
			HTTP:     fmt.Sprintf("http://127.0.0.1:%d/health", servicePort),
			Interval: "10s",
			Timeout:  "1s",
		},
	}

	err := consulClient.Agent().ServiceRegister(registration)
	if err != nil {
		return err
	}
	log.Println("服务已注册到Consul")
	return nil
}

const (
	authServiceAddr = "localhost:50051"
)

var authServiceClient pb.AuthServiceClient

func main() {
	fmt.Println("启动服务...")

	// 1. 先启动gRPC服务端
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("监听失败: %v", err)
	}
	grpcServer := grpc.NewServer()
	pb.RegisterAuthServiceServer(grpcServer, &authService{})
	reflection.Register(grpcServer)
	go func() {
		log.Printf("gRPC服务端正在监听 %s", lis.Addr().String())
		if err := grpcServer.Serve(lis); err != nil {
			log.Fatalf("gRPC服务启动失败: %v", err)
		}
	}()

	// 2. 初始化gRPC客户端（带超时）
	initAuthServiceClient()

	// 3. 初始化Consul客户端
	consulConfig := consulapi.DefaultConfig()
	consulClient, err := consulapi.NewClient(consulConfig)
	if err != nil {
		log.Fatalf("创建Consul客户端失败: %v", err)
	}

	// 4. 注册服务到Consul
	serviceName := "my-service"
	serviceID := "my-service-1"
	servicePort := 8080
	if err := registerService(consulClient, serviceName, serviceID, servicePort); err != nil {
		log.Fatalf("Consul服务注册失败: %v", err)
	}

	// 5. 初始化CasBin
	e, err := initCasbin()
	if err != nil {
		log.Fatalf("CasBin初始化失败: %v", err)
	}

	// 6. 配置Hertz服务器
	h := server.Default(server.WithHostPorts(":8080"))
	h.Use(authMiddleware(e)) // 添加鉴权中间件

	// 7. 注册路由
	h.GET("/hello", helloHandler)
	h.GET("/admin", adminHandler)
	h.GET("/health", func(c context.Context, ctx *app.RequestContext) {
		ctx.String(http.StatusOK, "OK")
	})

	log.Println("所有组件初始化完成")
	log.Println("HTTP服务正在监听 :8080")
	h.Spin()
}
