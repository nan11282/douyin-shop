// main.go
package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	fileadapter "github.com/casbin/casbin/v2/persist/file-adapter"
	consulapi "github.com/hashicorp/consul/api"
)

// 初始化 CasBin
func initCasbin() (*casbin.Enforcer, error) {
	m, err := model.NewModelFromFile("model.conf")
	if err != nil {
		return nil, err
	}

	a := fileadapter.NewAdapter("policy.csv")
	e, err := casbin.NewEnforcer(m, a)
	if err != nil {
		return nil, err
	}

	return e, nil
}

// 权限检查中间件
func authMiddleware(e *casbin.Enforcer) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sub := r.URL.Query().Get("user")
			if sub == "" {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			obj := r.URL.Path
			act := r.Method

			if ok, err := e.Enforce(sub, obj, act); err != nil {
				log.Printf("Enforce error: %v", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			} else if !ok {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func helloHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello, World!")
}

func adminHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Admin Page")
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

	return consulClient.Agent().ServiceRegister(registration)
}

func main() {
	// 创建 Consul 客户端
	consulConfig := consulapi.DefaultConfig()
	consulClient, err := consulapi.NewClient(consulConfig)
	if err != nil {
		log.Fatalf("Failed to create Consul client: %v", err)
	}

	// 注册服务
	serviceName := "my-service"
	serviceID := "my-service-1"
	servicePort := 8080

	if err := registerService(consulClient, serviceName, serviceID, servicePort); err != nil {
		log.Fatalf("Failed to register service: %v", err)
	}

	// 初始化 CasBin
	e, err := initCasbin()
	if err != nil {
		log.Fatalf("Failed to initialize CasBin: %v", err)
	}

	// 启动 HTTP 服务器
	http.Handle("/hello", authMiddleware(e)(http.HandlerFunc(helloHandler)))
	http.Handle("/admin", authMiddleware(e)(http.HandlerFunc(adminHandler)))
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "OK")
	})

	fmt.Println("Starting server at port 8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
