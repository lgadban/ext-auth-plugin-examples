package pkg

import (
	"context"
	"errors"
	"fmt"
	"log"

	envoyauthv2 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	"github.com/solo-io/ext-auth-plugins/api"
	"github.com/solo-io/go-utils/contextutils"
	"go.uber.org/zap"
	"google.golang.org/grpc"
)

var (
	UnexpectedConfigError = func(typ interface{}) error {
		return errors.New(fmt.Sprintf("unexpected config type %T", typ))
	}
	_ api.ExtAuthPlugin = new(RequiredHeaderPlugin)
)

type RequiredHeaderPlugin struct{}

type Config struct {
	RequiredHeader string
	AllowedValues  []string
}

func (p *RequiredHeaderPlugin) NewConfigInstance(ctx context.Context) (interface{}, error) {
	return &Config{}, nil
}

func (p *RequiredHeaderPlugin) GetAuthService(ctx context.Context, configInstance interface{}) (api.AuthService, error) {
	config, ok := configInstance.(*Config)
	if !ok {
		return nil, UnexpectedConfigError(configInstance)
	}

	logger(ctx).Infow("Parsed RequiredHeaderAuthService config",
		zap.Any("requiredHeader", config.RequiredHeader),
		zap.Any("allowedHeaderValues", config.AllowedValues),
	)

	valueMap := map[string]bool{}
	for _, v := range config.AllowedValues {
		valueMap[v] = true
	}

	return &RequiredHeaderAuthService{
		RequiredHeader: config.RequiredHeader,
		AllowedValues:  valueMap,
	}, nil
}

type RequiredHeaderAuthService struct {
	RequiredHeader string
	AllowedValues  map[string]bool
}

// You can use the provided context to perform operations that are bound to the services lifecycle.
func (c *RequiredHeaderAuthService) Start(context.Context) error {
	// no-op
	return nil
}

func (c *RequiredHeaderAuthService) Authorize(ctx context.Context, request *api.AuthorizationRequest) (*api.AuthorizationResponse, error) {
	conn, err := grpc.Dial("custom-ext-auth.default.svc.cluster.local:50051", grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()

	extAuthClient := envoyauthv2.NewAuthorizationClient(conn)

	checkResponse, err := extAuthClient.Check(context.Background(), request.CheckRequest)
	if err != nil {
		log.Fatalf("could not CheckRequest: %v", err)
	}

	log.Printf("successfully checked, response: %v\n", checkResponse.GetHttpResponse())
	logger(ctx).Infow("Required header not found, denying access")

	response := &api.AuthorizationResponse{
		CheckResponse: *checkResponse,
	}

	return response, nil
}

func logger(ctx context.Context) *zap.SugaredLogger {
	return contextutils.LoggerFrom(contextutils.WithLogger(ctx, "header_value_plugin"))
}
