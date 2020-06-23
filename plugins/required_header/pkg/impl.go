package pkg

import (
	"context"
	"errors"
	"fmt"

	"contrib.go.opencensus.io/exporter/zipkin"
	"go.opencensus.io/plugin/ochttp/propagation/b3"
	"go.opencensus.io/stats"
	"go.opencensus.io/stats/view"
	"go.opencensus.io/trace"

	envoycorev2 "github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	envoyauthv2 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	"github.com/solo-io/ext-auth-plugins/api"
	"github.com/solo-io/go-utils/contextutils"
	"go.uber.org/zap"
	"google.golang.org/grpc/metadata"

	openzipkin "github.com/openzipkin/zipkin-go"
	zipkinHTTP "github.com/openzipkin/zipkin-go/reporter/http"
)

var (
	UnexpectedConfigError = func(typ interface{}) error {
		return errors.New(fmt.Sprintf("unexpected config type %T", typ))
	}
	_ api.ExtAuthPlugin = new(RequiredHeaderPlugin)

	reqTotal     = stats.Int64("req_total", "Count of requests", "1")
	reqTotalView = &view.View{
		Name:        "demo/req_total",
		Measure:     reqTotal,
		Description: "Total count of requests",
		Aggregation: view.Count(),
	}
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
func (c *RequiredHeaderAuthService) Start(ctx context.Context) error {
	if err := view.Register(reqTotalView); err != nil {
		logger(ctx).With(zap.Error(err)).Error("failed to register view")
	}

	localEndpoint, err := openzipkin.NewEndpoint("ext-auth-plugin", "192.168.1.1:1337")
	if err != nil {
		return err
	}
	reporter := zipkinHTTP.NewReporter("http://zipkin.default.svc.cluster.local:9411/api/v2/spans")
	ze := zipkin.NewExporter(reporter, localEndpoint)
	trace.RegisterExporter(ze)

	trace.ApplyConfig(trace.Config{DefaultSampler: trace.AlwaysSample()})

	return nil
}

func (c *RequiredHeaderAuthService) Authorize(ctx context.Context, request *api.AuthorizationRequest) (*api.AuthorizationResponse, error) {
	stats.Record(ctx, reqTotal.M(1))

	incomingMetadata, _ := metadata.FromIncomingContext(ctx)

	traceIDStr := incomingMetadata.Get("x-b3-traceid")[0]
	spanIDStr := incomingMetadata.Get("x-b3-spanid")[0]
	sampledStr := incomingMetadata.Get("x-b3-sampled")[0]
	logger(ctx).Infof("trace: '%s', span: '%s', sampled: '%s'", traceIDStr, spanIDStr, sampledStr)

	traceID, _ := b3.ParseTraceID(traceIDStr)
	spanID, _ := b3.ParseSpanID(spanIDStr)
	traceOpts, _ := b3.ParseSampled(sampledStr)

	// create SpanContext from incoming gRPC metadata
	spanContext := trace.SpanContext{
		TraceID:      traceID,
		SpanID:       spanID,
		TraceOptions: traceOpts,
	}
	_, span := trace.StartSpanWithRemoteParent(ctx, "ext-auth-plugin/authorize", spanContext)
	defer span.End()

	for key, value := range request.CheckRequest.GetAttributes().GetRequest().GetHttp().GetHeaders() {
		if key == c.RequiredHeader {
			logger(ctx).Infow("Found required header, checking value.", "header", key, "value", value)

			if _, ok := c.AllowedValues[value]; ok {
				logger(ctx).Infow("Header value match. Allowing request.")
				response := api.AuthorizedResponse()

				// Append extra header
				response.CheckResponse.HttpResponse = &envoyauthv2.CheckResponse_OkResponse{
					OkResponse: &envoyauthv2.OkHttpResponse{
						Headers: []*envoycorev2.HeaderValueOption{{
							Header: &envoycorev2.HeaderValue{
								Key:   "matched-allowed-headers",
								Value: "true",
							},
						}},
					},
				}

				response.UserInfo.UserID = "test-user"
				return response, nil
			}
			logger(ctx).Infow("Header value does not match allowed values, denying access.")
			return api.UnauthorizedResponse(), nil
		}
	}
	logger(ctx).Infow("Required header not found, denying access")
	return api.UnauthorizedResponse(), nil
}

func logger(ctx context.Context) *zap.SugaredLogger {
	return contextutils.LoggerFrom(contextutils.WithLogger(ctx, "header_value_plugin"))
}
