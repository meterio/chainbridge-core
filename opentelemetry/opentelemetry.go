package opentelemetry

import (
	"context"
	"fmt"
	"go.opentelemetry.io/otel/attribute"
	"net/url"

	"github.com/ChainSafe/chainbridge-core/relayer/message"
	"github.com/ChainSafe/chainbridge-core/util"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/metric"
)

type OpenTelemetry struct {
	metrics *ChainbridgeMetrics
}

// NewOpenTelemetry initializes OpenTelementry metrics
func NewOpenTelemetry(collectorRawURL string) (*OpenTelemetry, error) {
	collectorURL, err := url.Parse(collectorRawURL)
	if err != nil {
		return &OpenTelemetry{}, err
	}

	metricOptions := []otlpmetrichttp.Option{
		otlpmetrichttp.WithURLPath(collectorURL.Path),
		otlpmetrichttp.WithEndpoint(collectorURL.Host),
	}
	if collectorURL.Scheme == "http" {
		metricOptions = append(metricOptions, otlpmetrichttp.WithInsecure())
	}

	metrics, err := initOpenTelemetryMetrics(metricOptions...)
	if err != nil {
		return &OpenTelemetry{}, err
	}

	return &OpenTelemetry{
		metrics: metrics,
	}, nil
}

// TrackDepositMessage extracts metrics from deposit message and sends
// them to OpenTelemetry collector
func (t *OpenTelemetry) TrackDepositMessage(m *message.Message) {
	t.metrics.DepositEventCount.Add(context.Background(), 1)
}

func (t *OpenTelemetry) TrackHeadBlock(id uint8, value int64, fromAddr string) {
	if _, ok := t.metrics.HeadBlocks[id]; !ok {
		t.metrics.HeadBlocks[id] = metric.Must(t.metrics.meter).NewInt64GaugeObserver(
			fmt.Sprintf("hb_%v", id),
			func(ctx context.Context, result metric.Int64ObserverResult) {
				result.Observe(value, attribute.KeyValue{Key: "from", Value: attribute.StringValue(fromAddr)},
					attribute.KeyValue{Key: "domain_id", Value: attribute.Int64Value(int64(id))},
					attribute.KeyValue{Key: "name", Value: attribute.StringValue(util.DomainIdToName[id])},
					attribute.KeyValue{Key: "type", Value: attribute.StringValue("HeadBlock")})
			},
			metric.WithDescription(fmt.Sprintf("Head Blocks of %s Chain", util.DomainIdToName[id])),
		)
	}

	t.metrics.HeadBlocks[id].Observation(value)
}

func (t *OpenTelemetry) TrackStartBlock(id uint8, value int64, fromAddr string) {
	if _, ok := t.metrics.StartBlocks[id]; !ok {
		t.metrics.StartBlocks[id] = metric.Must(t.metrics.meter).NewInt64GaugeObserver(
			fmt.Sprintf("sb_%v", id),
			func(ctx context.Context, result metric.Int64ObserverResult) {
				result.Observe(value, attribute.KeyValue{Key: "from", Value: attribute.StringValue(fromAddr)},
					attribute.KeyValue{Key: "domain_id", Value: attribute.Int64Value(int64(id))},
					attribute.KeyValue{Key: "name", Value: attribute.StringValue(util.DomainIdToName[id])},
					attribute.KeyValue{Key: "type", Value: attribute.StringValue("StartBlock")})
			},
			metric.WithDescription(fmt.Sprintf("Start Blocks of %s Chain", util.DomainIdToName[id])),
		)
	}

	t.metrics.StartBlocks[id].Observation(value)
}
