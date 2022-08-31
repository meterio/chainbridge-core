package opentelemetry

import (
	"context"
	"net/url"

	"github.com/ChainSafe/chainbridge-core/relayer"
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
	util.HEAD_STATS.Store(id, value)
}

func (t *OpenTelemetry) TrackSyncBlock(id uint8, value int64, fromAddr string) {
	util.SYNC_STATS.Store(id, value)
}

func (t *OpenTelemetry) MonitorHeadBlocks(chains []relayer.RelayedChain) {
	meter := t.metrics.meter
	var counter metric.Int64CounterObserver

	batchObserver := meter.NewBatchObserver(
		func(ctx context.Context, result metric.BatchObserverResult) {
			for _, chain := range chains {
				domainID := chain.DomainID()
				labels := chain.HeadBlockLabels()

				if value, ok := util.HEAD_STATS.Load(domainID); ok {
					result.Observe(labels, counter.Observation(value.(int64)))
				}
			}
		})

	counter, _ = batchObserver.NewInt64CounterObserver("head_block")
}

func (t *OpenTelemetry) MonitorSyncBlocks(chains []relayer.RelayedChain) {
	meter := t.metrics.meter
	var counter metric.Int64CounterObserver

	// Arbitrary key/value labels.
	batchObserver := meter.NewBatchObserver(
		// SDK periodically calls this function to collect data.
		func(ctx context.Context, result metric.BatchObserverResult) {
			for _, chain := range chains {
				domainID := chain.DomainID()
				labels := chain.SyncBlockLabels()

				if value, ok := util.SYNC_STATS.Load(domainID); ok {
					result.Observe(labels, counter.Observation(value.(int64)))
				}
			}
		})

	counter, _ = batchObserver.NewInt64CounterObserver("sync_block")
}
