package opentelemetry

import (
	"github.com/meterio/chainbridge-core/relayer/message"
	"github.com/rs/zerolog/log"
)

// ConsoleTelemetry is telemetry that logs metrics and should be used
// when metrics sending to OpenTelemetry should be disabled
type ConsoleTelemetry struct{}

func (t *ConsoleTelemetry) TrackDepositMessage(m *message.Message) {
	log.Info().Msgf("Relayer route message: %+v", m)
}
