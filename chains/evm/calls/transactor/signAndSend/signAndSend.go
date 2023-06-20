package signAndSend

import (
	"context"
	"math/big"

	"github.com/ethereum/go-ethereum/core/types"

	"github.com/ethereum/go-ethereum/common"
	"github.com/meterio/chainbridge-core/chains/evm/calls"
	"github.com/meterio/chainbridge-core/chains/evm/calls/transactor"
	"github.com/rs/zerolog/log"
)

var DefaultTransactionOptions = transactor.TransactOptions{
	GasLimit: 2000000,
	GasPrice: big.NewInt(0),
	Value:    big.NewInt(0),
}

type signAndSendTransactor struct {
	TxFabric       calls.TxFabric
	gasPriceClient calls.GasPricer
	client         calls.ClientDispatcher

	domainId uint8
}

const gasStationUrl = "https://gasstation-mainnet.matic.network/v2"

type gasOption struct {
	MaxPriorityFee float64 `json:"maxPriorityFee"`
	MaxFee         float64 `json:"maxFee"`
}

type gasStation struct {
	SafeLow          gasOption `json:"safeLow"`
	Standard         gasOption `json:"standard"`
	Fast             gasOption `json:"fast"`
	EstimatedBaseFee float64   `json:"estimatedBaseFee"`
	BlockTime        *big.Int  `json:"blockTime"`
	BlockNumber      *big.Int  `json:"blockNumber"`
}

func NewSignAndSendTransactor(txFabric calls.TxFabric, gasPriceClient calls.GasPricer, client calls.ClientDispatcher, domainId uint8) transactor.Transactor {
	return &signAndSendTransactor{
		TxFabric:       txFabric,
		gasPriceClient: gasPriceClient,
		client:         client,
		domainId:       domainId,
	}
}

func (t *signAndSendTransactor) Transact(to *common.Address, data []byte, opts transactor.TransactOptions) (*common.Hash, *types.Receipt, error) {
	h, err := t.transact(to, data, opts)
	if err != nil {
		return &common.Hash{}, nil, err
	}

	r, err := t.client.WaitAndReturnTxReceipt(*h)
	if err != nil {
		return &common.Hash{}, r, err
	}

	return h, r, nil
}

func (t *signAndSendTransactor) transact(to *common.Address, data []byte, opts transactor.TransactOptions) (*common.Hash, error) {
	defer t.client.UnlockNonce()
	t.client.LockNonce()
	n, err := t.client.UnsafeNonce()
	if err != nil {
		return &common.Hash{}, err
	}

	err = transactor.MergeTransactionOptions(&opts, &DefaultTransactionOptions)
	if err != nil {
		return &common.Hash{}, err
	}

	gp := []*big.Int{opts.GasPrice}
	if opts.GasPrice.Cmp(big.NewInt(0)) == 0 {
		// if t.client.PolygonGasStation() {
		// 	gp = make([]*big.Int, 2)

		// 	resp, err := http.Get(gasStationUrl)
		// 	if err != nil {
		// 		return &common.Hash{}, err
		// 	}
		// 	defer resp.Body.Close()
		// 	body, err := io.ReadAll(resp.Body)

		// 	var res gasStation
		// 	err = json.Unmarshal(body, &res)
		// 	if err != nil {
		// 		return &common.Hash{}, err
		// 	}
		// 	decimal := new(big.Int).SetUint64(9)

		// 	maxPriorityFee, err := calls.UserAmountToWei(fmt.Sprintf("%f", res.Fast.MaxPriorityFee), decimal)
		// 	if err != nil {
		// 		return &common.Hash{}, err
		// 	}
		// 	maxFee, err := calls.UserAmountToWei(fmt.Sprintf("%f", res.Fast.MaxFee), decimal)
		// 	if err != nil {
		// 		return &common.Hash{}, err
		// 	}

		// 	log.Info().Uint64("maxPriorityFee", maxPriorityFee.Uint64()).Uint64("maxFee", maxFee.Uint64()).Msg("Polygon GasStation")

		// 	gp[0] = maxPriorityFee
		// 	gp[1] = maxFee
		// } else {
		gp, err = t.gasPriceClient.GasPrice()
		if err != nil {
			return &common.Hash{}, err
		}
		// }
	}

	tx, err := t.TxFabric(n.Uint64(), to, opts.Value, opts.GasLimit, gp, data)
	if err != nil {
		return &common.Hash{}, err
	}

	h, err := t.client.SignAndSendTransaction(context.TODO(), tx)
	if err != nil {
		log.Error().Err(err)
		return &common.Hash{}, err
	}
	log.Info().Uint8("domainID", t.domainId).Str("nonce", n.String()).Msgf("sent tx %v", h.String())

	return &h, nil
}
