package consts

import "time"

const DefaultGasLimit = 2000000
const DefaultDeployGasLimit = 6000000
const DefaultGasPrice = 20000000000
const DefaultGasMultiplier = 1
const DefaultBlockConfirmations = 0
const DefaultDelayConfirmations = 0
const DefaultBlockRetryInterval = 5 * time.Second
const DefaultEndpointTries = 5

// Time between retrying a failed tx
const TxRetryInterval = time.Second * 2

// Maximum number of tx retries before exiting
const TxRetryLimit = 5

const (
	TxFailedOnChain = "transaction failed on chain"

	ErrNonceTooLow   = "nonce too low"
	ErrTxUnderpriced = "replacement transaction underpriced"
)
