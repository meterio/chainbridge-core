package admin

import (
	"math/big"

	"github.com/ChainSafe/chainbridge-core/crypto/secp256k1"

	"github.com/ethereum/go-ethereum/common"
)

//flag vars
var (
	Admin              string
	Implementation     string
	Relayer            string
	DepositNonce       uint64
	DomainID           uint8
	ChainID            uint64
	Fee                string
	RelayerThreshold   uint64
	SignatureThreshold uint64
	Amount             string
	TokenID            string
	Handler            string
	Token              string
	Decimals           uint64
	Recipient          string
	Bridge             string
	Account             string
	Proxy              string
	Signature          string
	FeeHandler         bool
)

//processed flag vars
var (
	BridgeAddr         common.Address
	AccountAddr         common.Address
	ProxyAddr          common.Address
	SignatureAddr      common.Address
	HandlerAddr        common.Address
	RelayerAddr        common.Address
	AdminAddr          common.Address
	ImplementationAddr common.Address
	RecipientAddr      common.Address
	TokenAddr          common.Address
	RealAmount         *big.Int
)

// global flags
var (
	url           string
	gasLimit      uint64
	gasPrice      *big.Int
	senderKeyPair *secp256k1.Keypair
	prepare       bool
)
