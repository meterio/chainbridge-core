package admin

import (
	"math/big"

	"github.com/meterio/chainbridge-core/crypto/secp256k1"

	"github.com/ethereum/go-ethereum/common"
)

// flag vars
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
	Account            string
	Proxy              string
	Signature          string
	FeeHandler         bool

	SrcBridge  string
	DestBridge string

	SrcUrl   string
	RelayUrl string
	DestUrl  string

	TxID   string
	Submit bool
)

// processed flag vars
var (
	BridgeAddr         common.Address
	TxHash             common.Hash
	SrcBridgeAddr      common.Address
	DestBridgeAddr     common.Address
	AccountAddr        common.Address
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
