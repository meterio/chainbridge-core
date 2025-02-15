package erc721

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/meterio/chainbridge-core/crypto/secp256k1"
	"github.com/meterio/chainbridge-core/types"
)

// flag vars
var (
	Erc721Address  string
	Dst            string
	Token          string
	Metadata       string
	Recipient      string
	Bridge         string
	DestionationID string
	ResourceID     string
	Minter         string
)

// processed flag vars
var (
	Erc721Addr    common.Address
	DstAddress    common.Address
	TokenId       *big.Int
	RecipientAddr common.Address
	BridgeAddr    common.Address
	DestinationID int
	ResourceId    types.ResourceID
	MinterAddr    common.Address
)

// global flags
var (
	url           string
	gasLimit      uint64
	gasPrice      *big.Int
	senderKeyPair *secp256k1.Keypair
	prepare       bool
	err           error
)
