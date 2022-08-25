package util

import (
	"github.com/ChainSafe/chainbridge-core/crypto"
	"github.com/ethereum/go-ethereum/common"
)

var ZeroAddress = common.HexToAddress("0x0000000000000000000000000000000000000000")

const OVERTHRESHOLD = "signature over threshold"

var PathKeypair = make(map[string]crypto.Keypair)
var DomainIdToName = make(map[uint8]string)
