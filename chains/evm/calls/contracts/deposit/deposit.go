package deposit

import (
	"github.com/ethereum/go-ethereum/common/math"
	"math/big"
)

func ConstructErc20DepositData(destRecipient []byte, amount *big.Int) []byte {
	var data []byte
	data = append(data, math.PaddedBigBytes(amount, 32)...)                                // 32: amount
	data = append(data, math.PaddedBigBytes(big.NewInt(int64(len(destRecipient))), 32)...) // 32: Length of recipient
	data = append(data, destRecipient...)                                                  // 20: Recipient
	return data
}

func ConstructErc721DepositData(destRecipient []byte, tokenId *big.Int, metadata []byte) []byte {
	var data []byte
	data = append(data, math.PaddedBigBytes(tokenId, 32)...)                               // 32: Token Id
	data = append(data, math.PaddedBigBytes(big.NewInt(int64(len(destRecipient))), 32)...) // 32: Length of recipient
	data = append(data, destRecipient...)                                                  // 20: Recipient
	data = append(data, math.PaddedBigBytes(big.NewInt(int64(len(metadata))), 32)...)      // 32: Length of metadata
	data = append(data, metadata...)                                                       // ?: Metadata
	return data
}

func ConstructGenericDepositData(metadata []byte) []byte {
	var data []byte
	data = append(data, math.PaddedBigBytes(big.NewInt(int64(len(metadata))), 32)...) // 32: Length of metadata
	data = append(data, metadata...)                                                  // ?: Metadata
	return data
}
