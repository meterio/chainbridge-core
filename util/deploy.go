package util

import (
	"errors"

	"github.com/ethereum/go-ethereum/common"
)

var ZeroAddress = common.HexToAddress("0x0000000000000000000000000000000000000000")

var (
	ErrAlreadyPassed = errors.New("signature >= threshold, proposal already passed")
	ErrAlreadyVoted  = errors.New("already voted on this proposal")
)
