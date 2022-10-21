package signAndSend

import (
	"encoding/json"
	"fmt"
	"github.com/ChainSafe/chainbridge-core/chains/evm/calls"
	"io"
	"math/big"
	"net/http"
	"testing"
)

func Test_PolygonGasStation(t *testing.T) {
	var gp []*big.Int

	resp, err := http.Get(gasStationUrl)
	if err != nil {
		t.Error(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)

	var res gasStation
	err = json.Unmarshal(body, &res)
	if err != nil {
		t.Error(err)
	}
	decimal := new(big.Int).SetUint64(9)

	maxPriorityFee, err := calls.UserAmountToWei(fmt.Sprintf("%f", res.Fast.MaxPriorityFee), decimal)

	if err != nil {
		t.Error(err)
	}
	maxFee, err := calls.UserAmountToWei(fmt.Sprintf("%f", res.Fast.MaxFee), decimal)
	if err != nil {
		t.Error(err)
	}

	gp = append(gp, maxPriorityFee)
	gp = append(gp, maxFee)

	fmt.Printf("gp: %v \n", gp)
}
