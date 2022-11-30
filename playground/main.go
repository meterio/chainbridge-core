package main

import (
	"fmt"
	"github.com/meterio/chainbridge-core/util"
	"time"
)

func main() {
	// init errCounterArr
	errCounterArr := [5]int64{11, 22, 33, 44, 55}
	_ = util.DomainIdMappingErrCounter[1] // mock value
	domainId := uint8(1)
	//errCounterArr = util.DomainIdMappingErrCounter[domainId]

	timeNow := time.Now().Unix()

	errCounterSlice := append(errCounterArr[1:], timeNow)

	var newErrCounterArr [5]int64

	copy(newErrCounterArr[:], errCounterSlice[:])

	util.DomainIdMappingErrCounter[domainId] = newErrCounterArr

	fiveMinutesAgo := timeNow - 5*60
	if newErrCounterArr[0] >= fiveMinutesAgo {
		fmt.Println(errCounterArr, ">=", newErrCounterArr)
		//evmClient := util.DomainIdMappingEVMClient[domainId]
		//evmClient.UpdateEndpoint()
	}
	fmt.Println(errCounterArr, "<", newErrCounterArr)
}
