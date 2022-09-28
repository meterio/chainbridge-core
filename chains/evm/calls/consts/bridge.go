package consts

const BridgeABI = `[
    {
      "inputs": [
        {
          "internalType": "uint8",
          "name": "domainID",
          "type": "uint8"
        },
        {
          "internalType": "address[]",
          "name": "initialRelayers",
          "type": "address[]"
        },
        {
          "internalType": "uint256",
          "name": "initialRelayerThreshold",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "expiry",
          "type": "uint256"
        }
      ],
      "stateMutability": "nonpayable",
      "type": "constructor"
    },
    {
      "inputs": [
        {
          "internalType": "uint256",
          "name": "msgValue",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "fee",
          "type": "uint256"
        }
      ],
      "name": "IncorrectFeeSupplied",
      "type": "error"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "signer",
          "type": "address"
        },
        {
          "internalType": "uint256",
          "name": "index",
          "type": "uint256"
        }
      ],
      "name": "InvalidSignature",
      "type": "error"
    },
    {
      "inputs": [],
      "name": "ResourceIDNotMappedToHandler",
      "type": "error"
    },
    {
      "anonymous": false,
      "inputs": [
        {
          "indexed": false,
          "internalType": "uint8",
          "name": "destinationDomainID",
          "type": "uint8"
        },
        {
          "indexed": false,
          "internalType": "bytes32",
          "name": "resourceID",
          "type": "bytes32"
        },
        {
          "indexed": false,
          "internalType": "uint64",
          "name": "depositNonce",
          "type": "uint64"
        },
        {
          "indexed": true,
          "internalType": "address",
          "name": "user",
          "type": "address"
        },
        {
          "indexed": false,
          "internalType": "bytes",
          "name": "data",
          "type": "bytes"
        },
        {
          "indexed": false,
          "internalType": "bytes",
          "name": "handlerResponse",
          "type": "bytes"
        }
      ],
      "name": "Deposit",
      "type": "event"
    },
    {
      "anonymous": false,
      "inputs": [
        {
          "indexed": false,
          "internalType": "bytes",
          "name": "lowLevelData",
          "type": "bytes"
        }
      ],
      "name": "FailedHandlerExecution",
      "type": "event"
    },
    {
      "anonymous": false,
      "inputs": [
        {
          "indexed": false,
          "internalType": "uint256",
          "name": "newFee",
          "type": "uint256"
        }
      ],
      "name": "FeeChanged",
      "type": "event"
    },
    {
      "anonymous": false,
      "inputs": [
        {
          "indexed": false,
          "internalType": "address",
          "name": "tokenAddress",
          "type": "address"
        },
        {
          "indexed": false,
          "internalType": "address",
          "name": "recipient",
          "type": "address"
        },
        {
          "indexed": false,
          "internalType": "uint256",
          "name": "amount",
          "type": "uint256"
        }
      ],
      "name": "FeeDistributed",
      "type": "event"
    },
    {
      "anonymous": false,
      "inputs": [
        {
          "indexed": false,
          "internalType": "address",
          "name": "newFeeHandler",
          "type": "address"
        }
      ],
      "name": "FeeHandlerChanged",
      "type": "event"
    },
    {
      "anonymous": false,
      "inputs": [
        {
          "indexed": false,
          "internalType": "address",
          "name": "account",
          "type": "address"
        }
      ],
      "name": "Paused",
      "type": "event"
    },
    {
      "anonymous": false,
      "inputs": [
        {
          "indexed": false,
          "internalType": "uint8",
          "name": "originDomainID",
          "type": "uint8"
        },
        {
          "indexed": false,
          "internalType": "uint64",
          "name": "depositNonce",
          "type": "uint64"
        },
        {
          "indexed": false,
          "internalType": "enum IBridge.ProposalStatus",
          "name": "status",
          "type": "uint8"
        },
        {
          "indexed": false,
          "internalType": "bytes32",
          "name": "dataHash",
          "type": "bytes32"
        }
      ],
      "name": "ProposalEvent",
      "type": "event"
    },
    {
      "anonymous": false,
      "inputs": [
        {
          "indexed": false,
          "internalType": "uint8",
          "name": "originDomainID",
          "type": "uint8"
        },
        {
          "indexed": false,
          "internalType": "uint64",
          "name": "depositNonce",
          "type": "uint64"
        },
        {
          "indexed": false,
          "internalType": "enum IBridge.ProposalStatus",
          "name": "status",
          "type": "uint8"
        },
        {
          "indexed": false,
          "internalType": "bytes32",
          "name": "dataHash",
          "type": "bytes32"
        }
      ],
      "name": "ProposalVote",
      "type": "event"
    },
    {
      "anonymous": false,
      "inputs": [
        {
          "indexed": false,
          "internalType": "address",
          "name": "relayer",
          "type": "address"
        }
      ],
      "name": "RelayerAdded",
      "type": "event"
    },
    {
      "anonymous": false,
      "inputs": [
        {
          "indexed": false,
          "internalType": "address",
          "name": "relayer",
          "type": "address"
        }
      ],
      "name": "RelayerRemoved",
      "type": "event"
    },
    {
      "anonymous": false,
      "inputs": [
        {
          "indexed": false,
          "internalType": "uint256",
          "name": "newThreshold",
          "type": "uint256"
        }
      ],
      "name": "RelayerThresholdChanged",
      "type": "event"
    },
    {
      "anonymous": false,
      "inputs": [
        {
          "indexed": true,
          "internalType": "bytes32",
          "name": "role",
          "type": "bytes32"
        },
        {
          "indexed": true,
          "internalType": "address",
          "name": "account",
          "type": "address"
        },
        {
          "indexed": true,
          "internalType": "address",
          "name": "sender",
          "type": "address"
        }
      ],
      "name": "RoleGranted",
      "type": "event"
    },
    {
      "anonymous": false,
      "inputs": [
        {
          "indexed": true,
          "internalType": "bytes32",
          "name": "role",
          "type": "bytes32"
        },
        {
          "indexed": true,
          "internalType": "address",
          "name": "account",
          "type": "address"
        },
        {
          "indexed": true,
          "internalType": "address",
          "name": "sender",
          "type": "address"
        }
      ],
      "name": "RoleRevoked",
      "type": "event"
    },
    {
      "anonymous": false,
      "inputs": [
        {
          "indexed": false,
          "internalType": "address",
          "name": "account",
          "type": "address"
        }
      ],
      "name": "Unpaused",
      "type": "event"
    },
    {
      "inputs": [],
      "name": "DEFAULT_ADMIN_ROLE",
      "outputs": [
        {
          "internalType": "bytes32",
          "name": "",
          "type": "bytes32"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "MAX_RELAYERS",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "PERMIT_TYPEHASH",
      "outputs": [
        {
          "internalType": "bytes32",
          "name": "",
          "type": "bytes32"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "RELAYER_ROLE",
      "outputs": [
        {
          "internalType": "bytes32",
          "name": "",
          "type": "bytes32"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "_chainId",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint8",
          "name": "",
          "type": "uint8"
        }
      ],
      "name": "_depositCounts",
      "outputs": [
        {
          "internalType": "uint64",
          "name": "",
          "type": "uint64"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "_domainID",
      "outputs": [
        {
          "internalType": "uint8",
          "name": "",
          "type": "uint8"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "_expiry",
      "outputs": [
        {
          "internalType": "uint40",
          "name": "",
          "type": "uint40"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "_fee",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "_feeHandler",
      "outputs": [
        {
          "internalType": "contract IFeeHandler",
          "name": "",
          "type": "address"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "_feeReserve",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "_fee_",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint72",
          "name": "destNonce",
          "type": "uint72"
        },
        {
          "internalType": "bytes32",
          "name": "dataHash",
          "type": "bytes32"
        },
        {
          "internalType": "address",
          "name": "relayer",
          "type": "address"
        }
      ],
      "name": "_hasVotedOnProposal",
      "outputs": [
        {
          "internalType": "bool",
          "name": "",
          "type": "bool"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "_relayerThreshold",
      "outputs": [
        {
          "internalType": "uint8",
          "name": "",
          "type": "uint8"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "bytes32",
          "name": "",
          "type": "bytes32"
        }
      ],
      "name": "_resourceIDToHandlerAddress",
      "outputs": [
        {
          "internalType": "address",
          "name": "",
          "type": "address"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "_totalRelayers",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "relayerAddress",
          "type": "address"
        }
      ],
      "name": "adminAddRelayer",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint256",
          "name": "expiry",
          "type": "uint256"
        }
      ],
      "name": "adminChangeExpiry",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint256",
          "name": "newThreshold",
          "type": "uint256"
        }
      ],
      "name": "adminChangeRelayerThreshold",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "adminPauseTransfers",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "bytes32",
          "name": "resourceID",
          "type": "bytes32"
        },
        {
          "internalType": "address",
          "name": "contractAddress",
          "type": "address"
        }
      ],
      "name": "adminRemoveGenericResource",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "relayerAddress",
          "type": "address"
        }
      ],
      "name": "adminRemoveRelayer",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "bytes32",
          "name": "resourceID",
          "type": "bytes32"
        },
        {
          "internalType": "address",
          "name": "tokenAddress",
          "type": "address"
        },
        {
          "internalType": "bool",
          "name": "isNative",
          "type": "bool"
        }
      ],
      "name": "adminRemoveResourceId",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint8",
          "name": "destinationDomainID",
          "type": "uint8"
        }
      ],
      "name": "adminRemoveSpecialFee",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "handlerAddress",
          "type": "address"
        },
        {
          "internalType": "address",
          "name": "tokenAddress",
          "type": "address"
        }
      ],
      "name": "adminSetBurnable",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint8",
          "name": "domainID",
          "type": "uint8"
        },
        {
          "internalType": "uint64",
          "name": "nonce",
          "type": "uint64"
        }
      ],
      "name": "adminSetDepositNonce",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint8",
          "name": "domainID",
          "type": "uint8"
        }
      ],
      "name": "adminSetDomainId",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint256",
          "name": "newFee",
          "type": "uint256"
        }
      ],
      "name": "adminSetFee",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "forwarder",
          "type": "address"
        },
        {
          "internalType": "bool",
          "name": "valid",
          "type": "bool"
        }
      ],
      "name": "adminSetForwarder",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "handlerAddress",
          "type": "address"
        },
        {
          "internalType": "bytes32",
          "name": "resourceID",
          "type": "bytes32"
        },
        {
          "internalType": "address",
          "name": "contractAddress",
          "type": "address"
        },
        {
          "internalType": "bytes4",
          "name": "depositFunctionSig",
          "type": "bytes4"
        },
        {
          "internalType": "uint256",
          "name": "depositFunctionDepositorOffset",
          "type": "uint256"
        },
        {
          "internalType": "bytes4",
          "name": "executeFunctionSig",
          "type": "bytes4"
        }
      ],
      "name": "adminSetGenericResource",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "handlerAddress",
          "type": "address"
        },
        {
          "internalType": "bytes32",
          "name": "resourceID",
          "type": "bytes32"
        },
        {
          "internalType": "address",
          "name": "tokenAddress",
          "type": "address"
        },
        {
          "internalType": "bool",
          "name": "isNative",
          "type": "bool"
        }
      ],
      "name": "adminSetResource",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint8",
          "name": "destinationDomainID",
          "type": "uint8"
        },
        {
          "internalType": "uint256",
          "name": "_specialFee",
          "type": "uint256"
        }
      ],
      "name": "adminSetSpecialFee",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "adminUnpauseTransfers",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "handlerAddress",
          "type": "address"
        },
        {
          "internalType": "bytes",
          "name": "data",
          "type": "bytes"
        }
      ],
      "name": "adminWithdraw",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "handlerAddress",
          "type": "address"
        },
        {
          "internalType": "bytes",
          "name": "data",
          "type": "bytes"
        }
      ],
      "name": "adminWithdrawETH",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint8",
          "name": "domainID",
          "type": "uint8"
        },
        {
          "internalType": "uint64",
          "name": "depositNonce",
          "type": "uint64"
        },
        {
          "internalType": "bytes32",
          "name": "dataHash",
          "type": "bytes32"
        }
      ],
      "name": "cancelProposal",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint8",
          "name": "domainID",
          "type": "uint8"
        },
        {
          "internalType": "uint64",
          "name": "depositNonce",
          "type": "uint64"
        },
        {
          "internalType": "bytes32",
          "name": "resourceID",
          "type": "bytes32"
        },
        {
          "internalType": "bytes",
          "name": "data",
          "type": "bytes"
        },
        {
          "internalType": "bytes",
          "name": "signature",
          "type": "bytes"
        }
      ],
      "name": "checkSignature",
      "outputs": [
        {
          "internalType": "bool",
          "name": "",
          "type": "bool"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint8",
          "name": "destinationDomainID",
          "type": "uint8"
        },
        {
          "internalType": "bytes32",
          "name": "resourceID",
          "type": "bytes32"
        },
        {
          "internalType": "bytes",
          "name": "depositData",
          "type": "bytes"
        },
        {
          "internalType": "bytes",
          "name": "feeData",
          "type": "bytes"
        }
      ],
      "name": "deposit",
      "outputs": [],
      "stateMutability": "payable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint8",
          "name": "domainID",
          "type": "uint8"
        },
        {
          "internalType": "uint64",
          "name": "depositNonce",
          "type": "uint64"
        },
        {
          "internalType": "bytes",
          "name": "data",
          "type": "bytes"
        },
        {
          "internalType": "bytes32",
          "name": "resourceID",
          "type": "bytes32"
        },
        {
          "internalType": "bool",
          "name": "revertOnFail",
          "type": "bool"
        }
      ],
      "name": "executeProposal",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint8",
          "name": "destinationDomainID",
          "type": "uint8"
        }
      ],
      "name": "getFee",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint8",
          "name": "originDomainID",
          "type": "uint8"
        },
        {
          "internalType": "uint64",
          "name": "depositNonce",
          "type": "uint64"
        },
        {
          "internalType": "bytes32",
          "name": "resourceID",
          "type": "bytes32"
        },
        {
          "internalType": "bytes",
          "name": "data",
          "type": "bytes"
        }
      ],
      "name": "getProposal",
      "outputs": [
        {
          "components": [
            {
              "internalType": "enum IBridge.ProposalStatus",
              "name": "_status",
              "type": "uint8"
            },
            {
              "internalType": "uint200",
              "name": "_yesVotes",
              "type": "uint200"
            },
            {
              "internalType": "uint8",
              "name": "_yesVotesTotal",
              "type": "uint8"
            },
            {
              "internalType": "uint40",
              "name": "_proposedBlock",
              "type": "uint40"
            }
          ],
          "internalType": "struct IBridge.Proposal",
          "name": "",
          "type": "tuple"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "bytes32",
          "name": "role",
          "type": "bytes32"
        }
      ],
      "name": "getRoleAdmin",
      "outputs": [
        {
          "internalType": "bytes32",
          "name": "",
          "type": "bytes32"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "bytes32",
          "name": "role",
          "type": "bytes32"
        },
        {
          "internalType": "uint256",
          "name": "index",
          "type": "uint256"
        }
      ],
      "name": "getRoleMember",
      "outputs": [
        {
          "internalType": "address",
          "name": "",
          "type": "address"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "bytes32",
          "name": "role",
          "type": "bytes32"
        }
      ],
      "name": "getRoleMemberCount",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "bytes32",
          "name": "role",
          "type": "bytes32"
        },
        {
          "internalType": "address",
          "name": "account",
          "type": "address"
        }
      ],
      "name": "getRoleMemberIndex",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "bytes32",
          "name": "role",
          "type": "bytes32"
        },
        {
          "internalType": "address",
          "name": "account",
          "type": "address"
        }
      ],
      "name": "grantRole",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "bytes32",
          "name": "role",
          "type": "bytes32"
        },
        {
          "internalType": "address",
          "name": "account",
          "type": "address"
        }
      ],
      "name": "hasRole",
      "outputs": [
        {
          "internalType": "bool",
          "name": "",
          "type": "bool"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "relayer",
          "type": "address"
        }
      ],
      "name": "isRelayer",
      "outputs": [
        {
          "internalType": "bool",
          "name": "",
          "type": "bool"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "",
          "type": "address"
        }
      ],
      "name": "isValidForwarder",
      "outputs": [
        {
          "internalType": "bool",
          "name": "",
          "type": "bool"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "paused",
      "outputs": [
        {
          "internalType": "bool",
          "name": "",
          "type": "bool"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "newAdmin",
          "type": "address"
        }
      ],
      "name": "renounceAdmin",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "bytes32",
          "name": "role",
          "type": "bytes32"
        },
        {
          "internalType": "address",
          "name": "account",
          "type": "address"
        }
      ],
      "name": "renounceRole",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "bytes32",
          "name": "role",
          "type": "bytes32"
        },
        {
          "internalType": "address",
          "name": "account",
          "type": "address"
        }
      ],
      "name": "revokeRole",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint8",
          "name": "",
          "type": "uint8"
        }
      ],
      "name": "special",
      "outputs": [
        {
          "internalType": "bool",
          "name": "",
          "type": "bool"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint8",
          "name": "",
          "type": "uint8"
        }
      ],
      "name": "specialFee",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "address payable[]",
          "name": "addrs",
          "type": "address[]"
        },
        {
          "internalType": "uint256[]",
          "name": "amounts",
          "type": "uint256[]"
        }
      ],
      "name": "transferFee",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint8",
          "name": "domainID",
          "type": "uint8"
        },
        {
          "internalType": "uint64",
          "name": "depositNonce",
          "type": "uint64"
        },
        {
          "internalType": "bytes32",
          "name": "resourceID",
          "type": "bytes32"
        },
        {
          "internalType": "bytes",
          "name": "data",
          "type": "bytes"
        }
      ],
      "name": "voteProposal",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint8",
          "name": "domainID",
          "type": "uint8"
        },
        {
          "internalType": "uint64",
          "name": "depositNonce",
          "type": "uint64"
        },
        {
          "internalType": "bytes32",
          "name": "resourceID",
          "type": "bytes32"
        },
        {
          "internalType": "bytes",
          "name": "data",
          "type": "bytes"
        },
        {
          "internalType": "bytes[]",
          "name": "signatures",
          "type": "bytes[]"
        }
      ],
      "name": "voteProposals",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    }
  ]`
const BridgeBin = "0x6101406040523480156200001257600080fd5b5060405162004bac38038062004bac83398101604081905262000035916200053b565b604080518082018252600c81526b5065726d697442726964676560a01b6020808301918252835180850190945260038452620312e360ec1b908401528151902060e08190527fe6bbd6277e1bf288eed5e8d1780f9a50b239e86b153736bceebccf4ea79d90b36101008190524660a0529192917f8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f620001198184846040805160208101859052908101839052606081018290524660808201523060a082015260009060c0016040516020818303038152906040528051906020012090509392505050565b6080523060c0526101205250506000805460ff199081169091556002805490911660ff8816179055506200015b90508262000241602090811b62002c1a17901c565b600260016101000a81548160ff021916908360ff1602179055506200018b816200029e60201b62002c711760201c565b6002805464ffffffffff92909216620100000266ffffffffff000019909216919091179055620001c66000620001c0620002f7565b6200033a565b60005b83518110156200023657620002217fe2b7fb3b832174769106daebcfd6d1970523240dda11281102db9363b83b0dc48583815181106200020d576200020d62000639565b60200260200101516200034a60201b60201c565b806200022d816200064f565b915050620001c9565b505050505062000679565b600061010082106200029a5760405162461bcd60e51b815260206004820152601c60248201527f76616c756520646f6573206e6f742066697420696e203820626974730000000060448201526064015b60405180910390fd5b5090565b60006501000000000082106200029a5760405162461bcd60e51b815260206004820152601d60248201527f76616c756520646f6573206e6f742066697420696e2034302062697473000000604482015260640162000291565b600033601436108015906200032457506001600160a01b03811660009081526005602052604090205460ff165b1562000335575060131936013560601c5b919050565b620003468282620003d7565b5050565b60008281526001602052604090206002015462000371906200036b620002f7565b62000452565b6200033a5760405162461bcd60e51b815260206004820152602f60248201527f416363657373436f6e74726f6c3a2073656e646572206d75737420626520616e60448201526e0818591b5a5b881d1bc819dc985b9d608a1b606482015260840162000291565b6000828152600160209081526040909120620003fe91839062002cc862000481821b17901c565b1562000346576200040e620002f7565b6001600160a01b0316816001600160a01b0316837f2f8788117e7eff1d82e926ec794901d17c78024a50270940304540a733656f0d60405160405180910390a45050565b600082815260016020908152604082206200047891849062002cdd62000498821b17901c565b90505b92915050565b600062000478836001600160a01b038416620004bb565b6001600160a01b0381166000908152600183016020526040812054151562000478565b600081815260018301602052604081205462000504575081546001818101845560008481526020808220909301849055845484825282860190935260409020919091556200047b565b5060006200047b565b634e487b7160e01b600052604160045260246000fd5b80516001600160a01b03811681146200033557600080fd5b600080600080608085870312156200055257600080fd5b845160ff811681146200056457600080fd5b602086810151919550906001600160401b03808211156200058457600080fd5b818801915088601f8301126200059957600080fd5b815181811115620005ae57620005ae6200050d565b8060051b604051601f19603f83011681018181108582111715620005d657620005d66200050d565b60405291825284820192508381018501918b831115620005f557600080fd5b938501935b828510156200061e576200060e8562000523565b84529385019392850192620005fa565b60408b01516060909b0151999c909b50975050505050505050565b634e487b7160e01b600052603260045260246000fd5b60006000198214156200067257634e487b7160e01b600052601160045260246000fd5b5060010190565b60805160a05160c05160e05161010051610120516144e3620006c960003960006132cc0152600061331b015260006132f60152600061324f01526000613279015260006132a301526144e36000f3fe6080604052600436106102e45760003560e01c80638c0c263111610190578063c5ec8970116100dc578063d7a9cd7911610095578063f8c39e441161006f578063f8c39e4414610949578063fe4648f414610979578063fe65c4be146109a0578063ffaac0eb146109c057600080fd5b8063d7a9cd79146108ea578063e2469d4014610909578063edc20c3c1461092957600080fd5b8063c5ec897014610810578063ca15c8731461084a578063cb10f2151461086a578063cdb0f73a1461088a578063d15ef64e146108aa578063d547741f146108ca57600080fd5b80639dd694f411610149578063a9cf69fa11610123578063a9cf69fa1461078e578063bd2a1820146107bb578063c0331b3e146107db578063c5b37c22146107fb57600080fd5b80639dd694f4146107385780639debb3bd14610764578063a217fddf1461077957600080fd5b80638c0c2631146106765780639010d07c1461069657806391d14854146106b6578063926d7d7f146106d65780639d4d39f5146106f85780639d82dd631461071857600080fd5b80635a1ad87c1161024f5780637477341211610208578063802aabe8116101e2578063802aabe8146105de57806380ae1c28146105f357806384db809f146106085780638b63aebf1461065657600080fd5b8063747734121461058b5780637d026d961461059e5780637febe63f146105be57600080fd5b80635a1ad87c146104e05780635c975abb146105005780635e1fab0f146105185780636d3b6eea146105385780637292dd911461055857806373c45c981461057857600080fd5b806336568abe116102a157806336568abe146103e25780634603ae38146104025780634b0b919d146104225780634e056005146104705780634e0df3f614610490578063541d5548146104b057600080fd5b806317f03ce5146102e9578063206a98fd1461030b578063231de0201461032b578063248a9ca31461034b5780632f2ff15d1461038e57806330adf81f146103ae575b600080fd5b3480156102f557600080fd5b50610309610304366004613848565b6109d5565b005b34801561031757600080fd5b506103096103263660046138d5565b610c6a565b34801561033757600080fd5b50610309610346366004613966565b610ef0565b34801561035757600080fd5b5061037b6103663660046139a4565b60009081526001602052604090206002015490565b6040519081526020015b60405180910390f35b34801561039a57600080fd5b506103096103a93660046139bd565b610f78565b3480156103ba57600080fd5b5061037b7fc4cb5d35714699d6e85b9562b644e60393b418d974a5c1dd8efaadac37a142c581565b3480156103ee57600080fd5b506103096103fd3660046139bd565b611008565b34801561040e57600080fd5b5061030961041d366004613a31565b611092565b34801561042e57600080fd5b5061045861043d366004613a9c565b6003602052600090815260409020546001600160401b031681565b6040516001600160401b039091168152602001610385565b34801561047c57600080fd5b5061030961048b3660046139a4565b611136565b34801561049c57600080fd5b5061037b6104ab3660046139bd565b611199565b3480156104bc57600080fd5b506104d06104cb366004613ab7565b6111c5565b6040519015158152602001610385565b3480156104ec57600080fd5b506103096104fb366004613aec565b6111df565b34801561050c57600080fd5b5060005460ff166104d0565b34801561052457600080fd5b50610309610533366004613ab7565b611295565b34801561054457600080fd5b50610309610553366004613c0d565b611321565b34801561056457600080fd5b50610309610573366004613c5c565b61138e565b610309610586366004613d72565b611aa4565b34801561059757600080fd5b504661037b565b3480156105aa57600080fd5b506103096105b93660046139a4565b611d4d565b3480156105ca57600080fd5b506104d06105d9366004613dfb565b611d82565b3480156105ea57600080fd5b5061037b611e26565b3480156105ff57600080fd5b50610309611e44565b34801561061457600080fd5b5061063e6106233660046139a4565b6004602052600090815260409020546001600160a01b031681565b6040516001600160a01b039091168152602001610385565b34801561066257600080fd5b50610309610671366004613ab7565b611e5e565b34801561068257600080fd5b50610309610691366004613e49565b611ec4565b3480156106a257600080fd5b5061063e6106b1366004613e77565b611efd565b3480156106c257600080fd5b506104d06106d13660046139bd565b611f1c565b3480156106e257600080fd5b5061037b60008051602061448e83398151915281565b34801561070457600080fd5b5061037b610713366004613d72565b611f34565b34801561072457600080fd5b50610309610733366004613ab7565b611ffd565b34801561074457600080fd5b506002546107529060ff1681565b60405160ff9091168152602001610385565b34801561077057600080fd5b5061037b60c881565b34801561078557600080fd5b5061037b600081565b34801561079a57600080fd5b506107ae6107a9366004613848565b6120b2565b6040516103859190613ed1565b3480156107c757600080fd5b506103096107d6366004613c0d565b612180565b3480156107e757600080fd5b506103096107f6366004613f1a565b6121b6565b34801561080757600080fd5b5061037b61268c565b34801561081c57600080fd5b506002546108349062010000900464ffffffffff1681565b60405164ffffffffff9091168152602001610385565b34801561085657600080fd5b5061037b6108653660046139a4565b612724565b34801561087657600080fd5b50610309610885366004613f88565b61273b565b34801561089657600080fd5b506103096108a5366004613ab7565b61279c565b3480156108b657600080fd5b506103096108c5366004613fa8565b6128a2565b3480156108d657600080fd5b506103096108e53660046139bd565b6128d5565b3480156108f657600080fd5b5060025461075290610100900460ff1681565b34801561091557600080fd5b50610309610924366004613ab7565b612958565b34801561093557600080fd5b50610309610944366004613fdd565b612a3f565b34801561095557600080fd5b506104d0610964366004613ab7565b60056020526000908152604090205460ff1681565b34801561098557600080fd5b5060025461063e90600160381b90046001600160a01b031681565b3480156109ac57600080fd5b506104d06109bb366004614007565b612af8565b3480156109cc57600080fd5b50610309612c02565b6109dd612cff565b60ff838116600884901b68ffffffffffffffff0016176000818152600660209081526040808320868452909152808220815160808101909252805493949293919290918391166004811115610a3457610a34613e99565b6004811115610a4557610a45613e99565b8152905461010081046001600160c81b03166020830152600160d01b810460ff166040830152600160d81b900464ffffffffff1660609091015280519091506001816004811115610a9857610a98613e99565b1480610ab557506002816004811115610ab357610ab3613e99565b145b610b065760405162461bcd60e51b815260206004820152601c60248201527f50726f706f73616c2063616e6e6f742062652063616e63656c6c65640000000060448201526064015b60405180910390fd5b600254606083015164ffffffffff62010000909204821691610b2a91439116612d83565b64ffffffffff1611610b7e5760405162461bcd60e51b815260206004820181905260248201527f50726f706f73616c206e6f7420617420657870697279207468726573686f6c646044820152606401610afd565b60048083526001600160481b03841660009081526006602090815260408083208884529091529020835181548593839160ff1916906001908490811115610bc757610bc7613e99565b02179055506020820151815460408085015160609095015164ffffffffff16600160d81b026001600160d81b0360ff909616600160d01b0260ff60d01b196001600160c81b039095166101000294909416610100600160d81b03199093169290921792909217939093169290921790555160008051602061446e83398151915290610c5a908890889060049089906140a1565b60405180910390a1505050505050565b610c72612dc5565b610c7a612e2b565b60008281526004602090815260408083205490516001600160a01b039091169268ffffffffffffffff0060088a901b1660ff8b1617929091610cc29185918a918a91016140d6565b60408051601f1981840301815291815281516020928301206001600160481b03851660009081526006845282812082825290935291209091506002815460ff166004811115610d1357610d13613e99565b14610d605760405162461bcd60e51b815260206004820181905260248201527f50726f706f73616c206d757374206861766520506173736564207374617475736044820152606401610afd565b805460ff19166003178155838515610dd95760405163712467f960e11b81526001600160a01b0382169063e248cff290610da2908a908d908d9060040161412b565b600060405180830381600087803b158015610dbc57600080fd5b505af1158015610dd0573d6000803e3d6000fd5b50505050610eb6565b60405163712467f960e11b81526001600160a01b0382169063e248cff290610e09908a908d908d9060040161412b565b600060405180830381600087803b158015610e2357600080fd5b505af1925050508015610e34575060015b610eb6573d808015610e62576040519150601f19603f3d011682016040523d82523d6000602084013e610e67565b606091505b50825460ff191660021783556040517fbd37c1f0d53bb2f33fe4c2104de272fcdeb4d2fef3acdbf1e4ddc3d6833ca37690610ea39083906141a1565b60405180910390a1505050505050610ee8565b60008051602061446e8339815191528b8b600386604051610eda94939291906140a1565b60405180910390a150505050505b505050505050565b610ef8612e71565b600083815260046020819052604091829020549151632129da1960e01b81526001600160a01b038581169282019290925283151560248201529116908190632129da19906044015b600060405180830381600087803b158015610f5a57600080fd5b505af1158015610f6e573d6000803e3d6000fd5b5050505050505050565b600082815260016020526040902060020154610f96906106d1612eca565b610ffa5760405162461bcd60e51b815260206004820152602f60248201527f416363657373436f6e74726f6c3a2073656e646572206d75737420626520616e60448201526e0818591b5a5b881d1bc819dc985b9d608a1b6064820152608401610afd565b6110048282612f0b565b5050565b611010612eca565b6001600160a01b0316816001600160a01b0316146110885760405162461bcd60e51b815260206004820152602f60248201527f416363657373436f6e74726f6c3a2063616e206f6e6c792072656e6f756e636560448201526e103937b632b9903337b91039b2b63360891b6064820152608401610afd565b6110048282612f74565b61109a612e71565b60005b8381101561112f578484828181106110b7576110b76141b4565b90506020020160208101906110cc9190613ab7565b6001600160a01b03166108fc8484848181106110ea576110ea6141b4565b905060200201359081150290604051600060405180830381858888f1935050505015801561111c573d6000803e3d6000fd5b5080611127816141e0565b91505061109d565b5050505050565b61113e612e71565b61114781612c1a565b6002805460ff929092166101000261ff00199092169190911790556040518181527fa20d6b84cd798a24038be305eff8a45ca82ef54a2aa2082005d8e14c0a4746c8906020015b60405180910390a150565b60008281526001602081815260408084206001600160a01b038616855290920190529020545b92915050565b60006111bf60008051602061448e83398151915283611f1c565b6111e7612e71565b60008581526004602081905260409182902080546001600160a01b0319166001600160a01b038a8116918217909255925163de319d9960e01b8152918201889052861660248201526001600160e01b03198086166044830152606482018590528316608482015287919063de319d999060a401600060405180830381600087803b15801561127457600080fd5b505af1158015611288573d6000803e3d6000fd5b5050505050505050505050565b61129d612e71565b60006112a7612eca565b9050816001600160a01b0316816001600160a01b0316141561130b5760405162461bcd60e51b815260206004820152601760248201527f43616e6e6f742072656e6f756e6365206f6e6573656c660000000000000000006044820152606401610afd565b611316600083610f78565b611004600082611008565b611329612e71565b60405163ab5c7bf160e01b815282906001600160a01b0382169063ab5c7bf1906113579085906004016141a1565b600060405180830381600087803b15801561137157600080fd5b505af1158015611385573d6000803e3d6000fd5b50505050505050565b611396612e2b565b60008481526004602090815260408083205490516001600160a01b039091169268ffffffffffffffff0060088a901b1660ff8b16179290916113de91859189918991016140d6565b60408051601f1981840301815282825280516020918201206001600160481b03861660009081526006835283812082825290925282822060808501909352825490945090929190829060ff16600481111561143b5761143b613e99565b600481111561144c5761144c613e99565b8152905461010081046001600160c81b0316602080840191909152600160d01b820460ff16604080850191909152600160d81b90920464ffffffffff1660609093019290925260008b815260049092529020549091506001600160a01b03166114f35760405162461bcd60e51b81526020600482015260196024820152781b9bc81a185b991b195c88199bdc881c995cdbdd5c98d95251603a1b6044820152606401610afd565b60005b85518110156119325760028251600481111561151457611514613e99565b14156115b0576003825260405163712467f960e11b815285906001600160a01b0382169063e248cff290611550908d908d908d9060040161412b565b600060405180830381600087803b15801561156a57600080fd5b505af115801561157e573d6000803e3d6000fd5b5050505060008051602061446e8339815191528c8c6003876040516115a694939291906140a1565b60405180910390a1505b60007fc4cb5d35714699d6e85b9562b644e60393b418d974a5c1dd8efaadac37a142c58c8c8c8c8c6040516115e69291906141fb565b604051908190038120611629959493929160200194855260ff9390931660208501526001600160401b039190911660408401526060830152608082015260a00190565b604051602081830303815290604052805190602001209050600061164c82612fdd565b90506000611673828a8681518110611666576116666141b4565b602002602001015161302b565b905061168d60008051602061448e83398151915282611f1c565b6116bc5760405163b4d8a3a160e01b81526001600160a01b038216600482015260248101859052604401610afd565b845160019060048111156116d2576116d2613e99565b11156116f05760405162461bcd60e51b8152600401610afd9061420b565b6116fa858261304f565b1561173f5760405162461bcd60e51b81526020600482015260156024820152741c995b185e595c88185b1c9958591e481d9bdd1959605a1b6044820152606401610afd565b60008551600481111561175457611754613e99565b14156117c5576040805160808101909152806001815260200160006001600160c81b03168152602001600060ff1681526020014364ffffffffff16815250945060008051602061446e8339815191528e8e6001896040516117b894939291906140a1565b60405180910390a161182b565b600254606086015164ffffffffff620100009092048216916117e991439116612d83565b64ffffffffff16111561182b57600485818152505060008051602061446e8339815191528e8e60048960405161182294939291906140a1565b60405180910390a15b60048551600481111561184057611840613e99565b1461191c5761186561185182613072565b86602001516001600160c81b0316176130a0565b6001600160c81b03166020860152604085018051906118838261424e565b60ff1660ff16815250507f25f8daaa4635a7729927ba3f5b3d59cc3320aca7c32c9db4e7ca7b95743436408e8e8760000151896040516118c694939291906140a1565b60405180910390a1600254604086015160ff610100909204821691161061191c57600285818152505060008051602061446e8339815191528e8e60028960405161191394939291906140a1565b60405180910390a15b505050808061192a906141e0565b9150506114f6565b5060028151600481111561194857611948613e99565b14156119e4576003815260405163712467f960e11b815284906001600160a01b0382169063e248cff290611984908c908c908c9060040161412b565b600060405180830381600087803b15801561199e57600080fd5b505af11580156119b2573d6000803e3d6000fd5b5050505060008051602061446e8339815191528b8b6003866040516119da94939291906140a1565b60405180910390a1505b6001600160481b038316600090815260066020908152604080832085845290915290208151815483929190829060ff19166001836004811115611a2957611a29613e99565b021790555060208201518154604084015160609094015164ffffffffff16600160d81b026001600160d81b0360ff909516600160d01b0260ff60d01b196001600160c81b039094166101000293909316610100600160d81b031990921691909117919091179290921691909117905550505050505050505050565b611aac612e2b565b6000611ab6612eca565b6002549091503490600160381b90046001600160a01b031615611bee5760025460405163ef4f081f60e01b81526000916001600160a01b03600160381b8204169163ef4f081f91611b1b91879160ff16908e908e908e908e908e908e9060040161426e565b6040805180830381865afa158015611b37573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190611b5b91906142bb565b5090508015611bec57600254604051632530706560e01b81526001600160a01b03600160381b830416916325307065918491611bab91889160ff16908f908f908f908f908f908f9060040161426e565b6000604051808303818588803b158015611bc457600080fd5b505af1158015611bd8573d6000803e3d6000fd5b50505050508082611be991906142e0565b91505b505b6000878152600460205260409020546001600160a01b031680611c24576040516308c231dd60e31b815260040160405180910390fd5b60ff8916600090815260036020526040812080548290611c4c906001600160401b03166142f7565b91906101000a8154816001600160401b0302191690836001600160401b031602179055905060008290506000816001600160a01b031663b07e54bb868d898e8e6040518663ffffffff1660e01b8152600401611cab949392919061431e565b60006040518083038185885af1158015611cc9573d6000803e3d6000fd5b50505050506040513d6000823e601f3d908101601f19168201604052611cf29190810190614349565b9050856001600160a01b03167f17bc3181e17a9620a479c24e6c606e474ba84fc036877b768926872e8cd0e11f8d8d868e8e87604051611d37969594939291906143b6565b60405180910390a2505050505050505050505050565b611d55612e71565b611d5e81612c71565b6002806101000a81548164ffffffffff021916908364ffffffffff16021790555050565b6001600160481b03831660009081526006602090815260408083208584529091528082208151608081019092528054611e1e929190829060ff166004811115611dcd57611dcd613e99565b6004811115611dde57611dde613e99565b8152905461010081046001600160c81b03166020830152600160d01b810460ff166040830152600160d81b900464ffffffffff166060909101528361304f565b949350505050565b6000611e3f60008051602061448e833981519152612724565b905090565b611e4c612e71565b611e5c611e57612eca565b6130f5565b565b611e66612e71565b60028054670100000000000000600160d81b031916600160381b6001600160a01b038416908102919091179091556040519081527f729170bd142e4965055b26a285faeedf03baf2b915bfc5a7c75d24b45815ff2c9060200161118e565b611ecc612e71565b6040516307b7ed9960e01b81526001600160a01b0382811660048301528391908216906307b7ed9990602401611357565b6000828152600160205260408120611f159083613143565b9392505050565b6000828152600160205260408120611f159083612cdd565b600080611f3f612eca565b600254909150600160381b90046001600160a01b031615611fed5760025460405163ef4f081f60e01b81526000916001600160a01b03600160381b8204169163ef4f081f91611fa291869160ff16908e908e908e908e908e908e9060040161426e565b6040805180830381865afa158015611fbe573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190611fe291906142bb565b509250611ff3915050565b60009150505b9695505050505050565b61201560008051602061448e83398151915282611f1c565b6120615760405162461bcd60e51b815260206004820152601f60248201527f6164647220646f65736e277420686176652072656c6179657220726f6c6521006044820152606401610afd565b61207960008051602061448e833981519152826128d5565b6040516001600160a01b03821681527f10e1f7ce9fd7d1b90a66d13a2ab3cb8dd7f29f3f8d520b143b063ccfbab6906b9060200161118e565b60408051608081018252600080825260208201819052918101829052606081019190915260ff848116600885901b68ffffffffffffffff0016176000818152600660209081526040808320878452909152908190208151608081019092528054929391929091839116600481111561212c5761212c613e99565b600481111561213d5761213d613e99565b8152905461010081046001600160c81b03166020830152600160d01b810460ff166040830152600160d81b900464ffffffffff1660609091015295945050505050565b612188612e71565b60405163025a3c9960e21b815282906001600160a01b03821690630968f264906113579085906004016141a1565b6121be612dc5565b6121c6612e2b565b60008381526004602090815260408083205490516001600160a01b039091169268ffffffffffffffff00600889901b1660ff8a161792909161220e91859188918891016140d6565b60408051601f1981840301815282825280516020918201206001600160481b03861660009081526006835283812082825290925282822060808501909352825490945090929190829060ff16600481111561226b5761226b613e99565b600481111561227c5761227c613e99565b8152905461010081046001600160c81b0316602080840191909152600160d01b820460ff16604080850191909152600160d81b90920464ffffffffff1660609093019290925260008a815260049092529020549091506001600160a01b03166123235760405162461bcd60e51b81526020600482015260196024820152781b9bc81a185b991b195c88199bdc881c995cdbdd5c98d95251603a1b6044820152606401610afd565b60028151600481111561233857612338613e99565b14156123565761234d898988888b6001610c6a565b5050505061112f565b6000612360612eca565b905060018260000151600481111561237a5761237a613e99565b11156123985760405162461bcd60e51b8152600401610afd9061420b565b6123a2828261304f565b156123e75760405162461bcd60e51b81526020600482015260156024820152741c995b185e595c88185b1c9958591e481d9bdd1959605a1b6044820152606401610afd565b6000825160048111156123fc576123fc613e99565b141561245c576040805160808101825260018082526000602083018190528284015264ffffffffff43166060830152915190935060008051602061446e8339815191529161244f918d918d9188906140a1565b60405180910390a16124bd565b600254606083015164ffffffffff6201000090920482169161248091439116612d83565b64ffffffffff1611156124bd57600480835260405160008051602061446e833981519152916124b4918d918d9188906140a1565b60405180910390a15b6004825160048111156124d2576124d2613e99565b146125a2576124f76124e382613072565b83602001516001600160c81b0316176130a0565b6001600160c81b03166020830152604082018051906125158261424e565b60ff1690525081516040517f25f8daaa4635a7729927ba3f5b3d59cc3320aca7c32c9db4e7ca7b957434364091612551918d918d9188906140a1565b60405180910390a1600254604083015160ff61010090920482169116106125a257600280835260405160008051602061446e83398151915291612599918d918d9188906140a1565b60405180910390a15b6001600160481b038416600090815260066020908152604080832086845290915290208251815484929190829060ff191660018360048111156125e7576125e7613e99565b021790555060208201518154604084015160609094015164ffffffffff16600160d81b026001600160d81b0360ff909516600160d01b0260ff60d01b196001600160c81b039094166101000293909316610100600160d81b031990921691909117919091179290921691909117905560028251600481111561266b5761266b613e99565b1415612680576126808a8a89898c6000610c6a565b50505050505050505050565b600254600090600160381b90046001600160a01b03161561271e57600260079054906101000a90046001600160a01b03166001600160a01b031663c5b37c226040518163ffffffff1660e01b8152600401602060405180830381865afa1580156126fa573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190611e3f9190614407565b50600090565b60008181526001602052604081206111bf9061314f565b612743612e71565b60008281526004602081905260409182902080546001600160a01b0319166001600160a01b038781169182179092559251635c7d1b9b60e11b81529182018590528316602482015284919063b8fa373690604401610f40565b6127b460008051602061448e83398151915282611f1c565b156128015760405162461bcd60e51b815260206004820152601e60248201527f6164647220616c7265616479206861732072656c6179657220726f6c652100006044820152606401610afd565b60c861280b611e26565b106128515760405162461bcd60e51b81526020600482015260166024820152751c995b185e595c9cc81b1a5b5a5d081c995858da195960521b6044820152606401610afd565b61286960008051602061448e83398151915282610f78565b6040516001600160a01b03821681527f03580ee9f53a62b7cb409a2cb56f9be87747dd15017afc5cef6eef321e4fb2c59060200161118e565b6128aa612e71565b6001600160a01b03919091166000908152600560205260409020805460ff1916911515919091179055565b6000828152600160205260409020600201546128f3906106d1612eca565b6110885760405162461bcd60e51b815260206004820152603060248201527f416363657373436f6e74726f6c3a2073656e646572206d75737420626520616e60448201526f2061646d696e20746f207265766f6b6560801b6064820152608401610afd565b612960612e71565b60025460019060009060ff1661297883610100614420565b612982919061443f565b60008181526004602081905260409182902080546001600160a01b0319166001600160a01b038881169182179092559251635c7d1b9b60e11b815291820184905285166024820152919250849163b8fa373690604401600060405180830381600087803b1580156129f257600080fd5b505af1158015612a06573d6000803e3d6000fd5b5050604051632129da1960e01b81526001600160a01b0386811660048301526001602483015284169250632129da199150604401610f40565b612a47612e71565b60ff82166000908152600360205260409020546001600160401b0390811690821611612ac45760405162461bcd60e51b815260206004820152602660248201527f446f6573206e6f7420616c6c6f772064656372656d656e7473206f6620746865604482015265206e6f6e636560d01b6064820152608401610afd565b60ff919091166000908152600360205260409020805467ffffffffffffffff19166001600160401b03909216919091179055565b6000807fc4cb5d35714699d6e85b9562b644e60393b418d974a5c1dd8efaadac37a142c58989898989604051612b2f9291906141fb565b604051908190038120612b72959493929160200194855260ff9390931660208501526001600160401b039190911660408401526060830152608082015260a00190565b6040516020818303038152906040528051906020012090506000612b9582612fdd565b90506000612bd98287878080601f01602080910402602001604051908101604052809392919081815260200183838082843760009201919091525061302b92505050565b9050612bf360008051602061448e83398151915282611f1c565b9b9a5050505050505050505050565b612c0a612e71565b611e5c612c15612eca565b613159565b60006101008210612c6d5760405162461bcd60e51b815260206004820152601c60248201527f76616c756520646f6573206e6f742066697420696e20382062697473000000006044820152606401610afd565b5090565b6000650100000000008210612c6d5760405162461bcd60e51b815260206004820152601d60248201527f76616c756520646f6573206e6f742066697420696e20343020626974730000006044820152606401610afd565b6000611f15836001600160a01b0384166131a4565b6001600160a01b03811660009081526001830160205260408120541515611f15565b6000612d09612eca565b9050612d16600082611f1c565b80612d345750612d3460008051602061448e83398151915282611f1c565b612d805760405162461bcd60e51b815260206004820152601e60248201527f73656e646572206973206e6f742072656c61796572206f722061646d696e00006044820152606401610afd565b50565b6000611f1583836040518060400160405280601e81526020017f536166654d6174683a207375627472616374696f6e206f766572666c6f7700008152506131f3565b612ddf60008051602061448e8339815191526106d1612eca565b611e5c5760405162461bcd60e51b815260206004820181905260248201527f73656e64657220646f65736e277420686176652072656c6179657220726f6c656044820152606401610afd565b60005460ff1615611e5c5760405162461bcd60e51b815260206004820152601060248201526f14185d5cd8589b194e881c185d5cd95960821b6044820152606401610afd565b612e7e60006106d1612eca565b611e5c5760405162461bcd60e51b815260206004820152601e60248201527f73656e64657220646f65736e277420686176652061646d696e20726f6c6500006044820152606401610afd565b60003360143610801590612ef657506001600160a01b03811660009081526005602052604090205460ff165b15612f06575060131936013560601c5b919050565b6000828152600160205260409020612f239082612cc8565b1561100457612f30612eca565b6001600160a01b0316816001600160a01b0316837f2f8788117e7eff1d82e926ec794901d17c78024a50270940304540a733656f0d60405160405180910390a45050565b6000828152600160205260409020612f8c908261322d565b1561100457612f99612eca565b6001600160a01b0316816001600160a01b0316837ff6391f5c32d9c69d2a47ea670b442974b53935d1edc7fd64eb21e047a839171b60405160405180910390a45050565b60006111bf612fea613242565b8360405161190160f01b6020820152602281018390526042810182905260009060620160405160208183030381529060405280519060200120905092915050565b600080600061303a8585613369565b91509150613047816133d9565b509392505050565b60008083602001516001600160c81b031661306984613072565b16119392505050565b600061309661308f60008051602061448e83398151915284611199565b6001612d83565b6001901b92915050565b6000600160c81b8210612c6d5760405162461bcd60e51b815260206004820152601e60248201527f76616c756520646f6573206e6f742066697420696e20323030206269747300006044820152606401610afd565b6130fd612e2b565b6000805460ff191660011790556040516001600160a01b03821681527f62e78cea01bee320cd4e420270b5ea74000d11b0c9f74754ebdbfc544b05a2589060200161118e565b6000611f158383613594565b60006111bf825490565b6131616135be565b6000805460ff191690556040516001600160a01b03821681527f5db9ee0a495bf2e6ff9c91a7834c1ba4fdd244a5e8aa4e537bd38aeae4b073aa9060200161118e565b60008181526001830160205260408120546131eb575081546001818101845560008481526020808220909301849055845484825282860190935260409020919091556111bf565b5060006111bf565b600081848411156132175760405162461bcd60e51b8152600401610afd91906141a1565b50600061322484866142e0565b95945050505050565b6000611f15836001600160a01b038416613607565b6000306001600160a01b037f00000000000000000000000000000000000000000000000000000000000000001614801561329b57507f000000000000000000000000000000000000000000000000000000000000000046145b156132c557507f000000000000000000000000000000000000000000000000000000000000000090565b50604080517f00000000000000000000000000000000000000000000000000000000000000006020808301919091527f0000000000000000000000000000000000000000000000000000000000000000828401527f000000000000000000000000000000000000000000000000000000000000000060608301524660808301523060a0808401919091528351808403909101815260c0909201909252805191012090565b6000808251604114156133a05760208301516040840151606085015160001a613394878285856136fa565b945094505050506133d2565b8251604014156133ca57602083015160408401516133bf8683836137e7565b9350935050506133d2565b506000905060025b9250929050565b60008160048111156133ed576133ed613e99565b14156133f65750565b600181600481111561340a5761340a613e99565b14156134585760405162461bcd60e51b815260206004820152601860248201527f45434453413a20696e76616c6964207369676e617475726500000000000000006044820152606401610afd565b600281600481111561346c5761346c613e99565b14156134ba5760405162461bcd60e51b815260206004820152601f60248201527f45434453413a20696e76616c6964207369676e6174757265206c656e677468006044820152606401610afd565b60038160048111156134ce576134ce613e99565b14156135275760405162461bcd60e51b815260206004820152602260248201527f45434453413a20696e76616c6964207369676e6174757265202773272076616c604482015261756560f01b6064820152608401610afd565b600481600481111561353b5761353b613e99565b1415612d805760405162461bcd60e51b815260206004820152602260248201527f45434453413a20696e76616c6964207369676e6174757265202776272076616c604482015261756560f01b6064820152608401610afd565b60008260000182815481106135ab576135ab6141b4565b9060005260206000200154905092915050565b60005460ff16611e5c5760405162461bcd60e51b815260206004820152601460248201527314185d5cd8589b194e881b9bdd081c185d5cd95960621b6044820152606401610afd565b600081815260018301602052604081205480156136f057600061362b6001836142e0565b855490915060009061363f906001906142e0565b90508181146136a457600086600001828154811061365f5761365f6141b4565b9060005260206000200154905080876000018481548110613682576136826141b4565b6000918252602080832090910192909255918252600188019052604090208390555b85548690806136b5576136b5614457565b6001900381819060005260206000200160009055905585600101600086815260200190815260200160002060009055600193505050506111bf565b60009150506111bf565b6000807f7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a083111561373157506000905060036137de565b8460ff16601b1415801561374957508460ff16601c14155b1561375a57506000905060046137de565b6040805160008082526020820180845289905260ff881692820192909252606081018690526080810185905260019060a0016020604051602081039080840390855afa1580156137ae573d6000803e3d6000fd5b5050604051601f1901519150506001600160a01b0381166137d7576000600192509250506137de565b9150600090505b94509492505050565b6000806001600160ff1b0383168161380460ff86901c601b61443f565b9050613812878288856136fa565b935093505050935093915050565b803560ff81168114612f0657600080fd5b80356001600160401b0381168114612f0657600080fd5b60008060006060848603121561385d57600080fd5b61386684613820565b925061387460208501613831565b9150604084013590509250925092565b60008083601f84011261389657600080fd5b5081356001600160401b038111156138ad57600080fd5b6020830191508360208285010111156133d257600080fd5b80358015158114612f0657600080fd5b60008060008060008060a087890312156138ee57600080fd5b6138f787613820565b955061390560208801613831565b945060408701356001600160401b0381111561392057600080fd5b61392c89828a01613884565b90955093505060608701359150613945608088016138c5565b90509295509295509295565b6001600160a01b0381168114612d8057600080fd5b60008060006060848603121561397b57600080fd5b83359250602084013561398d81613951565b915061399b604085016138c5565b90509250925092565b6000602082840312156139b657600080fd5b5035919050565b600080604083850312156139d057600080fd5b8235915060208301356139e281613951565b809150509250929050565b60008083601f8401126139ff57600080fd5b5081356001600160401b03811115613a1657600080fd5b6020830191508360208260051b85010111156133d257600080fd5b60008060008060408587031215613a4757600080fd5b84356001600160401b0380821115613a5e57600080fd5b613a6a888389016139ed565b90965094506020870135915080821115613a8357600080fd5b50613a90878288016139ed565b95989497509550505050565b600060208284031215613aae57600080fd5b611f1582613820565b600060208284031215613ac957600080fd5b8135611f1581613951565b80356001600160e01b031981168114612f0657600080fd5b60008060008060008060c08789031215613b0557600080fd5b8635613b1081613951565b9550602087013594506040870135613b2781613951565b9350613b3560608801613ad4565b92506080870135915061394560a08801613ad4565b634e487b7160e01b600052604160045260246000fd5b604051601f8201601f191681016001600160401b0381118282101715613b8857613b88613b4a565b604052919050565b60006001600160401b03821115613ba957613ba9613b4a565b50601f01601f191660200190565b600082601f830112613bc857600080fd5b8135613bdb613bd682613b90565b613b60565b818152846020838601011115613bf057600080fd5b816020850160208301376000918101602001919091529392505050565b60008060408385031215613c2057600080fd5b8235613c2b81613951565b915060208301356001600160401b03811115613c4657600080fd5b613c5285828601613bb7565b9150509250929050565b60008060008060008060a08789031215613c7557600080fd5b613c7e87613820565b95506020613c8d818901613831565b95506040880135945060608801356001600160401b0380821115613cb057600080fd5b613cbc8b838c01613884565b909650945060808a0135915080821115613cd557600080fd5b818a0191508a601f830112613ce957600080fd5b813581811115613cfb57613cfb613b4a565b8060051b613d0a858201613b60565b918252838101850191858101908e841115613d2457600080fd5b86860192505b83831015613d5e578483351115613d4057600080fd5b613d4f8f888535890101613bb7565b82529186019190860190613d2a565b809750505050505050509295509295509295565b60008060008060008060808789031215613d8b57600080fd5b613d9487613820565b95506020870135945060408701356001600160401b0380821115613db757600080fd5b613dc38a838b01613884565b90965094506060890135915080821115613ddc57600080fd5b50613de989828a01613884565b979a9699509497509295939492505050565b600080600060608486031215613e1057600080fd5b83356001600160481b0381168114613e2757600080fd5b9250602084013591506040840135613e3e81613951565b809150509250925092565b60008060408385031215613e5c57600080fd5b8235613e6781613951565b915060208301356139e281613951565b60008060408385031215613e8a57600080fd5b50508035926020909101359150565b634e487b7160e01b600052602160045260246000fd5b60058110613ecd57634e487b7160e01b600052602160045260246000fd5b9052565b6000608082019050613ee4828451613eaf565b60018060c81b03602084015116602083015260ff604084015116604083015264ffffffffff606084015116606083015292915050565b600080600080600060808688031215613f3257600080fd5b613f3b86613820565b9450613f4960208701613831565b93506040860135925060608601356001600160401b03811115613f6b57600080fd5b613f7788828901613884565b969995985093965092949392505050565b600080600060608486031215613f9d57600080fd5b8335613e2781613951565b60008060408385031215613fbb57600080fd5b8235613fc681613951565b9150613fd4602084016138c5565b90509250929050565b60008060408385031215613ff057600080fd5b613ff983613820565b9150613fd460208401613831565b600080600080600080600060a0888a03121561402257600080fd5b61402b88613820565b965061403960208901613831565b95506040880135945060608801356001600160401b038082111561405c57600080fd5b6140688b838c01613884565b909650945060808a013591508082111561408157600080fd5b5061408e8a828b01613884565b989b979a50959850939692959293505050565b60ff851681526001600160401b0384166020820152608081016140c76040830185613eaf565b82606083015295945050505050565b6bffffffffffffffffffffffff198460601b168152818360148301376000910160140190815292915050565b81835281816020850137506000828201602090810191909152601f909101601f19169091010190565b838152604060208201526000613224604083018486614102565b60005b83811015614160578181015183820152602001614148565b8381111561416f576000848401525b50505050565b6000815180845261418d816020860160208601614145565b601f01601f19169290920160200192915050565b602081526000611f156020830184614175565b634e487b7160e01b600052603260045260246000fd5b634e487b7160e01b600052601160045260246000fd5b60006000198214156141f4576141f46141ca565b5060010190565b8183823760009101908152919050565b60208082526023908201527f70726f706f73616c20616c72656164792065786563757465642f63616e63656c6040820152621b195960ea1b606082015260800190565b600060ff821660ff811415614265576142656141ca565b60010192915050565b60018060a01b038916815260ff8816602082015260ff8716604082015285606082015260c0608082015260006142a860c083018688614102565b82810360a0840152612bf3818587614102565b600080604083850312156142ce57600080fd5b8251915060208301516139e281613951565b6000828210156142f2576142f26141ca565b500390565b60006001600160401b0380831681811415614314576143146141ca565b6001019392505050565b8481526001600160a01b0384166020820152606060408201819052600090611ff39083018486614102565b60006020828403121561435b57600080fd5b81516001600160401b0381111561437157600080fd5b8201601f8101841361438257600080fd5b8051614390613bd682613b90565b8181528560208385010111156143a557600080fd5b613224826020830160208601614145565b60ff871681528560208201526001600160401b038516604082015260a0606082015260006143e860a083018587614102565b82810360808401526143fa8185614175565b9998505050505050505050565b60006020828403121561441957600080fd5b5051919050565b600081600019048311821515161561443a5761443a6141ca565b500290565b60008219821115614452576144526141ca565b500190565b634e487b7160e01b600052603160045260246000fdfe968626a768e76ba1363efe44e322a6c4900c5f084e0b45f35e294dfddaa9e0d5e2b7fb3b832174769106daebcfd6d1970523240dda11281102db9363b83b0dc4a264697066735822122088da442ce3d2cc7158aebd5fe28407fea367be7e114203a5d2a2857706737f5064736f6c634300080b0033"
