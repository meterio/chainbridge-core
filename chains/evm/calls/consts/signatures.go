package consts

const SignaturesABI = `[
    {
      "inputs": [],
      "stateMutability": "nonpayable",
      "type": "constructor"
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
          "indexed": true,
          "internalType": "uint8",
          "name": "originDomainID",
          "type": "uint8"
        },
        {
          "indexed": true,
          "internalType": "uint8",
          "name": "destinationDomainID",
          "type": "uint8"
        },
        {
          "indexed": false,
          "internalType": "uint64",
          "name": "depositNonce",
          "type": "uint64"
        },
        {
          "indexed": true,
          "internalType": "bytes32",
          "name": "resourceID",
          "type": "bytes32"
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
          "name": "signature",
          "type": "bytes"
        }
      ],
      "name": "SignaturePass",
      "type": "event"
    },
    {
      "anonymous": false,
      "inputs": [
        {
          "indexed": true,
          "internalType": "uint8",
          "name": "originDomainID",
          "type": "uint8"
        },
        {
          "indexed": true,
          "internalType": "uint8",
          "name": "destinationDomainID",
          "type": "uint8"
        },
        {
          "indexed": false,
          "internalType": "uint64",
          "name": "depositNonce",
          "type": "uint64"
        },
        {
          "indexed": true,
          "internalType": "bytes32",
          "name": "resourceID",
          "type": "bytes32"
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
          "name": "signature",
          "type": "bytes"
        }
      ],
      "name": "SubmitSignature",
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
      "name": "_TYPE_HASH",
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
          "internalType": "uint8",
          "name": "",
          "type": "uint8"
        }
      ],
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
          "internalType": "uint8",
          "name": "destinationDomainID",
          "type": "uint8"
        },
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
      "name": "adminPause",
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
          "name": "chainId",
          "type": "uint256"
        },
        {
          "internalType": "address",
          "name": "destinationBridge",
          "type": "address"
        }
      ],
      "name": "adminSetDestChainId",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "adminUnpause",
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
          "internalType": "uint8",
          "name": "destinationDomainID",
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
          "internalType": "uint8",
          "name": "",
          "type": "uint8"
        }
      ],
      "name": "destChainId",
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
      "name": "destinationBridgeAddress",
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
          "internalType": "uint256",
          "name": "index",
          "type": "uint256"
        }
      ],
      "name": "getProposal",
      "outputs": [
        {
          "components": [
            {
              "internalType": "uint8",
              "name": "originDomainID",
              "type": "uint8"
            },
            {
              "internalType": "uint8",
              "name": "destinationDomainID",
              "type": "uint8"
            },
            {
              "internalType": "address",
              "name": "destinationBridge",
              "type": "address"
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
              "internalType": "uint256",
              "name": "proposalIndex",
              "type": "uint256"
            }
          ],
          "internalType": "struct Signatures.Proposal",
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
          "internalType": "uint8",
          "name": "domainID",
          "type": "uint8"
        },
        {
          "internalType": "uint8",
          "name": "destinationDomainID",
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
      "name": "getSignatures",
      "outputs": [
        {
          "internalType": "bytes[]",
          "name": "",
          "type": "bytes[]"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint256",
          "name": "index",
          "type": "uint256"
        }
      ],
      "name": "getSignatures",
      "outputs": [
        {
          "internalType": "bytes[]",
          "name": "",
          "type": "bytes[]"
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
          "internalType": "bytes",
          "name": "",
          "type": "bytes"
        }
      ],
      "name": "hasVote",
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
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "name": "indexToProposal",
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
      "inputs": [],
      "name": "proposalIndex",
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
          "name": "",
          "type": "bytes32"
        }
      ],
      "name": "proposals",
      "outputs": [
        {
          "internalType": "uint8",
          "name": "originDomainID",
          "type": "uint8"
        },
        {
          "internalType": "uint8",
          "name": "destinationDomainID",
          "type": "uint8"
        },
        {
          "internalType": "address",
          "name": "destinationBridge",
          "type": "address"
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
          "internalType": "uint256",
          "name": "proposalIndex",
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
          "name": "",
          "type": "bytes32"
        },
        {
          "internalType": "address",
          "name": "",
          "type": "address"
        }
      ],
      "name": "relayerVote",
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
          "internalType": "bytes32",
          "name": "",
          "type": "bytes32"
        },
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "name": "signatures",
      "outputs": [
        {
          "internalType": "bytes",
          "name": "",
          "type": "bytes"
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
          "internalType": "uint8",
          "name": "destinationDomainID",
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
      "name": "submitSignature",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    }
  ]`
const SignaturesBin = "0x600c6080526b5065726d697442726964676560a01b60a0527f058443738ec3641a3233a9f285e16671e4ad9755445580d761017e695f75052b600155610100604052600360c052620312e360ec1b60e0527fe6bbd6277e1bf288eed5e8d1780f9a50b239e86b153736bceebccf4ea79d90b36002553480156200008157600080fd5b506200008f60003362000095565b6200017e565b620000a18282620000a5565b5050565b600082815260208181526040909120620000ca91839062000c1a6200010c821b17901c565b15620000a15760405133906001600160a01b0383169084907f2f8788117e7eff1d82e926ec794901d17c78024a50270940304540a733656f0d90600090a45050565b600062000123836001600160a01b0384166200012c565b90505b92915050565b6000818152600183016020526040812054620001755750815460018181018455600084815260208082209093018490558454848252828601909352604090209190915562000126565b50600062000126565b6117b9806200018e6000396000f3fe608060405234801561001057600080fd5b506004361061012c5760003560e01c8063861fd043116100ad578063a217fddf11610071578063a217fddf146102f1578063aa44739d146102f9578063ca15c8731461032e578063d547741f14610341578063e5787a751461035457600080fd5b8063861fd043146102665780639010d07c1461027957806391d14854146102a4578063926d7d7f146102b7578063a11279c7146102de57600080fd5b806330adf81f116100f457806330adf81f146101d257806336568abe146101f95780634e0df3f61461020c5780635d2dab0b1461021f57806374400fd11461024657600080fd5b80630b18fec5146101315780631f241eca14610164578063248a9ca3146101875780632f2ff15d146101aa5780632fda959e146101bf575b600080fd5b61015161013f36600461130f565b60046020526000908152604090205481565b6040519081526020015b60405180910390f35b61017761017236600461139b565b610374565b604051901515815260200161015b565b610151610195366004611459565b60009081526020819052604090206002015490565b6101bd6101b8366004611472565b61056c565b005b6101bd6101cd36600461149e565b6105ff565b6101517fc4cb5d35714699d6e85b9562b644e60393b418d974a5c1dd8efaadac37a142c581565b6101bd610207366004611472565b610683565b61015161021a366004611472565b6106fd565b6101517f8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f81565b6102596102543660046114c8565b610728565b60405161015b9190611537565b6101bd61027436600461139b565b6107e1565b61028c6102873660046114c8565b610986565b6040516001600160a01b03909116815260200161015b565b6101776102b2366004611472565b6109a5565b6101517fe2b7fb3b832174769106daebcfd6d1970523240dda11281102db9363b83b0dc481565b6101bd6102ec36600461154a565b6109bd565b610151600081565b61031c61030736600461130f565b60036020526000908152604090205460ff1681565b60405160ff909116815260200161015b565b61015161033c366004611459565b610a2d565b6101bd61034f366004611472565b610a44565b610367610362366004611574565b610ac5565b60405161015b91906115e3565b6000807fc4cb5d35714699d6e85b9562b644e60393b418d974a5c1dd8efaadac37a142c58b898989896040516103ab929190611645565b6040519081900381206103ef959493929160200194855260ff93909316602085015267ffffffffffffffff9190911660408401526060830152608082015260a00190565b60408051601f19818403018152918152815160209283012060ff8d1660009081526004909352908220549092506104eb9083901561043f5760ff8d16600090815260046020526040902054610444565b8c60ff165b600154600254604080517f8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f60208083019190915281830194909452606081019290925260808201939093526001600160a01b038f1660a0808301919091528351808303909101815260c08201845280519083012061190160f01b60e083015260e2820152610102808201949094528251808203909401845261012201909152815191012090565b9050600061052f8287878080601f016020809104026020016040519081016040528093929190818152602001838380828437600092019190915250610c2f92505050565b905061055b7fe2b7fb3b832174769106daebcfd6d1970523240dda11281102db9363b83b0dc4826109a5565b9d9c50505050505050505050505050565b60008281526020819052604090206002015461058890336109a5565b6105f15760405162461bcd60e51b815260206004820152602f60248201527f416363657373436f6e74726f6c3a2073656e646572206d75737420626520616e60448201526e0818591b5a5b881d1bc819dc985b9d608a1b60648201526084015b60405180910390fd5b6105fb8282610c53565b5050565b61060a6000336109a5565b6106565760405162461bcd60e51b815260206004820152601e60248201527f73656e64657220646f65736e277420686176652061646d696e20726f6c65000060448201526064016105e8565b61065f81610cac565b60ff9283166000908152600360205260409020805460ff1916919093161790915550565b6001600160a01b03811633146106f35760405162461bcd60e51b815260206004820152602f60248201527f416363657373436f6e74726f6c3a2063616e206f6e6c792072656e6f756e636560448201526e103937b632b9903337b91039b2b63360891b60648201526084016105e8565b6105fb8282610d03565b6000828152602081815260408083206001600160a01b03851684526001019091529020545b92915050565b6005602052816000526040600020818154811061074457600080fd5b9060005260206000200160009150915050805461076090611655565b80601f016020809104026020016040519081016040528092919081815260200182805461078c90611655565b80156107d95780601f106107ae576101008083540402835291602001916107d9565b820191906000526020600020905b8154815290600101906020018083116107bc57829003601f168201915b505050505081565b6107f2898989898989898989610374565b6108325760405162461bcd60e51b8152602060048201526011602482015270696e76616c6964207369676e617475726560781b60448201526064016105e8565b60008987878787604051610847929190611645565b6040519081900381206108849493929160200160ff94909416845267ffffffffffffffff9290921660208401526040830152606082015260800190565b60408051601f1981840301815291815281516020928301206000818152600584529182208054600181018255908352929091209092506108c691018484611269565b50858a60ff167f61cb4bceda51bce60b1d6ed6a15c758737872a125214641da0ae8bb0f2fd231189888888886040516109039594939291906116b9565b60405180910390a360ff808a1660009081526003602090815260408083205485845260059092529091205491161161097a57858a60ff167f34a202d5d1eb96571e8f79cd5ad505695728f56e0de6df829f702e6d4fc909eb89888888886040516109719594939291906116b9565b60405180910390a35b50505050505050505050565b600082815260208190526040812061099e9083610d5c565b9392505050565b600082815260208190526040812061099e9083610d68565b6109c86000336109a5565b610a145760405162461bcd60e51b815260206004820152601e60248201527f73656e64657220646f65736e277420686176652061646d696e20726f6c65000060448201526064016105e8565b60ff918216600090815260046020526040902091169055565b600081815260208190526040812061072290610d8a565b600082815260208190526040902060020154610a6090336109a5565b6106f35760405162461bcd60e51b815260206004820152603060248201527f416363657373436f6e74726f6c3a2073656e646572206d75737420626520616e60448201526f2061646d696e20746f207265766f6b6560801b60648201526084016105e8565b6060600560008787878787604051610ade929190611645565b604051908190038120610b1b9493929160200160ff94909416845267ffffffffffffffff9290921660208401526040830152606082015260800190565b604051602081830303815290604052805190602001208152602001908152602001600020805480602002602001604051908101604052809291908181526020016000905b82821015610c0b578382906000526020600020018054610b7e90611655565b80601f0160208091040260200160405190810160405280929190818152602001828054610baa90611655565b8015610bf75780601f10610bcc57610100808354040283529160200191610bf7565b820191906000526020600020905b815481529060010190602001808311610bda57829003601f168201915b505050505081526020019060010190610b5f565b50505050905095945050505050565b600061099e836001600160a01b038416610d94565b6000806000610c3e8585610de3565b91509150610c4b81610e53565b509392505050565b6000828152602081905260409020610c6b9082610c1a565b156105fb5760405133906001600160a01b0383169084907f2f8788117e7eff1d82e926ec794901d17c78024a50270940304540a733656f0d90600090a45050565b60006101008210610cff5760405162461bcd60e51b815260206004820152601c60248201527f76616c756520646f6573206e6f742066697420696e203820626974730000000060448201526064016105e8565b5090565b6000828152602081905260409020610d1b9082611011565b156105fb5760405133906001600160a01b0383169084907ff6391f5c32d9c69d2a47ea670b442974b53935d1edc7fd64eb21e047a839171b90600090a45050565b600061099e8383611026565b6001600160a01b0381166000908152600183016020526040812054151561099e565b6000610722825490565b6000818152600183016020526040812054610ddb57508154600181810184556000848152602080822090930184905584548482528286019093526040902091909155610722565b506000610722565b600080825160411415610e1a5760208301516040840151606085015160001a610e0e87828585611050565b94509450505050610e4c565b825160401415610e445760208301516040840151610e3986838361113d565b935093505050610e4c565b506000905060025b9250929050565b6000816004811115610e6757610e676116fc565b1415610e705750565b6001816004811115610e8457610e846116fc565b1415610ed25760405162461bcd60e51b815260206004820152601860248201527f45434453413a20696e76616c6964207369676e6174757265000000000000000060448201526064016105e8565b6002816004811115610ee657610ee66116fc565b1415610f345760405162461bcd60e51b815260206004820152601f60248201527f45434453413a20696e76616c6964207369676e6174757265206c656e6774680060448201526064016105e8565b6003816004811115610f4857610f486116fc565b1415610fa15760405162461bcd60e51b815260206004820152602260248201527f45434453413a20696e76616c6964207369676e6174757265202773272076616c604482015261756560f01b60648201526084016105e8565b6004816004811115610fb557610fb56116fc565b141561100e5760405162461bcd60e51b815260206004820152602260248201527f45434453413a20696e76616c6964207369676e6174757265202776272076616c604482015261756560f01b60648201526084016105e8565b50565b600061099e836001600160a01b038416611176565b600082600001828154811061103d5761103d611712565b9060005260206000200154905092915050565b6000807f7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a08311156110875750600090506003611134565b8460ff16601b1415801561109f57508460ff16601c14155b156110b05750600090506004611134565b6040805160008082526020820180845289905260ff881692820192909252606081018690526080810185905260019060a0016020604051602081039080840390855afa158015611104573d6000803e3d6000fd5b5050604051601f1901519150506001600160a01b03811661112d57600060019250925050611134565b9150600090505b94509492505050565b6000806001600160ff1b0383168161115a60ff86901c601b61173e565b905061116887828885611050565b935093505050935093915050565b6000818152600183016020526040812054801561125f57600061119a600183611756565b85549091506000906111ae90600190611756565b90508181146112135760008660000182815481106111ce576111ce611712565b90600052602060002001549050808760000184815481106111f1576111f1611712565b6000918252602080832090910192909255918252600188019052604090208390555b85548690806112245761122461176d565b600190038181906000526020600020016000905590558560010160008681526020019081526020016000206000905560019350505050610722565b6000915050610722565b82805461127590611655565b90600052602060002090601f01602090048101928261129757600085556112dd565b82601f106112b05782800160ff198235161785556112dd565b828001600101855582156112dd579182015b828111156112dd5782358255916020019190600101906112c2565b50610cff9291505b80821115610cff57600081556001016112e5565b803560ff8116811461130a57600080fd5b919050565b60006020828403121561132157600080fd5b61099e826112f9565b80356001600160a01b038116811461130a57600080fd5b803567ffffffffffffffff8116811461130a57600080fd5b60008083601f84011261136b57600080fd5b50813567ffffffffffffffff81111561138357600080fd5b602083019150836020828501011115610e4c57600080fd5b600080600080600080600080600060e08a8c0312156113b957600080fd5b6113c28a6112f9565b98506113d060208b016112f9565b97506113de60408b0161132a565b96506113ec60608b01611341565b955060808a0135945060a08a013567ffffffffffffffff8082111561141057600080fd5b61141c8d838e01611359565b909650945060c08c013591508082111561143557600080fd5b506114428c828d01611359565b915080935050809150509295985092959850929598565b60006020828403121561146b57600080fd5b5035919050565b6000806040838503121561148557600080fd5b823591506114956020840161132a565b90509250929050565b600080604083850312156114b157600080fd5b6114ba836112f9565b946020939093013593505050565b600080604083850312156114db57600080fd5b50508035926020909101359150565b6000815180845260005b81811015611510576020818501810151868301820152016114f4565b81811115611522576000602083870101525b50601f01601f19169290920160200192915050565b60208152600061099e60208301846114ea565b6000806040838503121561155d57600080fd5b611566836112f9565b9150611495602084016112f9565b60008060008060006080868803121561158c57600080fd5b611595866112f9565b94506115a360208701611341565b935060408601359250606086013567ffffffffffffffff8111156115c657600080fd5b6115d288828901611359565b969995985093965092949392505050565b6000602080830181845280855180835260408601915060408160051b870101925083870160005b8281101561163857603f198886030184526116268583516114ea565b9450928501929085019060010161160a565b5092979650505050505050565b8183823760009101908152919050565b600181811c9082168061166957607f821691505b6020821081141561168a57634e487b7160e01b600052602260045260246000fd5b50919050565b81835281816020850137506000828201602090810191909152601f909101601f19169091010190565b67ffffffffffffffff861681526060602082015260006116dd606083018688611690565b82810360408401526116f0818587611690565b98975050505050505050565b634e487b7160e01b600052602160045260246000fd5b634e487b7160e01b600052603260045260246000fd5b634e487b7160e01b600052601160045260246000fd5b6000821982111561175157611751611728565b500190565b60008282101561176857611768611728565b500390565b634e487b7160e01b600052603160045260246000fdfea2646970667358221220ebab373bf9b319cf969809a9c0421aa2db0924a1bc95d066ded83e410cb0005764736f6c634300080b0033"
