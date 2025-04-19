def name_network(chain_id: int) -> str:
    match chain_id:
        case 1:
            return "Ethereum Mainnet"
        case 5:
            return "Goerli"
        case 10:
            return "OP Mainnet"
        case 280:
            return "zkSync Era Testnet"
        case 324:
            return "zkSync Era Mainnet"
        case 420:
            return "Optimism Goerli Testnet"
        case 42161:
            return "Arbitrum One"
        case 43113:
            return "Avalanche Fuji Testnet"
        case 43114:
            return "Avalanche C-Chain"
        case 421613:
            return "Arbitrum Goerli"
        case _:
            return ""
