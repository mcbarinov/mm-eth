import json

import pytest
from mm_std import Err, get_dotenv
from web3.types import ABI

from mm_eth.anvil import Anvil


@pytest.fixture()
def mnemonic() -> str:
    return "diet render mix evil relax apology hazard bamboo desert sign fence usage baby athlete cannon season busy ten jaguar silk rebel identify foster shrimp"  # noqa


@pytest.fixture()
def erc20_token_abi_str() -> str:
    return r'[{"inputs":[{"internalType":"string","name":"symbol","type":"string"},{"internalType":"uint256","name":"totalSupply","type":"uint256"}],"stateMutability":"nonpayable","type":"constructor"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"owner","type":"address"},{"indexed":true,"internalType":"address","name":"spender","type":"address"},{"indexed":false,"internalType":"uint256","name":"value","type":"uint256"}],"name":"Approval","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"from","type":"address"},{"indexed":true,"internalType":"address","name":"to","type":"address"},{"indexed":false,"internalType":"uint256","name":"value","type":"uint256"}],"name":"Transfer","type":"event"},{"inputs":[{"internalType":"address","name":"owner","type":"address"},{"internalType":"address","name":"spender","type":"address"}],"name":"allowance","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"spender","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"approve","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"account","type":"address"}],"name":"balanceOf","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"decimals","outputs":[{"internalType":"uint8","name":"","type":"uint8"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"spender","type":"address"},{"internalType":"uint256","name":"subtractedValue","type":"uint256"}],"name":"decreaseAllowance","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"spender","type":"address"},{"internalType":"uint256","name":"addedValue","type":"uint256"}],"name":"increaseAllowance","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"name","outputs":[{"internalType":"string","name":"","type":"string"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"symbol","outputs":[{"internalType":"string","name":"","type":"string"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"totalSupply","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"recipient","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"transfer","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"sender","type":"address"},{"internalType":"address","name":"recipient","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"transferFrom","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"}]'  # noqa


@pytest.fixture()
def erc20_abi(erc20_token_abi_str) -> ABI:
    return json.loads(erc20_token_abi_str)


@pytest.fixture()
def erc20_token_bin() -> str:
    return "608060405234801562000010575f80fd5b5060405162000d1338038062000d138339810160408190526200003391620001dc565b60036200004183826200033b565b5060046200005083826200033b565b506005805460ff191660121790556200006a338262000072565b505062000423565b6001600160a01b038216620000ce5760405162461bcd60e51b815260206004820152601f60248201527f45524332303a206d696e7420746f20746865207a65726f20616464726573730060448201526064015b60405180910390fd5b600254620000dd90826200015d565b6002556001600160a01b0382165f908152602081905260409020546200010490826200015d565b6001600160a01b0383165f81815260208181526040808320949094559251848152919290917fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef910160405180910390a35050565b505050565b5f806200016b838562000403565b905083811015620001bf5760405162461bcd60e51b815260206004820152601b60248201527f536166654d6174683a206164646974696f6e206f766572666c6f7700000000006044820152606401620000c5565b90505b92915050565b634e487b7160e01b5f52604160045260245ffd5b5f8060408385031215620001ee575f80fd5b82516001600160401b038082111562000205575f80fd5b818501915085601f83011262000219575f80fd5b8151818111156200022e576200022e620001c8565b604051601f8201601f19908116603f01168101908382118183101715620002595762000259620001c8565b8160405282815260209350888484870101111562000275575f80fd5b5f91505b8282101562000298578482018401518183018501529083019062000279565b5f928101840192909252509401519395939450505050565b600181811c90821680620002c557607f821691505b602082108103620002e457634e487b7160e01b5f52602260045260245ffd5b50919050565b601f82111562000158575f81815260208120601f850160051c81016020861015620003125750805b601f850160051c820191505b8181101562000333578281556001016200031e565b505050505050565b81516001600160401b03811115620003575762000357620001c8565b6200036f81620003688454620002b0565b84620002ea565b602080601f831160018114620003a5575f84156200038d5750858301515b5f19600386901b1c1916600185901b17855562000333565b5f85815260208120601f198616915b82811015620003d557888601518255948401946001909101908401620003b4565b5085821015620003f357878501515f19600388901b60f8161c191681555b5050505050600190811b01905550565b80820180821115620001c257634e487b7160e01b5f52601160045260245ffd5b6108e280620004315f395ff3fe608060405234801561000f575f80fd5b50600436106100a6575f3560e01c8063395093511161006e578063395093511461012557806370a082311461013857806395d89b4114610160578063a457c2d714610168578063a9059cbb1461017b578063dd62ed3e1461018e575f80fd5b806306fdde03146100aa578063095ea7b3146100c857806318160ddd146100eb57806323b872dd146100fd578063313ce56714610110575b5f80fd5b6100b26101c6565b6040516100bf91906106b6565b60405180910390f35b6100db6100d636600461071c565b610256565b60405190151581526020016100bf565b6002545b6040519081526020016100bf565b6100db61010b366004610744565b61026c565b60055460405160ff90911681526020016100bf565b6100db61013336600461071c565b6102d3565b6100ef61014636600461077d565b6001600160a01b03165f9081526020819052604090205490565b6100b2610308565b6100db61017636600461071c565b610317565b6100db61018936600461071c565b610364565b6100ef61019c366004610796565b6001600160a01b039182165f90815260016020908152604080832093909416825291909152205490565b6060600380546101d5906107c7565b80601f0160208091040260200160405190810160405280929190818152602001828054610201906107c7565b801561024c5780601f106102235761010080835404028352916020019161024c565b820191905f5260205f20905b81548152906001019060200180831161022f57829003601f168201915b5050505050905090565b5f610262338484610370565b5060015b92915050565b5f610278848484610499565b6102c984336102c485604051806060016040528060288152602001610860602891396001600160a01b038a165f9081526001602090815260408083203384529091529020549190610619565b610370565b5060019392505050565b335f8181526001602090815260408083206001600160a01b038716845290915281205490916102629185906102c49086610651565b6060600480546101d5906107c7565b5f61026233846102c48560405180606001604052806025815260200161088860259139335f9081526001602090815260408083206001600160a01b038d1684529091529020549190610619565b5f610262338484610499565b6001600160a01b0383166103d75760405162461bcd60e51b8152602060048201526024808201527f45524332303a20617070726f76652066726f6d20746865207a65726f206164646044820152637265737360e01b60648201526084015b60405180910390fd5b6001600160a01b0382166104385760405162461bcd60e51b815260206004820152602260248201527f45524332303a20617070726f766520746f20746865207a65726f206164647265604482015261737360f01b60648201526084016103ce565b6001600160a01b038381165f8181526001602090815260408083209487168084529482529182902085905590518481527f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b92591015b60405180910390a3505050565b6001600160a01b0383166104fd5760405162461bcd60e51b815260206004820152602560248201527f45524332303a207472616e736665722066726f6d20746865207a65726f206164604482015264647265737360d81b60648201526084016103ce565b6001600160a01b03821661055f5760405162461bcd60e51b815260206004820152602360248201527f45524332303a207472616e7366657220746f20746865207a65726f206164647260448201526265737360e81b60648201526084016103ce565b61059b8160405180606001604052806026815260200161083a602691396001600160a01b0386165f908152602081905260409020549190610619565b6001600160a01b038085165f9081526020819052604080822093909355908416815220546105c99082610651565b6001600160a01b038381165f818152602081815260409182902094909455518481529092918616917fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef910161048c565b5f818484111561063c5760405162461bcd60e51b81526004016103ce91906106b6565b505f6106488486610813565b95945050505050565b5f8061065d8385610826565b9050838110156106af5760405162461bcd60e51b815260206004820152601b60248201527f536166654d6174683a206164646974696f6e206f766572666c6f77000000000060448201526064016103ce565b9392505050565b5f6020808352835180828501525f5b818110156106e1578581018301518582016040015282016106c5565b505f604082860101526040601f19601f8301168501019250505092915050565b80356001600160a01b0381168114610717575f80fd5b919050565b5f806040838503121561072d575f80fd5b61073683610701565b946020939093013593505050565b5f805f60608486031215610756575f80fd5b61075f84610701565b925061076d60208501610701565b9150604084013590509250925092565b5f6020828403121561078d575f80fd5b6106af82610701565b5f80604083850312156107a7575f80fd5b6107b083610701565b91506107be60208401610701565b90509250929050565b600181811c908216806107db57607f821691505b6020821081036107f957634e487b7160e01b5f52602260045260245ffd5b50919050565b634e487b7160e01b5f52601160045260245ffd5b81810381811115610266576102666107ff565b80820180821115610266576102666107ff56fe45524332303a207472616e7366657220616d6f756e7420657863656564732062616c616e636545524332303a207472616e7366657220616d6f756e74206578636565647320616c6c6f77616e636545524332303a2064656372656173656420616c6c6f77616e63652062656c6f77207a65726fa2646970667358221220fdf5850518272abc852e84db2b1c5e730e5de114aa27c25a2f3447b021fb005064736f6c63430008140033"  # noqa


@pytest.fixture()
def anvil(mnemonic):
    res = Anvil.launch(mnemonic=mnemonic)
    if isinstance(res, Err):
        raise Exception(f"can't start anvil: {res.err}")
    a = res.ok
    try:
        yield a
    finally:
        a.stop()


@pytest.fixture
def etherscan_key():
    return get_dotenv("MM_PROXIES_APP")


@pytest.fixture
def mm_proxies() -> list[str]:
    # url, token = get_dotenv("MM_PROXIES_APP").split("|")
    # res = hr(f"{url}/api/proxies/live", headers={"access-token": token})
    # return res.json.get("proxies")
    return []


@pytest.fixture
def infura():
    infura = get_dotenv("INFURA_API_KEY")

    def _infura(network="mainnet", ws=False):
        if ws:
            return f"wss://{network}.infura.io/ws/v3/{infura}"
        else:
            return f"https://{network}.infura.io/v3/{infura}"

    return _infura


@pytest.fixture
def mainnet_archive_node():
    return get_dotenv("MAINNET_ARCHIVE_NODE")


@pytest.fixture
def address_bnb():
    return "0xB8c77482e45F1F44dE1745F52C74426C631bDD52"


@pytest.fixture
def address_tether():
    return "0xdac17f958d2ee523a2206206994597c13d831ec7"


@pytest.fixture
def address_0():
    return "0x10fd602Bff689e64D4720D1DCCCD3494f1f16623"


@pytest.fixture
def private_0():
    return "0x7bb5b9c0ba991275f84b796b4d25fd3a8d7320911f50fade85410e7a2b000632"


@pytest.fixture
def address_1():
    return "0x58487485c3858109f5A37e42546FE87473f79a4b"


@pytest.fixture
def private_1():
    return "0xe4d16faffffa9b28adf02fb5f06998d174046c369d2daffe9a750fbe6a333417"


@pytest.fixture
def address_2():
    return "0x97C77B548aE0d4925F5C201220fC6d8996424309"


@pytest.fixture
def private_2():
    return "0xb7e0b671e176b04ceb0897a698d34771bfe9acf29273dc52a141be6e97145a00"
