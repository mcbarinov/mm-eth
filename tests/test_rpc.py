from mm_eth import rpc, tx


async def test_eth_block_number(mainnet, random_proxy):
    res = await rpc.eth_block_number(mainnet, proxy=random_proxy)
    assert res.unwrap() > 9_000_000


async def test_eth_get_block_by_number_with_wss(mainnet_ws):
    res = await rpc.eth_block_number(mainnet_ws)
    assert res.unwrap() > 9_000_000


async def test_eth_chain_id(mainnet, random_proxy):
    res = await rpc.eth_chain_id(mainnet, proxy=random_proxy)
    assert res.unwrap() == 1


async def test_eth_get_balance(mainnet, address_bnb, random_proxy):
    res = await rpc.eth_get_balance(mainnet, address_bnb, proxy=random_proxy)
    assert res.unwrap() > 1


async def test_eth_get_block_by_number(mainnet, random_proxy):
    res = await rpc.eth_get_block_by_number(mainnet, 8972973, True, proxy=random_proxy)
    assert res.unwrap()["transactions"][0]["hash"] == "0x1bc1f41a0999c4ff4afe8f17704400ba0328b8b8bf60681fb809969c2127054a"


async def test_eth_get_transaction_count(mainnet, address_binance, random_proxy):
    res = await rpc.eth_get_transaction_count(mainnet, address_binance, proxy=random_proxy)
    assert res.unwrap() > 1000


async def test_eth_send_raw_transaction(mainnet, private_0, address_1):
    raw_tx = tx.sign_legacy_tx(nonce=0, gas_price=111, gas=21000, private_key=private_0, chain_id=1, value=222, to=address_1)
    res = await rpc.eth_send_raw_transaction(mainnet, raw_tx.raw_tx)
    assert res.unwrap_err().startswith("service_error: insufficient funds for")


async def test_erc20_balance(mainnet, address_tether, address_bnb, random_proxy):
    res = await rpc.erc20_balance(mainnet, token=address_tether, wallet=address_bnb, proxy=random_proxy)
    assert res.unwrap() > 1_000_000


async def test_erc20_name(mainnet, address_tether, random_proxy):
    res = await rpc.erc20_name(mainnet, address_tether, proxy=random_proxy)
    assert res.unwrap() == "Tether USD"


async def test_erc20_symbol(mainnet, address_tether, random_proxy):
    res = await rpc.erc20_symbol(mainnet, address_tether, proxy=random_proxy)
    assert res.unwrap() == "USDT"


async def test_erc20_decimals(mainnet, address_tether, random_proxy):
    res = await rpc.erc20_decimals(mainnet, address_tether, proxy=random_proxy)
    assert res.unwrap() == 6


async def test_ens_name(mainnet, random_proxy):
    # exists
    address = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
    assert (await rpc.ens_name(mainnet, address, proxy=random_proxy)).unwrap() == "vitalik.eth"

    # random empty address
    address = "0x743997F620846ab4CE946CBe3f5e5b5c51921D6E"
    assert (await rpc.ens_name(mainnet, address, proxy=random_proxy)).unwrap() is None
