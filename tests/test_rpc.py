import pytest

from mm_eth import rpc, tx

pytestmark = pytest.mark.infura


def test_eth_block_number(infura):
    res = rpc.eth_block_number(infura())
    assert res.unwrap() > 9_000_000

    res = rpc.eth_block_number(infura(ws=True))
    assert res.unwrap() > 9_000_000


def test_eth_get_code(infura, address_bnb):
    res = rpc.eth_get_code(infura(), address_bnb)
    assert res.unwrap().startswith("0x606060405236")


def test_net_version(infura):
    res = rpc.net_version(infura())
    assert res.unwrap() == "1"


def test_eth_send_raw_transaction(infura, private_0, address_1):
    raw_tx = tx.sign_legacy_tx(nonce=0, gas_price=111, gas=21000, private_key=private_0, chain_id=1, value=222, to=address_1)
    res = rpc.eth_send_raw_transaction(infura(), raw_tx.raw_tx)
    assert res.unwrap_err().startswith("service_error: insufficient funds for")


def test_web3_client_version(infura):
    res = rpc.web3_client_version(infura())
    assert res.unwrap().startswith("Geth")


def test_net_peer_count(infura):
    res = rpc.net_peer_count(infura())
    assert res.unwrap() > 1


def test_eth_get_balance(infura, address_bnb):
    res = rpc.eth_get_balance(infura(), address_bnb)
    assert res.unwrap() > 1


def test_eth_get_block_by_number(infura):
    res = rpc.eth_get_block_by_number(infura(), 8972973, True)
    assert res.unwrap()["transactions"][0]["hash"] == "0x1bc1f41a0999c4ff4afe8f17704400ba0328b8b8bf60681fb809969c2127054a"


def test_eth_get_logs(infura, address_bnb):
    res = rpc.eth_get_logs(infura(), address=address_bnb, from_block=9_000_000, to_block=9_001_000)
    assert len(res.unwrap()) == 70


def test_eth_get_transaction_receipt(mainnet_archive_node):
    res = rpc.eth_get_transaction_receipt(
        mainnet_archive_node,
        "0xc10fc67499a037b6c2f14ae0c63b659b05bd7b553378202f96e777dd4843130f",
    )
    assert res.unwrap().block_number == 3154196


def test_eth_get_transaction_by_hash(mainnet_archive_node):
    res = rpc.eth_get_transaction_by_hash(
        mainnet_archive_node,
        "0x11f52d6cf97fd61c261f54d38134c1dcc32d32c4d60de6e64c31e776a46e6373",
    )
    assert res.unwrap().block_number == 9914284


def test_eth_call(infura, address_tether):
    # get tether balance of bnb address
    data = "0x27e235e3000000000000000000000000B8c77482e45F1F44dE1745F52C74426C631bDD52"
    res = rpc.eth_call(infura(), to=address_tether, data=data)
    assert int(res.unwrap(), 16) > 1_000_000


def test_eth_estimate_gas(infura, address_0, address_1):
    data = "0x27e235e30000000000000000000000003f5ce5fbfe3e9af3971dd833d26ba9b5c936f0be"
    res = rpc.eth_estimate_gas(infura(), from_=address_0, to=address_1, data=data)
    assert res.unwrap() == 21598


def test_eth_gas_price(anvil):
    res = rpc.eth_gas_price(anvil.rpc_url)
    assert res.unwrap() > 1_000_000


def test_eth_syncing(anvil):
    res = rpc.eth_syncing(anvil.rpc_url)
    assert res.unwrap() is False


def test_eth_chain_id(anvil):
    res = rpc.eth_chain_id(anvil.rpc_url)
    assert res.ok == anvil.chain_id


def test_get_base_fee_per_gas(anvil):
    res = rpc.get_base_fee_per_gas(anvil.rpc_url)
    assert res.unwrap() == 1000000000
