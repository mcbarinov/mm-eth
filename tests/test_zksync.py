from mm_eth import zksync


def test_zksync_contract_abi():
    res = zksync.zksync_contract_abi()
    assert res[0]["name"] == "BlockCommit"
    assert res[-1]["name"] == "upgradeProposalHash"
