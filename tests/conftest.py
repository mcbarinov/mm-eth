import os

import pytest
from dotenv import load_dotenv
from mm_crypto_utils import proxy
from typer.testing import CliRunner

load_dotenv()


@pytest.fixture
def mainnet() -> str:
    return os.getenv("MAINNET_RPC")


@pytest.fixture
def mainnet_ws() -> str:
    return os.getenv("MAINNET_RPC_WS")


@pytest.fixture
def address_bnb():
    return "0xB8c77482e45F1F44dE1745F52C74426C631bDD52"


@pytest.fixture
def address_tether():
    return "0xdac17f958d2ee523a2206206994597c13d831ec7"


@pytest.fixture()
def mnemonic() -> str:
    return "diet render mix evil relax apology hazard bamboo desert sign fence usage baby athlete cannon season busy ten jaguar silk rebel identify foster shrimp"  # noqa: E501


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


@pytest.fixture(scope="session")
def proxies() -> list[str]:
    return proxy.fetch_proxies_or_fatal_sync(os.getenv("PROXIES_URL"))


@pytest.fixture()
def random_proxy(proxies: list[str]) -> str:
    return proxy.random_proxy(proxies)


@pytest.fixture
def cli_runner() -> CliRunner:
    return CliRunner()
