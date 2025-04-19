import os

import pytest
from dotenv import load_dotenv
from mm_crypto_utils import proxy

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


@pytest.fixture(scope="session")
def proxies() -> list[str]:
    return proxy.fetch_proxies_or_fatal_sync(os.getenv("PROXIES_URL"))


@pytest.fixture()
def random_proxy(proxies: list[str]) -> str:
    return proxy.random_proxy(proxies)
