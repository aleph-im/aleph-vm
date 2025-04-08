import logging

from aleph_message.models import Chain
from pydantic import BaseModel, model_validator

logger = logging.getLogger(__name__)


class ChainInfo(BaseModel):
    """
    A chain information.
    """

    chain_id: int
    rpc: str
    standard_token: str | None = None
    super_token: str | None = None
    testnet: bool = False
    active: bool = True

    @property
    def token(self) -> str | None:
        return self.super_token or self.standard_token

    @model_validator(mode="before")
    @classmethod
    def check_tokens(cls, values):
        if not values.get("standard_token") and not values.get("super_token"):
            msg = "At least one of standard_token or super_token must be provided."
            raise ValueError(msg)
        return values


STREAM_CHAINS: dict[Chain | str, ChainInfo] = {
    # TESTNETS
    "SEPOLIA": ChainInfo(
        chain_id=11155111,
        rpc="https://eth-sepolia.public.blastapi.io",
        standard_token="0xc4bf5cbdabe595361438f8c6a187bdc330539c60",
        super_token="0x22064a21fee226d8ffb8818e7627d5ff6d0fc33a",
        active=False,
        testnet=True,
    ),
    # MAINNETS
    Chain.ETH: ChainInfo(
        chain_id=1,
        rpc="https://eth-mainnet.public.blastapi.io",
        standard_token="0x27702a26126e0B3702af63Ee09aC4d1A084EF628",
        active=False,
    ),
    Chain.AVAX: ChainInfo(
        chain_id=43114,
        rpc="https://api.avax.network/ext/bc/C/rpc",
        super_token="0xc0Fbc4967259786C743361a5885ef49380473dCF",
    ),
    Chain.BASE: ChainInfo(
        chain_id=8453,
        rpc="https://base-mainnet.public.blastapi.io",
        super_token="0xc0Fbc4967259786C743361a5885ef49380473dCF",
    ),
}


class InvalidChainError(ValueError):
    pass


def get_chain(chain: str) -> ChainInfo:
    try:
        return STREAM_CHAINS[chain]
    except KeyError:
        msg = f"Unknown chain id for chain {chain}"
        raise InvalidChainError(msg)
