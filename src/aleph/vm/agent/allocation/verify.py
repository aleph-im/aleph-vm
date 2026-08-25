"""Local verification of a message the scheduler embedded in its plan.

Two gates, only meaningful together:

1. aleph_message's own validators enforce item_hash == sha256(item_content)
   and content == json(item_content) for inline messages, so parsing binds the
   content to the hash.
2. The sender's signature covers "chain\\nsender\\ntype\\nitem_hash", so a
   valid signature proves the sender authorized exactly that content.

The result is that the scheduler picks WHICH user messages run here and never
WHAT they contain, which is the authority it already had.

Only EVM signatures are checked. A chain we cannot verify, or a message with
no inline content, is UNVERIFIABLE rather than REJECTED: the caller falls back
to fetching it from the CCN, exactly as before this feature existed.

There is deliberately no "amended message" in the payload. What
``update_message`` resolves is not a message-level amend but the ``use_latest``
refs inside volumes, rootfs and code, and a resolved ref is just a hash: the
agent has nothing to check it against. Accepting one from the scheduler would
let it point a rootfs at content of its choosing, which is exactly the
authority this module exists to deny. The agent resolves those refs itself.
"""

import logging
from dataclasses import dataclass
from enum import Enum

from aleph_message import parse_message
from aleph_message.models import (
    ExecutableMessage,
    InstanceMessage,
    ItemType,
    ProgramMessage,
    VerifiableProgramMessage,
)
from eth_account import Account
from eth_account.messages import encode_defunct

logger = logging.getLogger(__name__)

EVM_CHAINS = {"ETH", "AVAX", "BASE", "BSC"}


class VerificationOutcome(Enum):
    VERIFIED = "verified"
    REJECTED = "rejected"
    UNVERIFIABLE = "unverifiable"


@dataclass(frozen=True)
class VerifiedMessage:
    message: ExecutableMessage
    original: ExecutableMessage


def verification_buffer(message: ExecutableMessage) -> bytes:
    """The bytes an aleph sender signs. Confirmed against live network messages."""
    return f"{message.chain.value}\n{message.sender}\n{message.type.value}\n{message.item_hash}".encode()


def _signature_matches(message: ExecutableMessage) -> bool:
    try:
        recovered = Account.recover_message(encode_defunct(verification_buffer(message)), signature=message.signature)
    except Exception:
        logger.warning("Could not recover the signer of %s", message.item_hash, exc_info=True)
        return False
    return recovered.lower() == message.sender.lower()


def _parse(raw: dict) -> ExecutableMessage:
    """Parse and narrow to an executable message.

    parse_message returns the whole message union, so the type check is also
    what makes the narrowed return type honest.
    """
    message = parse_message(raw)
    if not isinstance(message, (InstanceMessage, ProgramMessage, VerifiableProgramMessage)):
        msg = f"message type {message.type} is not executable"
        raise ValueError(msg)
    return message


def verify_entry(entry: dict) -> tuple[VerificationOutcome, VerifiedMessage | None, str]:
    """Verify one plan entry.

    Returns (outcome, verified, reason). ``verified`` is set only for VERIFIED;
    ``reason`` is a safe, caller-facing string for REJECTED.
    """
    raw = entry.get("message")
    if not raw:
        return VerificationOutcome.UNVERIFIABLE, None, ""
    if raw.get("item_type") != ItemType.inline.value:
        return VerificationOutcome.UNVERIFIABLE, None, ""
    if raw.get("chain") not in EVM_CHAINS:
        return VerificationOutcome.UNVERIFIABLE, None, ""

    try:
        message = _parse(raw)
    except Exception as error:
        logger.warning("Refusing embedded message for %s: %s", entry.get("item_hash"), error)
        return VerificationOutcome.REJECTED, None, "message failed validation"

    if str(message.item_hash) != str(entry.get("item_hash")):
        logger.warning("Embedded message claims %s, plan lists %s", message.item_hash, entry.get("item_hash"))
        return VerificationOutcome.REJECTED, None, "message does not match the requested item_hash"

    if not _signature_matches(message):
        logger.warning("Embedded message %s is not signed by its sender", message.item_hash)
        return VerificationOutcome.REJECTED, None, "signature does not match the sender"

    return VerificationOutcome.VERIFIED, VerifiedMessage(message=message, original=message), ""
