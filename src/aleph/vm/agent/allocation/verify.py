"""Local verification of a message the scheduler embedded in its plan.

Two gates, only meaningful together:

1. aleph_message's validators enforce item_hash == sha256(item_content), so
   the hash binds the JSON the user actually signed.
2. The sender's signature covers "chain\\nsender\\ntype\\nitem_hash", so a
   valid signature proves the sender authorized exactly that JSON.

Those two gates bind item_content, and nothing else. A message also carries a
separate ``content`` field, and that is the one a caller reads. aleph_message
does not tie the two together for every type: ProgramMessage and
VerifiableProgramMessage have a check_content validator, InstanceMessage does
not. Left alone, a scheduler could therefore hand us a message carrying the
user's genuine item_content and signature next to a ``content`` of its own
choosing (more vCPUs, a different rootfs) and it would verify.

So we do not read the ``content`` the scheduler sent: it is replaced with the
JSON parsed out of item_content before the message is built. A divergent
``content`` is ignored rather than rejected, because comparing a parsed
pydantic model against raw JSON invites false rejections over defaults and
type coercion, while re-deriving cannot be wrong: what comes out is the signed
bytes or nothing.

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

import json
import logging
from copy import deepcopy
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

# Chains whose signatures we currently recover, not every EVM chain aleph
# supports. The enum also carries OP, ARB, POL, LINEA and more; a message on
# one of those is UNVERIFIABLE, which costs a CCN fetch and nothing else, so
# this set can grow whenever a chain is worth the fast path.
VERIFIABLE_CHAINS = {"ETH", "AVAX", "BASE", "BSC"}


class VerificationOutcome(Enum):
    VERIFIED = "verified"
    REJECTED = "rejected"
    UNVERIFIABLE = "unverifiable"


@dataclass(frozen=True)
class VerifiedMessage:
    """A message and an untouched copy of it.

    ``original`` is a deep copy, not the same object: a caller that resolves
    use_latest refs does so with update_message, which mutates the message in
    place, and an aliased original would be rewritten along with it.
    """

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

    The content is re-derived from item_content rather than taken from the
    ``content`` the sender of the plan supplied, so the parsed message can only
    ever hold what the signature covers.

    parse_message returns the whole message union, so the type check is also
    what makes the narrowed return type honest.
    """
    item_content = raw.get("item_content")
    if not isinstance(item_content, str):
        msg = "inline message without item_content"
        raise ValueError(msg)
    message = parse_message({**raw, "content": json.loads(item_content)})
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
    if not isinstance(raw, dict):
        # Everything else malformed answers REJECTED; a non-dict must not be
        # the one shape that escapes with an AttributeError instead.
        logger.warning("Refusing embedded message for %s: not an object", entry.get("item_hash"))
        return VerificationOutcome.REJECTED, None, "message is not an object"
    if raw.get("item_type") != ItemType.inline.value:
        return VerificationOutcome.UNVERIFIABLE, None, ""
    if raw.get("chain") not in VERIFIABLE_CHAINS:
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

    return VerificationOutcome.VERIFIED, VerifiedMessage(message=message, original=deepcopy(message)), ""
