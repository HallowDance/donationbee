"""RFC 6962 / RFC 9162 Merkle tree verification. Written from the RFCs, not from `vpp`."""

import hashlib

EMPTY_ROOT = hashlib.sha256(b"").digest()


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def root_from_leaves(leaves: list[bytes]) -> bytes:
    """MTH over leaf *hashes* (already 0x00-prefixed and hashed). O(n), for verifiers that hold
    every entry anyway."""
    if not leaves:
        return EMPTY_ROOT
    # Stack of (height, hash) for perfect subtrees, merged right to left at the end.
    stack: list[tuple[int, bytes]] = []
    for h in leaves:
        height, cur = 0, h
        while stack and stack[-1][0] == height:
            _, left = stack.pop()
            cur = node_hash(left, cur)
            height += 1
        stack.append((height, cur))
    _, acc = stack.pop()
    while stack:
        _, left = stack.pop()
        acc = node_hash(left, acc)
    return acc


def verify_inclusion(leaf: bytes, index: int, size: int, proof: list[bytes], root: bytes) -> bool:
    """RFC 9162 §2.1.3.2. `leaf` is the leaf hash."""
    if index >= size or index < 0:
        return False
    fn, sn, r = index, size - 1, leaf
    for p in proof:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def verify_consistency(
    size1: int, size2: int, root1: bytes, root2: bytes, proof: list[bytes]
) -> bool:
    """RFC 9162 §2.1.4.2, plus the trivial cases tlog-witness spells out."""
    if size1 < 0 or size1 > size2:
        return False
    if size1 == size2:
        return not proof and root1 == root2
    if size1 == 0:
        return not proof
    if not proof:
        return False
    if size1 & (size1 - 1) == 0:  # exact power of two: old root is the first node
        proof = [root1, *proof]
    fn, sn = size1 - 1, size2 - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = proof[0]
    for c in proof[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return fr == root1 and sr == root2 and sn == 0
