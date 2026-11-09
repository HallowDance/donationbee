"""RFC 6962 Merkle tree over entry hashes, built incrementally from stored perfect subtrees.

Node (level, idx) is the root of leaves [idx << level, (idx + 1) << level). Only complete
subtrees are stored, so every stored node is final and the table is append-only.
"""

import hashlib
from typing import Protocol

EMPTY_ROOT = hashlib.sha256(b"").digest()


def leaf_hash(entry_hash: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + entry_hash).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


class NodeStore(Protocol):
    def get(self, level: int, idx: int) -> bytes: ...
    def put(self, level: int, idx: int, h: bytes) -> None: ...


class MemoryStore:
    def __init__(self) -> None:
        self.nodes: dict[tuple[int, int], bytes] = {}

    def get(self, level: int, idx: int) -> bytes:
        return self.nodes[(level, idx)]

    def put(self, level: int, idx: int, h: bytes) -> None:
        self.nodes[(level, idx)] = h


def append_leaf(store: NodeStore, index: int, entry_hash: bytes) -> None:
    """Add leaf `index` (must be the next one) and every subtree it completes."""
    level, idx, cur = 0, index, leaf_hash(entry_hash)
    store.put(0, idx, cur)
    while idx & 1:
        cur = node_hash(store.get(level, idx - 1), cur)
        level += 1
        idx >>= 1
        store.put(level, idx, cur)


def _split(n: int) -> int:
    """Largest power of two strictly less than n (n >= 2)."""
    return 1 << ((n - 1).bit_length() - 1)


def subtree_hash(store: NodeStore, start: int, end: int) -> bytes:
    n = end - start
    if n == 0:
        return EMPTY_ROOT
    if n & (n - 1) == 0 and start % n == 0:
        return store.get(n.bit_length() - 1, start // n)
    k = _split(n)
    return node_hash(subtree_hash(store, start, start + k), subtree_hash(store, start + k, end))


def root(store: NodeStore, size: int) -> bytes:
    return subtree_hash(store, 0, size)


def inclusion_proof(store: NodeStore, index: int, size: int) -> list[bytes]:
    """RFC 6962 §2.1.1 PATH(m, D[n]), leaf-to-root order."""
    if not 0 <= index < size:
        raise ValueError("index out of range")

    def path(m: int, start: int, end: int) -> list[bytes]:
        n = end - start
        if n == 1:
            return []
        k = _split(n)
        if m < k:
            return [*path(m, start, start + k), subtree_hash(store, start + k, end)]
        return [*path(m - k, start + k, end), subtree_hash(store, start, start + k)]

    return path(index, 0, size)


def consistency_proof(store: NodeStore, old: int, new: int) -> list[bytes]:
    """RFC 6962 §2.1.2 PROOF(m, D[n])."""
    if not 0 <= old <= new:
        raise ValueError("bad sizes")
    if old == 0 or old == new:
        return []

    def subproof(m: int, start: int, end: int, complete: bool) -> list[bytes]:
        n = end - start
        if m == n:
            return [] if complete else [subtree_hash(store, start, end)]
        k = _split(n)
        if m <= k:
            return [*subproof(m, start, start + k, complete), subtree_hash(store, start + k, end)]
        return [*subproof(m - k, start + k, end, False), subtree_hash(store, start, start + k)]

    return subproof(old, 0, new, True)
