"""
Implements Merkle proof verification and hashing logic
based on RFC 6962 (Certificate Transparency).
"""

import hashlib
import binascii
import base64

# domain separation prefixes according to the RFC
RFC6962_LEAF_HASH_PREFIX = 0
RFC6962_NODE_HASH_PREFIX = 1


class Hasher:
    """Hasher wrapper supporting RFC 6962 leaf and node hashing."""

    def __init__(self, hash_func=hashlib.sha256):
        """
        Initialize the hasher with a given hash function.

        Args:
            hash_func (callable): Hash function to use
                                  (default: hashlib.sha256).
        """
        self.hash_func = hash_func

    def new(self):
        """Return a new hash object."""
        return self.hash_func()

    def empty_root(self):
        """Return the digest for an empty Merkle tree."""
        return self.new().digest()

    def hash_leaf(self, leaf):
        """
        Compute the hash of a leaf node.

        Args:
            leaf (bytes): Leaf data.

        Returns:
            bytes: SHA256 digest of the leaf hash.
        """
        h = self.new()
        h.update(bytes([RFC6962_LEAF_HASH_PREFIX]))
        h.update(leaf)
        return h.digest()

    def hash_children(self, leaf, r):
        """
        Compute the hash of two child nodes.

        Args:
            leaf (bytes): Left child hash.
            r (bytes): Right child hash.

        Returns:
            bytes: Combined node hash.
        """
        h = self.new()
        b = bytes([RFC6962_NODE_HASH_PREFIX]) + leaf + r
        h.update(b)
        return h.digest()

    def size(self):
        """Return the size of the hash digest."""
        return self.new().digest_size


# DEFAULT_HASHER is a SHA256 based LogHasher
DEFAULT_HASHER = Hasher(hashlib.sha256)


def verify_consistency(hasher, size1, size2, proof, root1, root2):
    """
    Verify consistency proof between two tree roots.

    Args:
        hasher (Hasher): Hasher instance.
        size1 (int): Size of first tree.
        size2 (int): Size of second tree.
        proof (list): List of hex-encoded proof hashes.
        root1 (str): Old root hash in hex.
        root2 (str): New root hash in hex.
    """
    # change format of args to be bytearray instead of hex strings
    root1 = bytes.fromhex(root1)
    root2 = bytes.fromhex(root2)
    bytearray_proof = []
    for elem in proof:
        bytearray_proof.append(bytes.fromhex(elem))

    if size2 < size1:
        raise ValueError(f"size2 ({size2}) < size1 ({size1})")
    if size1 == size2:
        if bytearray_proof:
            raise ValueError("size1=size2, but bytearray_proof is not empty")
        verify_match(root1, root2)
        return
    if size1 == 0:
        if bytearray_proof:
            raise ValueError(
                "expected empty bytearray_proof, but"
                f" got {len(bytearray_proof)} components"
            )
        return
    if not bytearray_proof:
        raise ValueError("empty bytearray_proof")

    inner, border = decomp_incl_proof(size1 - 1, size2)
    shift = (size1 & -size1).bit_length() - 1
    inner -= shift

    if size1 == 1 << shift:
        seed, start = root1, 0
    else:
        seed, start = bytearray_proof[0], 1

    if len(bytearray_proof) != start + inner + border:
        raise ValueError(
            "wrong bytearray_proof size"
            f" {len(bytearray_proof)}, want {start + inner + border}"
        )

    bytearray_proof = bytearray_proof[start:]

    mask = (size1 - 1) >> shift
    hash1 = chain_inner_right(hasher, seed, bytearray_proof[:inner], mask)
    hash1 = chain_border_right(hasher, hash1, bytearray_proof[inner:])
    verify_match(hash1, root1)

    hash2 = chain_inner(hasher, seed, bytearray_proof[:inner], mask)
    hash2 = chain_border_right(hasher, hash2, bytearray_proof[inner:])
    verify_match(hash2, root2)


def verify_match(calculated, expected):
    """Raise RootMismatchError if calculated and expected roots differ."""
    if calculated != expected:
        raise RootMismatchError(expected, calculated)


def decomp_incl_proof(index, size):
    """Decompose proof size into inner and border components."""
    inner = inner_proof_size(index, size)
    border = bin(index >> inner).count("1")
    return inner, border


def inner_proof_size(index, size):
    """Return the number of inner proof nodes."""
    return (index ^ (size - 1)).bit_length()


def chain_inner(hasher, seed, proof, index):
    """Chain inner proof hashes in Merkle path."""
    for i, h in enumerate(proof):
        if (index >> i) & 1 == 0:
            seed = hasher.hash_children(seed, h)
        else:
            seed = hasher.hash_children(h, seed)
    return seed


def chain_inner_right(hasher, seed, proof, index):
    """Chain right-side proof nodes in Merkle path."""
    for i, h in enumerate(proof):
        if (index >> i) & 1 == 1:
            seed = hasher.hash_children(h, seed)
    return seed


def chain_border_right(hasher, seed, proof):
    """Append border proof nodes on the right."""
    for h in proof:
        seed = hasher.hash_children(h, seed)
    return seed


class RootMismatchError(Exception):
    """Raised when Merkle root verification fails."""

    def __init__(self, expected_root, calculated_root):
        """
        Initialize with expected and calculated root hashes.

        Args:
            expected_root (bytes): Expected root digest.
            calculated_root (bytes): Calculated root digest.
        """
        self.expected_root = binascii.hexlify(bytearray(expected_root))
        self.calculated_root = binascii.hexlify(bytearray(calculated_root))

    def __str__(self):
        """
        Return error as string.
        """
        return (
            f"calculated root:\n{self.calculated_root}\n does not"
            f" match expected root:\n{self.expected_root}"
        )


def root_from_inclusion_proof(hasher, index, size, leaf_hash, proof):
    """
    Compute the Merkle root from an inclusion proof.

    Args:
        hasher (Hasher): Hasher instance.
        index (int): Leaf index.
        size (int): Tree size.
        leaf_hash (bytes): Leaf hash.
        proof (list): Inclusion proof hashes.

    Returns:
        bytes: Calculated root hash.
    """
    if index >= size:
        raise ValueError(f"index is beyond size: {index} >= {size}")

    if len(leaf_hash) != hasher.size():
        raise ValueError(
            f"leaf_hash has unexpected size {len(leaf_hash)}, want {hasher.size()}"  # noqa: E501
        )

    inner, border = decomp_incl_proof(index, size)
    if len(proof) != inner + border:
        raise ValueError(
            f"wrong proof size {len(proof)}, want {inner + border}"
        )

    res = chain_inner(hasher, leaf_hash, proof[:inner], index)
    res = chain_border_right(hasher, res, proof[inner:])
    return res


def verify_inclusion(hasher, index, size, leaf_hash, proof, root, debug=False):
    """
    Verify inclusion proof for a leaf in a Merkle tree.

    Args:
        hasher (Hasher): Hasher instance.
        index (int): Leaf index.
        size (int): Tree size.
        leaf_hash (str): Leaf hash (hex).
        proof (list): Inclusion proof (hex-encoded hashes).
        root (str): Expected Merkle root (hex).
        debug (bool): Print debug info if True.
    """
    bytearray_proof = []
    for elem in proof:
        bytearray_proof.append(bytes.fromhex(elem))

    bytearray_root = bytes.fromhex(root)
    bytearray_leaf = bytes.fromhex(leaf_hash)
    calc_root = root_from_inclusion_proof(
        hasher, index, size, bytearray_leaf, bytearray_proof
    )
    verify_match(calc_root, bytearray_root)
    if debug:
        print("Calculated root hash", calc_root.hex())
        print("Given root hash", bytearray_root.hex())


# requires entry["body"] output for a log entry
# returns the leaf hash according to the rfc 6962 spec
def compute_leaf_hash(body):
    """
    Compute leaf hash for an entry according to RFC 6962.

    Args:
        body (str): Base64-encoded body of the log entry.

    Returns:
        str: Hexadecimal SHA256 leaf hash.
    """
    entry_bytes = base64.b64decode(body)

    # create a new sha256 hash object
    h = hashlib.sha256()
    # write the leaf hash prefix
    h.update(bytes([RFC6962_LEAF_HASH_PREFIX]))

    # write the actual leaf data
    h.update(entry_bytes)

    # return the computed hash
    return h.hexdigest()
