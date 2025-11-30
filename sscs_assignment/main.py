"""
Command-line tool for verifying Rekor transparency log entries.

Supports:
    - Inclusion proof verification
    - Consistency proof verification
    - Fetching latest checkpoints
"""

import os
import sys
import base64
import json
import argparse
import requests

try:
    from util import extract_public_key, verify_artifact_signature
    from merkle_proof import (
        DEFAULT_HASHER,
        verify_consistency,
        verify_inclusion,
        compute_leaf_hash,
    )
except ModuleNotFoundError:
    from sscs_assignment.util import extract_public_key, verify_artifact_signature
    from sscs_assignment.merkle_proof import (
        DEFAULT_HASHER,
        verify_consistency,
        verify_inclusion,
        compute_leaf_hash,
    )

REKOR_BASE_URL = os.environ.get(
    "REKOR_BASE_URL", "https://rekor.sigstore.dev/api/v1"
)


def get_log_entry(log_index, debug=False):
    """
    Fetch a log entry from Rekor by index.

    Args:
        log_index (int): Log index to retrieve.
        debug (bool): Enable debug output.

    Returns:
        dict: Parsed log entry data.
    """

    # verify that log index value is sane
    if debug:
        print(f"fetching log entry {log_index}...")
    url = f"{REKOR_BASE_URL}/log/entries"
    params = {"logIndex": log_index}

    try:
        response = requests.get(url, params=params, timeout=(5, 15))
        response.raise_for_status()
        data = response.json()

        if data:
            first_key = list(data.keys())[0]
            if debug:
                print(f"entry uuid: {first_key}")
            entry = data[first_key]
            if debug:
                print(f"entry keys: {entry.keys()}")

        return data
    except requests.exceptions.RequestException as e:
        print(f"failed to fetch log entry: {e}")
        sys.exit(1)


def extract_signature_and_cert(log_entry):
    """
    Extract the signature and certificate from a Rekor log entry.

    Args:
        log_entry (dict): Rekor log entry.

    Returns:
        tuple: (signature_bytes, cert_bytes, entry_dict)
    """

    if not log_entry or not isinstance(log_entry, dict):
        print("empty or invalid log_entry received")
        sys.exit(1)

    entry_uuid = list(log_entry.keys())[0]
    entry = log_entry[entry_uuid]

    body = entry["body"]
    decoded_body = base64.b64decode(body)
    entry_data = json.loads(decoded_body)

    spec = entry_data["spec"]
    signature_b64 = spec["signature"]["content"]
    cert_b64 = spec["signature"]["publicKey"]["content"]

    signature = base64.b64decode(signature_b64)
    cert_data = base64.b64decode(cert_b64)

    return signature, cert_data, entry


def inclusion(log_index, artifact_filepath, debug=False):
    """
    Perform inclusion proof verification for an artifact.

    Args:
        log_index (int): Rekor log index.
        artifact_filepath (str): Path to artifact file.
        debug (bool): Enable debug mode.
    """

    signature, cert_data, entry = extract_signature_and_cert(
        get_log_entry(log_index)
    )
    public_key = extract_public_key(cert_data)

    try:
        verify_artifact_signature(signature, public_key, artifact_filepath)
        if debug:
            print("Signature is valid.")

    except (ValueError, TypeError) as e:
        if debug:
            print(f"Artifact signature verification failed: {e}")
        return False

    # get_verification_proof(log_index)

    log_index = entry["verification"]["inclusionProof"]["logIndex"]
    tree_size = entry["verification"]["inclusionProof"]["treeSize"]
    leaf_hash = compute_leaf_hash(entry["body"])
    hashes = entry["verification"]["inclusionProof"]["hashes"]
    root_hash = entry["verification"]["inclusionProof"]["rootHash"]

    try:
        verify_inclusion(
            DEFAULT_HASHER,
            log_index,
            tree_size,
            leaf_hash,
            hashes,
            root_hash,
        )
        print("Offline root hash calculation for inclusion verified.")

    except ValueError as e:
        print(f"Leaf inclusion verification failed: {e}")
        return False


def get_latest_checkpoint(debug=False):
    """
    Retrieve the latest Rekor checkpoint from the server.

    Args:
        debug (bool): Enable debug output.

    Returns:
        dict: Checkpoint data.
    """

    url = f"{REKOR_BASE_URL}/log"

    try:
        response = requests.get(url, timeout=(5, 15))
        response.raise_for_status()
        data = response.json()

        if len(data) < 1:
            print("latest checkpoint response nil")
            sys.exit(1)

        if debug:
            print("current checkpoint:")
            print(f"  tree_id: {data.get('treeID', 'N/A')}")
            print(f"  tree_size: {data.get('treeSize', 'N/A')}")
            print(f"  root_hash: {data.get('rootHash', 'N/A')}")

        return data
    except requests.exceptions.RequestException as e:
        print(f"failed to fetch checkpoint: {e}")
        sys.exit(1)


def consistency(prev_checkpoint, debug=False):
    """
    Verify consistency between a previous and the latest checkpoint.

    Args:
        prev_checkpoint (dict): Previous checkpoint data.
        debug (bool): Enable debug output.
    """

    current_checkpoint = get_latest_checkpoint()

    url = f"{REKOR_BASE_URL}/log/proof"
    params = {
        "firstSize": prev_checkpoint["treeSize"],
        "lastSize": current_checkpoint["treeSize"],
    }

    try:
        response = requests.get(url, params=params, timeout=(5, 15))
        response.raise_for_status()
        proof_data = response.json()

        verify_consistency(
            DEFAULT_HASHER,
            prev_checkpoint["treeSize"],
            current_checkpoint["treeSize"],
            proof_data["hashes"],
            prev_checkpoint["rootHash"],
            current_checkpoint["rootHash"],
        )

        if debug:
            print("Consistency verification successful.")

    except requests.exceptions.RequestException as e:
        print(f"Failed to get consistency proof: {e}")
        return False
    except ValueError as e:
        print(f"Consistency verification failed: {e}")
        return False


def main():
    """Main entry point for the Rekor Verifier CLI."""

    debug = False
    parser = argparse.ArgumentParser(description="Rekor Verifier")
    parser.add_argument(
        "-d",
        "--debug",
        help="Debug mode",
        required=False,
        action="store_true",
    )  # Default false
    parser.add_argument(
        "-c",
        "--checkpoint",
        help="Obtain latest checkpoint\
                        from Rekor Server public instance",
        required=False,
        action="store_true",
    )
    parser.add_argument(
        "--inclusion",
        help="Verify inclusion of an\
                        entry in the Rekor Transparency Log using log index\
                        and artifact filename.\
                        Usage: --inclusion 126574567",
        required=False,
        type=int,
    )
    parser.add_argument(
        "--artifact",
        help="Artifact filepath for verifying\
                        signature",
        required=False,
    )
    parser.add_argument(
        "--consistency",
        help="Verify consistency of a given\
                        checkpoint with the latest checkpoint.",
        action="store_true",
    )
    parser.add_argument(
        "--tree-id",
        help="Tree ID for consistency proof",
        required=False,
    )
    parser.add_argument(
        "--tree-size",
        help="Tree size for consistency proof",
        required=False,
        type=int,
    )
    parser.add_argument(
        "--root-hash",
        help="Root hash for consistency proof",
        required=False,
    )
    args = parser.parse_args()
    if args.debug:
        debug = True
        print("enabled debug mode")
    if args.checkpoint:
        # get and print latest checkpoint from server
        # if debug is enabled, store it in a file checkpoint.json
        checkpoint = get_latest_checkpoint(1)
        print(json.dumps(checkpoint, indent=4))
    if args.inclusion:
        inclusion(args.inclusion, args.artifact, debug)
    if args.consistency:
        if not args.tree_id:
            print("please specify tree id for prev checkpoint")
            return
        if not args.tree_size:
            print("please specify tree size for prev checkpoint")
            return
        if not args.root_hash:
            print("please specify root hash for prev checkpoint")
            return

        prev_checkpoint = {}
        prev_checkpoint["treeID"] = args.tree_id
        prev_checkpoint["treeSize"] = args.tree_size
        prev_checkpoint["rootHash"] = args.root_hash

        consistency(prev_checkpoint, debug)


if __name__ == "__main__":
    main()
