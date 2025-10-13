import argparse, json, requests, base64, sys
from util import extract_public_key, verify_artifact_signature
from merkle_proof import DefaultHasher, verify_consistency, verify_inclusion, compute_leaf_hash

def get_log_entry(log_index, debug=False):
    # verify that log index value is sane
    print(f"fetching log entry {log_index}...")
    url = f"{REKOR_BASE_URL}/log/entries"
    params = {"logIndex": log_index}
    
    try:
        response = requests.get(url, params=params, timeout=(5, 15))
        response.raise_for_status()
        data = response.json()
        
        if data:
            first_key = list(data.keys())[0]
            print(f"entry uuid: {first_key}")
            entry = data[first_key]
            print(f"entry keys: {entry.keys()}")
            
        return data
    except requests.exceptions.RequestException as e:
        print(f"failed to fetch log entry: {e}")
        sys.exit(1)

def get_verification_proof(log_index, debug=False):
    # verify that log index value is sane
    pass

def extract_signature_and_cert(log_entry):

    if not log_entry or not isinstance(log_entry, dict):
        logger.warning("empty or invalid log_entry received")
        sys.exit(1)

    entry_uuid = list(log_entry.keys())[0]
    entry = log_entry[entry_uuid]
    
    body = entry['body']
    decoded_body = base64.b64decode(body)
    entry_data = json.loads(decoded_body)
    
    spec = entry_data['spec']
    signature_b64 = spec['signature']['content']
    cert_b64 = spec['signature']['publicKey']['content']
    
    signature = base64.b64decode(signature_b64)
    cert_data = base64.b64decode(cert_b64)
    
    return signature, cert_data, entry

def inclusion(log_index, artifact_filepath, debug=False):
    # verify that log index and artifact filepath values are sane

    signature, cert_data, entry = extract_signature_and_cert(get_log_entry(log_index))
    public_key = extract_public_key(cert_data)
        
    try:
        verification = verify_artifact_signature(signature, public_key, artifact_filepath)
        print("Signature is valid.")

    except Exception as e:
        print(f"Artifact signature verification failed: {e}")
        return False

     # get_verification_proof(log_index)

    log_index = entry['verification']['inclusionProof']['logIndex']
    tree_size = entry['verification']['inclusionProof']['treeSize']
    leaf_hash = compute_leaf_hash(entry['body'])
    hashes = entry['verification']['inclusionProof']['hashes']
    root_hash = entry['verification']['inclusionProof']['rootHash']

    try:
        verify_inclusion(DefaultHasher, log_index, tree_size, leaf_hash, hashes, root_hash)
        print("Offline root hash calculation for inclusion verified.")

    except Exception as e:
        print(f"Leaf inclusion verification failed: {e}")
        return False
    

def get_latest_checkpoint(debug=False):

    url = f"{REKOR_BASE_URL}/log"
    
    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()

        if len(data)<1:
            print(f"latest checkpoint response nil")
            sys.exit(1)

        
        if debug:
            print(f"current checkpoint:")
            print(f"  tree_id: {data.get('treeID', 'N/A')}")
            print(f"  tree_size: {data.get('treeSize', 'N/A')}")
            print(f"  root_hash: {data.get('rootHash', 'N/A')}")
        
        return data
    except requests.exceptions.RequestException as e:
        print(f"failed to fetch checkpoint: {e}")
        sys.exit(1)

def consistency(prev_checkpoint, debug=False):
    # verify that prev checkpoint is not empty

    current_checkpoint = get_latest_checkpoint()

    url = f"{REKOR_BASE_URL}/log/proof"
    params = {
        "firstSize": prev_checkpoint['treeSize'],
        "lastSize": current_checkpoint['treeSize']
    }
    
    try:
        response = requests.get(url, params=params)
        response.raise_for_status()
        proof_data = response.json()
        
        result = verify_consistency(DefaultHasher, prev_checkpoint['treeSize'], current_checkpoint['treeSize'],
                                  proof_data['hashes'], prev_checkpoint['rootHash'], current_checkpoint['rootHash'])
        
        print("Consistency verification successful.")

    except requests.exceptions.RequestException as e:
        print(f"Failed to get consistency proof: {e}")
        return False
    except Exception as e:
        print(f"Consistency verification failed: {e}")
        return False

def main():
    debug = False
    REKOR_BASE_URL = os.environ.get('REKOR_BASE_URL', "https://rekor.sigstore.dev/api/v1")
    parser = argparse.ArgumentParser(description="Rekor Verifier")
    parser.add_argument('-d', '--debug', help='Debug mode',
                        required=False, action='store_true') # Default false
    parser.add_argument('-c', '--checkpoint', help='Obtain latest checkpoint\
                        from Rekor Server public instance',
                        required=False, action='store_true')
    parser.add_argument('--inclusion', help='Verify inclusion of an\
                        entry in the Rekor Transparency Log using log index\
                        and artifact filename.\
                        Usage: --inclusion 126574567',
                        required=False, type=int)
    parser.add_argument('--artifact', help='Artifact filepath for verifying\
                        signature',
                        required=False)
    parser.add_argument('--consistency', help='Verify consistency of a given\
                        checkpoint with the latest checkpoint.',
                        action='store_true')
    parser.add_argument('--tree-id', help='Tree ID for consistency proof',
                        required=False)
    parser.add_argument('--tree-size', help='Tree size for consistency proof',
                        required=False, type=int)
    parser.add_argument('--root-hash', help='Root hash for consistency proof',
                        required=False)
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
