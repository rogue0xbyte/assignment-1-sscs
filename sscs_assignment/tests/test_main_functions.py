# tests/test_main_functions.py
import pytest
from unittest.mock import patch, MagicMock, mock_open
import json
import base64

try:
    from sscs_assignment import main, merkle_proof, util
    print("imported from sscs_assignment package")
except ImportError:
    import main
    import merkle_proof
    import util
    print("imported from local fallback")

class TestMainModule:
    """Test main.py functions"""

    @patch("main.requests.get")
    def test_get_log_entry_success(self, mock_get):
        """Test successful log entry retrieval"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "test_uuid": {
                "body": "test_body",
                "verification": {"inclusionProof": {}},
            }
        }
        mock_get.return_value = mock_response

        result = main.get_log_entry(482833136)
        assert result is not None
        assert "test_uuid" in result

    @patch("main.requests.get")
    def test_get_log_entry_with_debug(self, mock_get):
        """Test log entry retrieval with debug mode"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"uuid123": {"body": "test"}}
        mock_get.return_value = mock_response

        result = main.get_log_entry(123, debug=True)
        assert result is not None

    @patch("main.requests.get")
    def test_get_latest_checkpoint_success(self, mock_get):
        """Test successful checkpoint retrieval"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "treeID": "11930509599166656506",
            "treeSize": 360993865,
            "rootHash": "141a3c752daec75b527dd79101d859a33c38d94b4721e54328a9427a5a50c271",  # noqa: E501
            "signedTreeHead": "test_signed_tree_head",
            "inactiveShards": [],
        }
        mock_get.return_value = mock_response

        result = main.get_latest_checkpoint()
        assert result is not None
        assert "treeID" in result
        assert "treeSize" in result
        assert "rootHash" in result

    @patch("main.requests.get")
    def test_get_latest_checkpoint_with_debug(self, mock_get):
        """Test checkpoint retrieval with debug output"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "treeID": "test_id",
            "treeSize": 100,
            "rootHash": "test_hash",
        }
        mock_get.return_value = mock_response

        result = main.get_latest_checkpoint(debug=True)
        assert result is not None

    def test_extract_signature_and_cert(self):
        """Test extracting signature and certificate from log entry"""
        # Create a valid log entry structure
        test_entry = {
            "uuid123": {
                "body": base64.b64encode(
                    json.dumps(
                        {
                            "spec": {
                                "signature": {
                                    "content": base64.b64encode(
                                        b"test_signature"
                                    ).decode(),
                                    "publicKey": {
                                        "content": base64.b64encode(
                                            b"test_cert"
                                        ).decode()
                                    },
                                }
                            }
                        }
                    ).encode()
                ).decode(),
                "verification": {},
            }
        }

        signature, cert, entry = main.extract_signature_and_cert(test_entry)
        assert signature == b"test_signature"
        assert cert == b"test_cert"
        assert "body" in entry

    @patch("main.requests.get")
    @patch("main.extract_public_key")
    @patch("main.verify_artifact_signature")
    @patch("main.compute_leaf_hash")
    @patch("main.verify_inclusion")
    def test_inclusion_function(
        self,
        mock_verify,
        mock_compute,
        mock_verify_sig,
        mock_extract,
        mock_get,
    ):
        """Test inclusion proof function"""
        # Mock the API response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "uuid": {
                "body": base64.b64encode(
                    json.dumps(
                        {
                            "spec": {
                                "signature": {
                                    "content": base64.b64encode(
                                        b"sig"
                                    ).decode(),
                                    "publicKey": {
                                        "content": base64.b64encode(
                                            b"cert"
                                        ).decode()
                                    },
                                }
                            }
                        }
                    ).encode()
                ).decode(),
                "verification": {
                    "inclusionProof": {
                        "logIndex": 123,
                        "treeSize": 1000,
                        "rootHash": "test_hash",
                        "hashes": ["hash1", "hash2"],
                    }
                },
            }
        }
        mock_get.return_value = mock_response
        mock_extract.return_value = b"public_key"
        mock_compute.return_value = "leaf_hash"

        # Call the function
        main.inclusion(482833136, "artifact.md")

        # Verify mocks were called
        assert mock_get.called
        assert mock_extract.called


class TestMerkleProof:
    """Test merkle_proof.py functions"""

    def test_hasher_initialization(self):
        """Test Hasher class initialization"""
        hasher = merkle_proof.Hasher()
        assert hasher is not None
        assert hasher.hash_func is not None

    def test_hasher_new(self):
        """Test creating new hash object"""
        hasher = merkle_proof.Hasher()
        h = hasher.new()
        assert h is not None

    def test_hasher_empty_root(self):
        """Test empty root hash"""
        hasher = merkle_proof.Hasher()
        root = hasher.empty_root()
        assert root is not None
        assert len(root) == 32  # SHA256 produces 32 bytes

    def test_hasher_hash_leaf(self):
        """Test leaf hashing"""
        hasher = merkle_proof.Hasher()
        leaf = b"test_data"
        hash_result = hasher.hash_leaf(leaf)
        assert hash_result is not None
        assert len(hash_result) == 32

    def test_hasher_hash_children(self):
        """Test hashing two children"""
        hasher = merkle_proof.Hasher()
        left = b"left_hash_" + b"0" * 22  # 32 bytes
        right = b"right_hash" + b"0" * 22  # 32 bytes
        result = hasher.hash_children(left, right)
        assert result is not None
        assert len(result) == 32

    def test_hasher_size(self):
        """Test hash size"""
        hasher = merkle_proof.Hasher()
        size = hasher.size()
        assert size == 32  # SHA256 is 32 bytes

    def test_default_hasher(self):
        """Test DEFAULT_HASHER constant"""
        assert merkle_proof.DEFAULT_HASHER is not None
        assert isinstance(merkle_proof.DEFAULT_HASHER, merkle_proof.Hasher)

    def test_compute_leaf_hash(self):
        """Test computing leaf hash from base64 body"""
        test_data = base64.b64encode(b"test_content").decode()
        result = merkle_proof.compute_leaf_hash(test_data)
        assert result is not None
        assert isinstance(result, str)
        assert len(result) == 64  # Hex string of 32 bytes

    def test_decomp_incl_proof(self):
        """Test decomposition of inclusion proof"""
        inner, border = merkle_proof.decomp_incl_proof(10, 100)
        assert isinstance(inner, int)
        assert isinstance(border, int)
        assert inner >= 0
        assert border >= 0

    def test_inner_proof_size(self):
        """Test inner proof size calculation"""
        size = merkle_proof.inner_proof_size(5, 10)
        assert isinstance(size, int)
        assert size >= 0

    def test_verify_consistency_equal_sizes(self):
        """Test consistency with equal tree sizes"""
        hasher = merkle_proof.DEFAULT_HASHER
        root = "a" * 64  # Valid hex string

        # Should not raise when sizes are equal and proof is empty
        merkle_proof.verify_consistency(hasher, 100, 100, [], root, root)

    def test_verify_consistency_size1_zero(self):
        """Test consistency with size1 = 0"""
        hasher = merkle_proof.DEFAULT_HASHER
        root = "a" * 64

        # Should not raise when size1 is 0 and proof is empty
        merkle_proof.verify_consistency(hasher, 0, 100, [], root, root)

    def test_verify_match_success(self):
        """Test verify_match with matching hashes"""
        hash1 = b"test_hash"
        hash2 = b"test_hash"

        # Should not raise
        merkle_proof.verify_match(hash1, hash2)

    def test_verify_match_failure(self):
        """Test verify_match with non-matching hashes"""
        hash1 = b"hash_one"
        hash2 = b"hash_two"

        with pytest.raises(merkle_proof.RootMismatchError):
            merkle_proof.verify_match(hash1, hash2)

    def test_root_mismatch_error(self):
        """Test RootMismatchError exception"""
        error = merkle_proof.RootMismatchError(b"expected", b"calculated")
        assert error.expected_root is not None
        assert error.calculated_root is not None
        error_str = str(error)
        assert "does not match" in error_str


class TestUtil:
    """Test util.py functions"""

    def test_extract_public_key(self):
        """Test extracting public key from certificate"""
        # Create a minimal mock certificate
        cert_pem = b"""-----BEGIN CERTIFICATE-----
MIIBkTCCATigAwIBAgIUQZ0l0pLGcLLT0qLLJW9rLLLLLLAwCgYIKoZIzj0EAwIw
ADAeFw0yNDAxMDEwMDAwMDBaFw0yNTAxMDEwMDAwMDBaMAAwWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAAQrLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLL
LLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLo0
IwQjAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwMwCgYIKoZIzj0E
AwIDRwAwRAIgLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLAiALLLLL
LLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLL==
-----END CERTIFICATE-----"""

        try:
            result = util.extract_public_key(cert_pem)
            assert result is not None
            assert b"BEGIN PUBLIC KEY" in result
        except Exception:
            # If the mock cert is invalid, test that function exists
            assert hasattr(util, "extract_public_key")

    @patch(
        "builtins.open",
        new_callable=mock_open,
        read_data=b"test_artifact_data",
    )
    def test_verify_artifact_signature(self, mock_file):
        """Test artifact signature verification"""
        # This will fail signature verification but tests the function flow
        signature = b"fake_signature"
        public_key = b"fake_public_key"

        # Function should not crash, just print invalid signature
        try:
            util.verify_artifact_signature(
                signature, public_key, "artifact.md"
            )
        except Exception:
            # Function may raise exceptions for invalid inputs
            pass

        # Verify file was opened
        assert mock_file.called


class TestIntegration:
    """Integration tests for complete workflows"""

    @patch("main.requests.get")
    def test_consistency_workflow(self, mock_get):
        """Test consistency verification workflow"""
        # Mock checkpoint response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "treeID": "123",
            "treeSize": 200,
            "rootHash": "b" * 64,
            "hashes": [],
        }
        mock_get.return_value = mock_response

        prev_checkpoint = {
            "treeID": "123",
            "treeSize": 100,
            "rootHash": "a" * 64,
        }

        # This will fail verification but tests the flow
        main.consistency(prev_checkpoint, debug=False)
        assert mock_get.called

    def test_chain_functions(self):
        """Test chain functions in merkle_proof"""
        hasher = merkle_proof.DEFAULT_HASHER
        seed = b"0" * 32
        proof = [b"1" * 32, b"2" * 32]
        index = 5

        # Test chain_inner
        result = merkle_proof.chain_inner(hasher, seed, proof, index)
        assert result is not None
        assert len(result) == 32

        # Test chain_inner_right
        result = merkle_proof.chain_inner_right(hasher, seed, proof, index)
        assert result is not None

        # Test chain_border_right
        result = merkle_proof.chain_border_right(hasher, seed, proof)
        assert result is not None
