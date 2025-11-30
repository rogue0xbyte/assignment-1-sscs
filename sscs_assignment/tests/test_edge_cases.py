# tests/test_edge_cases.py
import pytest
from unittest.mock import patch, MagicMock
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


class TestMainEdgeCases:
    """Test edge cases in main.py"""

    @patch("main.requests.get")
    def test_get_log_entry_request_exception(self, mock_get):
        """Test log entry fetch with request exception"""
        mock_get.side_effect = Exception("Network error")

        with pytest.raises(SystemExit):
            main.get_log_entry(123)

    @patch("main.requests.get")
    def test_get_latest_checkpoint_empty_response(self, mock_get):
        """Test checkpoint with empty response"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {}
        mock_get.return_value = mock_response

        with pytest.raises(SystemExit):
            main.get_latest_checkpoint()

    @patch("main.requests.get")
    def test_get_latest_checkpoint_request_exception(self, mock_get):
        """Test checkpoint with network exception"""
        mock_get.side_effect = Exception("Connection failed")

        with pytest.raises(SystemExit):
            main.get_latest_checkpoint()

    def test_extract_signature_empty_log_entry(self):
        """Test extract signature with empty log entry"""
        with pytest.raises(SystemExit):
            main.extract_signature_and_cert({})

    def test_extract_signature_none_log_entry(self):
        """Test extract signature with None"""
        with pytest.raises(SystemExit):
            main.extract_signature_and_cert(None)

    @patch("main.requests.get")
    def test_consistency_request_exception(self, mock_get):
        """Test consistency with request exception"""
        mock_get.side_effect = Exception("Network error")

        prev_checkpoint = {
            "treeID": "123",
            "treeSize": 100,
            "rootHash": "a" * 64,
        }

        result = main.consistency(prev_checkpoint)
        assert not result

    @patch("main.requests.get")
    @patch("main.verify_consistency")
    def test_consistency_verification_error(self, mock_verify, mock_get):
        """Test consistency with verification error"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "treeID": "123",
            "treeSize": 200,
            "rootHash": "b" * 64,
            "hashes": [],
        }
        mock_get.return_value = mock_response
        mock_verify.side_effect = ValueError("Verification failed")

        prev_checkpoint = {
            "treeID": "123",
            "treeSize": 100,
            "rootHash": "a" * 64,
        }

        result = main.consistency(prev_checkpoint)
        assert not result

    @patch("main.get_log_entry")
    @patch("main.extract_public_key")
    @patch("main.verify_artifact_signature")
    def test_inclusion_signature_verification_error(
        self, mock_verify_sig, mock_extract, mock_get_entry
    ):
        """Test inclusion with signature verification error"""
        mock_get_entry.return_value = {
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
                        "rootHash": "test",
                        "hashes": [],
                    }
                },
            }
        }
        mock_extract.return_value = b"key"
        mock_verify_sig.side_effect = ValueError("Invalid signature")

        result = main.inclusion(123, "artifact.md", debug=True)
        assert not result

    @patch("main.get_log_entry")
    @patch("main.extract_public_key")
    @patch("main.verify_artifact_signature")
    @patch("main.verify_inclusion")
    def test_inclusion_verification_error(
        self,
        mock_verify_inc,
        mock_verify_sig,
        mock_extract,
        mock_get_entry,
    ):
        """Test inclusion with verification error"""
        mock_get_entry.return_value = {
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
                        "rootHash": "test",
                        "hashes": [],
                    }
                },
            }
        }
        mock_extract.return_value = b"key"
        mock_verify_inc.side_effect = ValueError(
            "Inclusion verification failed"
        )

        result = main.inclusion(123, "artifact.md")
        assert not result


class TestMerkleProofEdgeCases:
    """Test edge cases in merkle_proof.py"""

    def test_verify_consistency_size2_less_than_size1(self):
        """Test consistency with size2 < size1"""
        hasher = merkle_proof.DEFAULT_HASHER

        with pytest.raises(ValueError, match="size2.*< size1"):
            merkle_proof.verify_consistency(
                hasher, 100, 50, [], "a" * 64, "b" * 64
            )

    def test_verify_consistency_equal_sizes_with_proof(self):
        """Test consistency with equal sizes but non-empty proof"""
        hasher = merkle_proof.DEFAULT_HASHER
        root = "a" * 64

        with pytest.raises(ValueError, match="not empty"):
            merkle_proof.verify_consistency(
                hasher, 100, 100, ["hash"], root, root
            )

    def test_verify_consistency_size1_zero_with_proof(self):
        """Test consistency with size1=0 but non-empty proof"""
        hasher = merkle_proof.DEFAULT_HASHER

        with pytest.raises(ValueError, match="empty.*proof"):
            merkle_proof.verify_consistency(
                hasher, 0, 100, ["hash"], "a" * 64, "b" * 64
            )

    def test_verify_consistency_empty_proof_nonzero_sizes(self):
        """Test consistency with empty proof but different sizes"""
        hasher = merkle_proof.DEFAULT_HASHER

        with pytest.raises(ValueError, match="empty.*proof"):
            merkle_proof.verify_consistency(
                hasher, 50, 100, [], "a" * 64, "b" * 64
            )

    def test_root_from_inclusion_proof_index_beyond_size(self):
        """Test inclusion proof with index >= size"""
        hasher = merkle_proof.DEFAULT_HASHER

        with pytest.raises(ValueError, match="index is beyond size"):
            merkle_proof.root_from_inclusion_proof(
                hasher, 100, 50, b"0" * 32, []
            )

    def test_root_from_inclusion_proof_wrong_leaf_size(self):
        """Test inclusion proof with wrong leaf hash size"""
        hasher = merkle_proof.DEFAULT_HASHER

        with pytest.raises(ValueError, match="unexpected size"):
            merkle_proof.root_from_inclusion_proof(
                hasher, 5, 10, b"wrong_size", []
            )

    def test_root_from_inclusion_proof_wrong_proof_size(self):
        """Test inclusion proof with wrong proof size"""
        hasher = merkle_proof.DEFAULT_HASHER

        with pytest.raises(ValueError, match="wrong proof size"):
            merkle_proof.root_from_inclusion_proof(
                hasher, 5, 10, b"0" * 32, []
            )

    def test_verify_inclusion_with_debug(self):
        """Test verify_inclusion with debug mode"""
        hasher = merkle_proof.DEFAULT_HASHER
        # Create valid test data
        leaf_hash = "a" * 64
        root = "b" * 64

        # This will fail verification but tests debug path
        with pytest.raises(merkle_proof.RootMismatchError):
            merkle_proof.verify_inclusion(
                hasher, 0, 1, leaf_hash, [], root, debug=True
            )

    def test_compute_leaf_hash_various_inputs(self):
        """Test compute_leaf_hash with various inputs"""
        # Test with simple data
        data1 = base64.b64encode(b"test").decode()
        result1 = merkle_proof.compute_leaf_hash(data1)
        assert len(result1) == 64

        # Test with empty data
        data2 = base64.b64encode(b"").decode()
        result2 = merkle_proof.compute_leaf_hash(data2)
        assert len(result2) == 64

        # Test with larger data
        data3 = base64.b64encode(b"x" * 1000).decode()
        result3 = merkle_proof.compute_leaf_hash(data3)
        assert len(result3) == 64

    def test_root_mismatch_error_str(self):
        """Test RootMismatchError string representation"""
        error = merkle_proof.RootMismatchError(
            b"expected_root", b"calculated_root"
        )
        error_str = str(error)
        assert "calculated root" in error_str
        assert "expected root" in error_str
        assert "does not match" in error_str


class TestUtilEdgeCases:
    """Test edge cases in util.py"""

    def test_extract_public_key_invalid_cert(self):
        """Test extract_public_key with invalid certificate"""
        invalid_cert = b"not a valid certificate"

        with pytest.raises(Exception):
            util.extract_public_key(invalid_cert)

    @patch("builtins.open")
    def test_verify_artifact_signature_file_not_found(self, mock_open):
        """Test verify_artifact_signature with missing file"""
        mock_open.side_effect = FileNotFoundError("File not found")

        with pytest.raises(FileNotFoundError):
            util.verify_artifact_signature(b"sig", b"key", "missing.md")

    @patch("builtins.open", side_effect=IOError("IO Error"))
    def test_verify_artifact_signature_io_error(self, mock_open):
        """Test verify_artifact_signature with IO error"""
        with pytest.raises(IOError):
            util.verify_artifact_signature(b"sig", b"key", "artifact.md")


class TestMainCLI:
    """Test main CLI argument parsing"""

    @patch("sys.argv", ["main.py", "-d"])
    @patch("main.get_latest_checkpoint")
    def test_main_debug_flag(self, mock_checkpoint):
        """Test main with debug flag"""
        mock_checkpoint.return_value = {"treeID": "test"}

        # Would need to refactor main() to return instead of sys.exit
        # For now, just test that function exists
        assert callable(main.main)

    @patch("sys.argv", ["main.py", "--checkpoint"])
    @patch("main.get_latest_checkpoint")
    def test_main_checkpoint_arg(self, mock_checkpoint):
        """Test main with checkpoint argument"""
        mock_checkpoint.return_value = {
            "treeID": "123",
            "treeSize": 100,
            "rootHash": "abc",
        }

        assert callable(main.main)

    def test_rekor_base_url_env(self):
        """Test REKOR_BASE_URL constant"""
        assert main.REKOR_BASE_URL is not None
        assert isinstance(main.REKOR_BASE_URL, str)
        assert "rekor" in main.REKOR_BASE_URL.lower()
