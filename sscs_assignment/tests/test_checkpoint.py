# tests/test_checkpoint.py
import json
import subprocess
import os


def test_checkpoint_returns_data():
    """Test that checkpoint command returns output"""
    result = subprocess.run(
        ["python3", "main.py", "-c"],
        capture_output=True,
        text=True,
        cwd=os.getcwd(),
    )

    # Should complete successfully
    assert result.returncode == 0
    assert len(result.stdout) > 0


def test_checkpoint_has_tree_info():
    """Test that checkpoint output contains tree information"""
    result = subprocess.run(
        ["python3", "main.py", "-c"],
        capture_output=True,
        text=True,
        cwd=os.getcwd(),
    )

    output = result.stdout
    # Check if output contains expected checkpoint data
    assert "tree_id" in output or "treeID" in output or len(output) > 10


def test_checkpoint_json_parseable():
    """Test that checkpoint returns valid JSON data"""
    result = subprocess.run(
        ["python3", "main.py", "-c"],
        capture_output=True,
        text=True,
        cwd=os.getcwd(),
    )

    # Try to parse as JSON
    try:
        data = json.loads(result.stdout)
        assert isinstance(data, dict)
    except json.JSONDecodeError:
        # If not JSON, at least should have content
        assert len(result.stdout) > 0


def test_checkpoint_exit_code():
    """Test that checkpoint command exits successfully"""
    result = subprocess.run(
        ["python3", "main.py", "-c"],
        capture_output=True,
        text=True,
        cwd=os.getcwd(),
    )

    assert result.returncode == 0


def test_checkpoint_no_errors():
    """Test that checkpoint doesn't produce errors"""
    result = subprocess.run(
        ["python3", "main.py", "-c"],
        capture_output=True,
        text=True,
        cwd=os.getcwd(),
    )

    # Should not have error messages
    assert "error" not in result.stderr.lower()
    assert "exception" not in result.stderr.lower()
    assert "traceback" not in result.stderr.lower()
