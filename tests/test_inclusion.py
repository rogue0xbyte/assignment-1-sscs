# tests/test_inclusion.py
import sys
import json
import subprocess
import pytest
import os

def test_inclusion_with_valid_params():
    """Test inclusion proof with valid log ID and artifact"""
    result = subprocess.run(
        ['python3', 'main.py', '--inclusion', '482833136', '--artifact', 'artifact.md'],
        capture_output=True,
        text=True,
        cwd=os.getcwd()
    )
    
    # Should complete successfully
    assert result.returncode == 0

def test_inclusion_verification_output():
    """Test that inclusion proof produces verification output"""
    result = subprocess.run(
        ['python3', 'main.py', '--inclusion', '482833136', '--artifact', 'artifact.md'],
        capture_output=True,
        text=True,
        cwd=os.getcwd()
    )
    
    # Should mention verification
    output = result.stdout.lower()
    assert "verified" in output or "signature" in output or "inclusion" in output

def test_inclusion_offline_verification():
    """Test that inclusion performs offline verification"""
    result = subprocess.run(
        ['python3', 'main.py', '--inclusion', '482833136', '--artifact', 'artifact.md'],
        capture_output=True,
        text=True,
        cwd=os.getcwd()
    )
    
    # Should mention offline verification
    assert "offline" in result.stdout.lower() or "root hash" in result.stdout.lower()

def test_inclusion_requires_artifact():
    """Test that inclusion requires artifact parameter"""
    result = subprocess.run(
        ['python3', 'main.py', '--inclusion', '482833136'],
        capture_output=True,
        text=True,
        cwd=os.getcwd()
    )
    
    # Should either fail or show error about missing artifact
    assert result.returncode != 0 or "artifact" in result.stderr.lower() or "required" in result.stderr.lower()

def test_inclusion_with_nonexistent_artifact():
    """Test inclusion with file that doesn't exist"""
    result = subprocess.run(
        ['python3', 'main.py', '--inclusion', '482833136', '--artifact', 'nonexistent_file.md'],
        capture_output=True,
        text=True,
        cwd=os.getcwd()
    )
    
    # Should handle error - either return code or error message
    if result.returncode == 0:
        # If it returns 0, check for error in output
        assert "error" in result.stderr.lower() or "not found" in result.stderr.lower() or len(result.stderr) > 0
    else:
        assert result.returncode != 0