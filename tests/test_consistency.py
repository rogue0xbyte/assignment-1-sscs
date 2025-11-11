# tests/test_consistency.py
import sys
import json
import subprocess
import pytest
import os

def test_consistency_with_all_params():
    """Test consistency proof with all required parameters"""
    result = subprocess.run(
        ['python3', 'main.py', '--consistency', 
         '--tree-id', '11930509599166656506',
         '--tree-size', '360993865',
         '--root-hash', '141a3c752daec75b527dd79101d859a33c38d94b4721e54328a9427a5a50c271'],
        capture_output=True,
        text=True,
        cwd=os.getcwd()
    )
    
    # Should complete successfully
    assert result.returncode == 0

def test_consistency_verification_message():
    """Test that consistency produces verification output"""
    result = subprocess.run(
        ['python3', 'main.py', '--consistency', 
         '--tree-id', '11930509599166656506',
         '--tree-size', '360993865',
         '--root-hash', '141a3c752daec75b527dd79101d859a33c38d94b4721e54328a9427a5a50c271'],
        capture_output=True,
        text=True,
        cwd=os.getcwd()
    )
    
    # Should show verification message
    output = result.stdout.lower()
    assert "consistency" in output or "verification" in output or "successful" in output

def test_consistency_requires_root_hash():
    """Test that consistency requires root hash parameter"""
    result = subprocess.run(
        ['python3', 'main.py', '--consistency', 
         '--tree-id', '11930509599166656506',
         '--tree-size', '360993865'],
        capture_output=True,
        text=True,
        cwd=os.getcwd()
    )
    
    # Should mention missing root hash
    output = result.stdout.lower() + result.stderr.lower()
    assert "root hash" in output or "specify" in output

def test_consistency_requires_tree_id():
    """Test that consistency requires tree ID"""
    result = subprocess.run(
        ['python3', 'main.py', '--consistency', 
         '--tree-size', '360993865',
         '--root-hash', '141a3c752daec75b527dd79101d859a33c38d94b4721e54328a9427a5a50c271'],
        capture_output=True,
        text=True,
        cwd=os.getcwd()
    )
    
    # Should either fail or show error
    output = result.stdout.lower() + result.stderr.lower()
    assert result.returncode != 0 or "tree" in output or "required" in output

def test_consistency_requires_tree_size():
    """Test that consistency requires tree size"""
    result = subprocess.run(
        ['python3', 'main.py', '--consistency', 
         '--tree-id', '11930509599166656506',
         '--root-hash', '141a3c752daec75b527dd79101d859a33c38d94b4721e54328a9427a5a50c271'],
        capture_output=True,
        text=True,
        cwd=os.getcwd()
    )
    
    # Should either fail or show error
    output = result.stdout.lower() + result.stderr.lower()
    assert result.returncode != 0 or "size" in output or "required" in output