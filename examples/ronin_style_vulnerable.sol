// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;

/**
 * Simplified recreation of Ronin Bridge vulnerability
 * This contract has CRITICAL security flaws similar to the real hack
 */

contract RoninStyleBridge {
    mapping(address => uint256) public deposits;
    address[] public validators;
    mapping(bytes32 => bool) public processedWithdrawals;
    
    uint256 public requiredValidators = 5;
    
    // VULNERABILITY 1: No proper access control on adding validators
    function addValidator(address validator) public {
        validators.push(validator);
    }
    
    // VULNERABILITY 2: Weak signature verification
    // In real Ronin hack, attackers compromised validator keys
    function deposit() public payable {
        deposits[msg.sender] += msg.value;
    }
    
    // VULNERABILITY 3: No nonce/replay protection
    // VULNERABILITY 4: Insufficient validator checks
    function withdraw(
        uint256 amount,
        bytes32 withdrawalId,
        bytes[] memory signatures
    ) public {
        require(!processedWithdrawals[withdrawalId], "Already processed");
        
        // CRITICAL FLAW: Only checks signature count, not validity!
        require(signatures.length >= requiredValidators, "Not enough signatures");
        
        // Missing: Actual signature verification!
        // Missing: Check if signers are valid validators!
        
        processedWithdrawals[withdrawalId] = true;
        
        // VULNERABILITY 5: External call before state change (reentrancy)
        msg.sender.call{value: amount}("");
        deposits[msg.sender] -= amount;
    }
    
    // VULNERABILITY 6: Validators can be changed without proper governance
    function updateRequiredValidators(uint256 newRequired) public {
        requiredValidators = newRequired;
    }
    
    // VULNERABILITY 7: Weak randomness for transaction ID
    function generateWithdrawalId(uint256 amount) public view returns (bytes32) {
        return keccak256(abi.encodePacked(block.timestamp, amount));
    }
}