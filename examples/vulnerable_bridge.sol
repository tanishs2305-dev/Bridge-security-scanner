// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

/**
 * This contract demonstrates multiple security vulnerabilities
 * commonly found in cross-chain bridge implementations
 */

contract VulnerableBridge {
    mapping(address => uint256) public balances;
    address public owner;
    
    // VULNERABILITY 1: Missing proper initialization - anyone can become owner
    function initialize() public {
        owner = msg.sender;
    }
    
    // VULNERABILITY 2: No access control on critical deposit function
    // VULNERABILITY 3: Integer overflow possible (old Solidity version)
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
    
    // VULNERABILITY 4: Reentrancy attack possible
    // VULNERABILITY 5: No checks on return value from call
    // State change happens AFTER external call (wrong order!)
    function withdraw(uint256 amount) public {
        msg.sender.call{value: amount}("");
        balances[msg.sender] -= amount;
    }
    
    // VULNERABILITY 6: Replay attack possible (no nonce/timestamp)
    // VULNERABILITY 7: No verification of cross-chain transaction
    function bridge(address to, uint256 amount) public {
        balances[msg.sender] -= amount;
        // Missing: Verification that funds were actually locked on source chain
    }
    
    // VULNERABILITY 8: Weak key generation using predictable randomness
    function generateKey() public view returns (bytes32) {
        return keccak256(abi.encodePacked(block.timestamp));
    }
}