// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * This contract demonstrates security best practices
 * for cross-chain bridge implementations
 */

contract SecureBridge {
    mapping(address => uint256) public balances;
    mapping(bytes32 => bool) public processedTransactions;
    address public owner;
    uint256 public nonce;
    
    // Proper access control modifier
    modifier onlyOwner() {
        require(msg.sender == owner, "Not authorized");
        _;
    }
    
    // Constructor sets owner properly
    constructor() {
        owner = msg.sender;
    }
    
    // Safe deposit with event emission
    function deposit() public payable {
        require(msg.value > 0, "Must deposit something");
        balances[msg.sender] += msg.value;
        emit Deposited(msg.sender, msg.value);
    }
    
    // Safe withdrawal with checks-effects-interactions pattern
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // Update state BEFORE external call (prevents reentrancy)
        balances[msg.sender] -= amount;
        
        // Safe external call with proper error handling
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        emit Withdrawn(msg.sender, amount);
    }
    
    // Replay-protected bridge function with nonce
    function bridge(address to, uint256 amount, bytes32 txHash) public {
        require(!processedTransactions[txHash], "Transaction already processed");
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // Mark transaction as processed (prevents replay)
        processedTransactions[txHash] = true;
        balances[msg.sender] -= amount;
        
        nonce++;
        emit Bridged(msg.sender, to, amount, nonce);
    }
    
    // Events for transparency
    event Deposited(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);
    event Bridged(address indexed from, address indexed to, uint256 amount, uint256 nonce);
}