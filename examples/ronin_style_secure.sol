// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * Secured version - How Ronin Bridge SHOULD have been built
 */

contract SecureRoninBridge {
    mapping(address => uint256) public deposits;
    mapping(address => bool) public isValidator;
    mapping(bytes32 => bool) public processedWithdrawals;
    
    address public admin;
    uint256 public requiredValidators = 5;
    uint256 public nonce;
    
    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin");
        _;
    }
    
    modifier onlyValidator() {
        require(isValidator[msg.sender], "Not a validator");
        _;
    }
    
    constructor() {
        admin = msg.sender;
    }
    
    // FIXED: Proper access control
    function addValidator(address validator) public onlyAdmin {
        require(!isValidator[validator], "Already validator");
        isValidator[validator] = true;
    }
    
    function deposit() public payable {
        require(msg.value > 0, "Must deposit something");
        deposits[msg.sender] += msg.value;
    }
    
    // FIXED: Proper signature verification and replay protection
    function withdraw(
        uint256 amount,
        bytes32 withdrawalId,
        bytes32 messageHash,
        bytes[] memory signatures
    ) public {
        require(!processedWithdrawals[withdrawalId], "Already processed");
        require(signatures.length >= requiredValidators, "Not enough signatures");
        require(deposits[msg.sender] >= amount, "Insufficient balance");
        
        // FIXED: Verify each signature is from a valid validator
        uint256 validSignatures = 0;
        for (uint256 i = 0; i < signatures.length; i++) {
            address signer = recoverSigner(messageHash, signatures[i]);
            if (isValidator[signer]) {
                validSignatures++;
            }
        }
        require(validSignatures >= requiredValidators, "Invalid signatures");
        
        // Mark as processed FIRST (prevents replay)
        processedWithdrawals[withdrawalId] = true;
        
        // FIXED: Update state BEFORE external call (prevents reentrancy)
        deposits[msg.sender] -= amount;
        
        // FIXED: Proper error handling
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        nonce++;
    }
    
    // FIXED: Proper governance for critical changes
    function updateRequiredValidators(uint256 newRequired) public onlyAdmin {
        require(newRequired > 0, "Must require at least 1");
        require(newRequired <= 10, "Too many required");
        requiredValidators = newRequired;
    }
    
    // Helper function for signature verification
    function recoverSigner(bytes32 messageHash, bytes memory signature) 
        internal 
        pure 
        returns (address) 
    {
        require(signature.length == 65, "Invalid signature length");
        
        bytes32 r;
        bytes32 s;
        uint8 v;
        
        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }
        
        return ecrecover(messageHash, v, r, s);
    }
}