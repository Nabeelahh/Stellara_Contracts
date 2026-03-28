// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/access/Ownable.sol";

/// @notice Simple on-chain revocation registry for credentials
contract RevocationRegistry is Ownable {
    // tokenContract => tokenId => revoked
    mapping(address => mapping(uint256 => bool)) public revoked;

    event RevocationSet(address indexed tokenContract, uint256 indexed tokenId, bool revoked);

    /// @dev Set revocation status for a token. Only owner (registry operator) can set.
    function setRevoked(address tokenContract, uint256 tokenId, bool isRevoked) external onlyOwner {
        revoked[tokenContract][tokenId] = isRevoked;
        emit RevocationSet(tokenContract, tokenId, isRevoked);
    }

    function isRevoked(address tokenContract, uint256 tokenId) external view returns (bool) {
        return revoked[tokenContract][tokenId];
    }
}
