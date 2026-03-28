// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/// @notice Minimal Soulbound Token (SBT) implementation
contract SoulboundCredential is ERC721, Ownable {
    // tokenId -> expiration timestamp (0 = no expiration)
    mapping(uint256 => uint64) public expiration;
    // tokenId -> revoked
    mapping(uint256 => bool) public revoked;

    event Issued(address indexed to, uint256 indexed tokenId, uint64 expiresAt);
    event Revoked(uint256 indexed tokenId);
    event Renewed(uint256 indexed tokenId, uint64 expiresAt);

    constructor(string memory name_, string memory symbol_) ERC721(name_, symbol_) {}

    /// @dev Only owner (issuer) can mint SBTs
    function issue(address to, uint256 tokenId, uint64 expiresAt) external onlyOwner {
        _safeMint(to, tokenId);
        expiration[tokenId] = expiresAt;
        emit Issued(to, tokenId, expiresAt);
    }

    /// @dev Owner/issuer can revoke a credential
    function revoke(uint256 tokenId) external onlyOwner {
        require(_exists(tokenId), "SBT: token not exist");
        revoked[tokenId] = true;
        emit Revoked(tokenId);
    }

    /// @dev Owner/issuer can renew by updating expiration
    function renew(uint256 tokenId, uint64 expiresAt) external onlyOwner {
        require(_exists(tokenId), "SBT: token not exist");
        expiration[tokenId] = expiresAt;
        emit Renewed(tokenId, expiresAt);
    }

    /// @dev Non-transferable: block all transfers and approvals
    function _transfer(address, address, uint256) internal pure override {
        revert("SBT: non-transferable");
    }

    function approve(address, uint256) public pure override {
        revert("SBT: approvals disabled");
    }

    function setApprovalForAll(address, bool) public pure override {
        revert("SBT: approvals disabled");
    }

    function safeTransferFrom(address, address, uint256) public pure override {
        revert("SBT: non-transferable");
    }

    function safeTransferFrom(address, address, uint256, bytes memory) public pure override {
        revert("SBT: non-transferable");
    }

    /// @dev Helper: check if credential is valid (not revoked and not expired)
    function valid(uint256 tokenId) public view returns (bool) {
        if (revoked[tokenId]) return false;
        uint64 exp = expiration[tokenId];
        if (exp == 0) return true;
        return uint64(block.timestamp) <= exp;
    }
}
