// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/// @notice Soulbound Token (SBT) with secure credential lifecycle enforcement.
/// @dev Revocation, expiration, and re-issuance are enforced consistently on all entry points.
contract SoulboundCredential is ERC721, Ownable {
    // tokenId => expiration timestamp (0 = no expiration)
    mapping(uint256 => uint64) public expiration;
    // tokenId => revoked
    mapping(uint256 => bool) public revoked;

    event CredentialIssued(address indexed to, uint256 indexed tokenId, uint64 expiresAt);
    event CredentialRevoked(uint256 indexed tokenId);
    event CredentialExpired(uint256 indexed tokenId);
    event CredentialRenewed(uint256 indexed tokenId, uint64 newExpiresAt);
    event CredentialReissued(address indexed to, uint256 indexed tokenId, uint64 expiresAt);

    constructor(string memory name_, string memory tokenSymbol_) ERC721(name_, tokenSymbol_) {}

    // ── Modifiers ──────────────────────────────────────────────────────

    modifier onlyIfNotRevoked(uint256 tokenId) {
        require(!revoked[tokenId], "SBT: credential revoked");
        _;
    }

    modifier onlyIfNotExpired(uint256 tokenId) {
        uint64 exp = expiration[tokenId];
        require(exp == 0 || uint64(block.timestamp) <= exp, "SBT: credential expired");
        _;
    }

    modifier onlyIfValid(uint256 tokenId) {
        require(_exists(tokenId), "SBT: token does not exist");
        require(!revoked[tokenId], "SBT: credential revoked");
        uint64 exp = expiration[tokenId];
        require(exp == 0 || uint64(block.timestamp) <= exp, "SBT: credential expired");
        _;
    }

    // ── Issuer functions ───────────────────────────────────────────────

    /// @dev Only issuer (owner) can mint new credentials.
    function issue(address to, uint256 tokenId, uint64 expiresAt) external onlyOwner {
        require(!_exists(tokenId), "SBT: token already exists");
        _safeMint(to, tokenId);
        expiration[tokenId] = expiresAt;
        emit CredentialIssued(to, tokenId, expiresAt);
    }

    /// @dev Issuer can revoke a credential.  Subsequent operations requiring validity
    ///      will revert via `onlyIfValid`.
    function revoke(uint256 tokenId) external onlyOwner onlyIfValid(tokenId) {
        revoked[tokenId] = true;
        emit CredentialRevoked(tokenId);
    }

    /// @dev Issuer can renew by extending or resetting the expiration window.
    ///      Cannot renew a revoked credential – use `reissue` instead.
    function renew(uint256 tokenId, uint64 newExpiresAt) external onlyOwner onlyIfValid(tokenId) {
        expiration[tokenId] = newExpiresAt;
        emit CredentialRenewed(tokenId, newExpiresAt);
    }

    /// @dev Re-issue a credential after revocation or expiration.
    ///      Burns the old token (if it still exists) and mints a fresh one to the new holder.
    function reissue(
        address newHolder,
        uint256 oldTokenId,
        uint256 newTokenId,
        uint64 expiresAt
    ) external onlyOwner {
        require(!_exists(newTokenId), "SBT: new token already exists");

        if (_exists(oldTokenId)) {
            _burn(oldTokenId);
            // Clean up state
            delete expiration[oldTokenId];
            delete revoked[oldTokenId];
        }

        _safeMint(newHolder, newTokenId);
        expiration[newTokenId] = expiresAt;
        emit CredentialReissued(newHolder, newTokenId, expiresAt);
    }

    // ── Transfer / approval overrides (all blocked) ────────────────────

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

    // ── View helpers ───────────────────────────────────────────────────

    /// @dev Returns true when the credential exists, is not revoked, and is not expired.
    function valid(uint256 tokenId) public view returns (bool) {
        if (!_exists(tokenId)) return false;
        if (revoked[tokenId]) return false;
        uint64 exp = expiration[tokenId];
        if (exp == 0) return true;
        return uint64(block.timestamp) <= exp;
    }

    /// @dev Returns true if the credential has been revoked.
    function isRevoked(uint256 tokenId) external view returns (bool) {
        return revoked[tokenId];
    }

    /// @dev Returns true if the credential is expired (regardless of revocation).
    function isExpired(uint256 tokenId) external view returns (bool) {
        uint64 exp = expiration[tokenId];
        if (exp == 0) return false;
        return uint64(block.timestamp) > exp;
    }
}
