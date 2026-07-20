// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/access/Ownable.sol";

/// @notice Optimized on-chain revocation registry for credentials.
/// @dev Uses bitmap packing to store 256 revocation statuses per storage slot.
///      Supports optional per-token revocation expiry (time-based revocation).
contract RevocationRegistry is Ownable {
    // tokenContract => bucketIndex => bitmap (256 tokens per slot)
    // bucketIndex = tokenId / 256, bit position = tokenId % 256
    mapping(address => mapping(uint256 => uint256)) private _revokedBitmap;

    // tokenContract => tokenId => expiry timestamp (0 = no expiry / permanent)
    mapping(address => mapping(uint256 => uint256)) public revocationExpiry;

    // Cached count of revoked tokens per contract
    mapping(address => uint256) public revokedCount;

    event RevocationSet(
        address indexed tokenContract,
        uint256 indexed tokenId,
        bool revoked,
        uint256 expiry
    );
    event RevocationBatchSet(
        address indexed tokenContract,
        uint256 indexed fromTokenId,
        uint256 count,
        uint256 expiry
    );
    event RevocationBatchCleared(address indexed tokenContract, uint256 count);

    // ── Single operations ─────────────────────────────────────────────

    /// @dev Set revocation status for a single token (permanent revocation).
    function setRevoked(address tokenContract, uint256 tokenId, bool isRevoked) external onlyOwner {
        _setRevoked(tokenContract, tokenId, isRevoked, 0);
    }

    /// @dev Set revocation with an expiry timestamp.
    ///      Once `expiry` passes the token is automatically considered un-revoked.
    function setRevokedWithExpiry(
        address tokenContract,
        uint256 tokenId,
        bool isRevoked,
        uint256 expiry
    ) external onlyOwner {
        _setRevoked(tokenContract, tokenId, isRevoked, expiry);
    }

    // ── Batch operations ──────────────────────────────────────────────

    /// @dev Batch set revocation status for multiple tokens (permanent).
    function batchSetRevoked(
        address tokenContract,
        uint256[] calldata tokenIds,
        bool[] calldata isRevoked
    ) external onlyOwner {
        require(tokenIds.length == isRevoked.length, "array length mismatch");
        for (uint256 i = 0; i < tokenIds.length; ) {
            _setRevoked(tokenContract, tokenIds[i], isRevoked[i], 0);
            unchecked { ++i; }
        }
    }

    /// @dev Batch set revocation with per-token expiry.
    function batchSetRevokedWithExpiry(
        address tokenContract,
        uint256[] calldata tokenIds,
        bool[] calldata isRevoked,
        uint256[] calldata expiries
    ) external onlyOwner {
        require(tokenIds.length == isRevoked.length, "array length mismatch");
        require(tokenIds.length == expiries.length, "expiry array length mismatch");
        for (uint256 i = 0; i < tokenIds.length; ) {
            _setRevoked(tokenContract, tokenIds[i], isRevoked[i], expiries[i]);
            unchecked { ++i; }
        }
    }

    /// @dev Batch set revocation for a contiguous range of tokens (permanent).
    function batchSetRevokedInRange(
        address tokenContract,
        uint256 fromTokenId,
        uint256 toTokenId,
        bool isRevoked
    ) external onlyOwner {
        require(fromTokenId <= toTokenId, "invalid range");
        uint256 count = 0;
        for (uint256 i = fromTokenId; i <= toTokenId; ) {
            _setRevoked(tokenContract, i, isRevoked, 0);
            unchecked { ++i; ++count; }
        }
        if (isRevoked) {
            emit RevocationBatchSet(tokenContract, fromTokenId, count, 0);
        }
    }

    /// @dev Batch set revocation for a contiguous range with a shared expiry.
    function batchSetRevokedInRangeWithExpiry(
        address tokenContract,
        uint256 fromTokenId,
        uint256 toTokenId,
        bool isRevoked,
        uint256 expiry
    ) external onlyOwner {
        require(fromTokenId <= toTokenId, "invalid range");
        uint256 count = 0;
        for (uint256 i = fromTokenId; i <= toTokenId; ) {
            _setRevoked(tokenContract, i, isRevoked, expiry);
            unchecked { ++i; ++count; }
        }
        if (isRevoked) {
            emit RevocationBatchSet(tokenContract, fromTokenId, count, expiry);
        }
    }

    /// @dev Convenience: revoke multiple tokens in one call.
    function batchRevoke(address tokenContract, uint256[] calldata tokenIds) external onlyOwner {
        for (uint256 i = 0; i < tokenIds.length; ) {
            _setRevoked(tokenContract, tokenIds[i], true, 0);
            unchecked { ++i; }
        }
    }

    /// @dev Convenience: unrevoke multiple tokens in one call.
    function batchUnrevoke(address tokenContract, uint256[] calldata tokenIds) external onlyOwner {
        for (uint256 i = 0; i < tokenIds.length; ) {
            _setRevoked(tokenContract, tokenIds[i], false, 0);
            unchecked { ++i; }
        }
    }

    /// @dev Clear all revocation state for a contract (resets bitmap + count).
    function clearAll(address tokenContract) external onlyOwner {
        uint256 count = revokedCount[tokenContract];
        if (count == 0) return;
        // Reset bitmap buckets
        uint256 buckets = (count + 255) / 256;
        for (uint256 i = 0; i < buckets; ) {
            _revokedBitmap[tokenContract][i] = 0;
            unchecked { ++i; }
        }
        revokedCount[tokenContract] = 0;
        emit RevocationBatchCleared(tokenContract, count);
    }

    // ── Query functions ───────────────────────────────────────────────

    /// @dev Check if a single token is revoked.
    ///      Returns false if the revocation has expired.
    function isRevoked(address tokenContract, uint256 tokenId) public view returns (bool) {
        uint256 bucket = tokenId / 256;
        uint256 bit = tokenId % 256;
        bool bitSet = (_revokedBitmap[tokenContract][bucket] >> bit) & 1 == 1;
        if (!bitSet) return false;
        // Check time-based expiry
        uint256 exp = revocationExpiry[tokenContract][tokenId];
        if (exp != 0 && block.timestamp > exp) return false;
        return true;
    }

    /// @dev Batch check revocation status for multiple tokens.
    function batchIsRevoked(
        address tokenContract,
        uint256[] calldata tokenIds
    ) external view returns (bool[] memory results) {
        results = new bool[](tokenIds.length);
        for (uint256 i = 0; i < tokenIds.length; ) {
            results[i] = isRevoked(tokenContract, tokenIds[i]);
            unchecked { ++i; }
        }
    }

    /// @dev Get revoked bitmap for a given token contract and bucket.
    function getRevokedBitmap(address tokenContract, uint256 bucket) external view returns (uint256) {
        return _revokedBitmap[tokenContract][bucket];
    }

    // ── Internal ──────────────────────────────────────────────────────

    function _setRevoked(
        address tokenContract,
        uint256 tokenId,
        bool isRevoked,
        uint256 expiry
    ) private {
        uint256 bucket = tokenId / 256;
        uint256 bit = tokenId % 256;
        uint256 mask = 1 << bit;
        uint256 current = _revokedBitmap[tokenContract][bucket];
        bool currentlyRevoked = (current >> bit) & 1 == 1;

        if (isRevoked != currentlyRevoked) {
            if (isRevoked) {
                _revokedBitmap[tokenContract][bucket] = current | mask;
                revokedCount[tokenContract]++;
                revocationExpiry[tokenContract][tokenId] = expiry;
            } else {
                _revokedBitmap[tokenContract][bucket] = current & ~mask;
                revokedCount[tokenContract]--;
                delete revocationExpiry[tokenContract][tokenId];
            }
            emit RevocationSet(tokenContract, tokenId, isRevoked, expiry);
        }
    }
}
