// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/access/Ownable.sol";

/// @notice Optimized on-chain revocation registry for credentials
/// @dev Uses bitmap packing to store 256 revocation statuses per storage slot
contract RevocationRegistry is Ownable {
    // tokenContract => bucketIndex => bitmap (256 tokens per slot)
    // bucketIndex = tokenId / 256, bit position = tokenId % 256
    mapping(address => mapping(uint256 => uint256)) private _revokedBitmap;

    // Cached count of revoked tokens per contract
    mapping(address => uint256) public revokedCount;

    event RevocationSet(address indexed tokenContract, uint256 indexed tokenId, bool revoked);
    event RevocationBatchSet(address indexed tokenContract, uint256 indexed fromTokenId, uint256 count);

    /// @dev Set revocation status for a single token
    function setRevoked(address tokenContract, uint256 tokenId, bool isRevoked) external onlyOwner {
        _setRevoked(tokenContract, tokenId, isRevoked);
    }

    /// @dev Batch set revocation status for multiple tokens
    function batchSetRevoked(
        address tokenContract,
        uint256[] calldata tokenIds,
        bool[] calldata isRevoked
    ) external onlyOwner {
        require(tokenIds.length == isRevoked.length, "array length mismatch");
        for (uint256 i = 0; i < tokenIds.length; ) {
            _setRevoked(tokenContract, tokenIds[i], isRevoked[i]);
            unchecked { ++i; }
        }
    }

    /// @dev Batch set revocation for a contiguous range of tokens
    function batchSetRevokedInRange(
        address tokenContract,
        uint256 fromTokenId,
        uint256 toTokenId,
        bool isRevoked
    ) external onlyOwner {
        require(fromTokenId <= toTokenId, "invalid range");
        for (uint256 i = fromTokenId; i <= toTokenId; ) {
            _setRevoked(tokenContract, i, isRevoked);
            unchecked { ++i; }
        }
    }

    /// @dev Convenience: revoke multiple tokens in one call
    function batchRevoke(address tokenContract, uint256[] calldata tokenIds) external onlyOwner {
        for (uint256 i = 0; i < tokenIds.length; ) {
            _setRevoked(tokenContract, tokenIds[i], true);
            unchecked { ++i; }
        }
    }

    /// @dev Convenience: unrevoke multiple tokens in one call
    function batchUnrevoke(address tokenContract, uint256[] calldata tokenIds) external onlyOwner {
        for (uint256 i = 0; i < tokenIds.length; ) {
            _setRevoked(tokenContract, tokenIds[i], false);
            unchecked { ++i; }
        }
    }

    /// @dev Check if a single token is revoked
    function isRevoked(address tokenContract, uint256 tokenId) public view returns (bool) {
        uint256 bucket = tokenId / 256;
        uint256 bit = tokenId % 256;
        return (_revokedBitmap[tokenContract][bucket] >> bit) & 1 == 1;
    }

    /// @dev Batch check revocation status for multiple tokens
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

    /// @dev Get revoked bitmap for a given token contract and bucket
    function getRevokedBitmap(address tokenContract, uint256 bucket) external view returns (uint256) {
        return _revokedBitmap[tokenContract][bucket];
    }

    /// @dev Get number of storage buckets used by a token contract
    function getBucketCount(address tokenContract) external view returns (uint256 count) {
        // Since revokedCount is stored separately, we estimate by scanning
        // In practice, this is a best-effort view
        uint256 total = revokedCount[tokenContract];
        if (total == 0) return 0;
        return (total + 255) / 256;
    }

    function _setRevoked(address tokenContract, uint256 tokenId, bool isRevoked) private {
        uint256 bucket = tokenId / 256;
        uint256 bit = tokenId % 256;
        uint256 mask = 1 << bit;
        uint256 current = _revokedBitmap[tokenContract][bucket];
        bool currentlyRevoked = (current >> bit) & 1 == 1;

        if (isRevoked != currentlyRevoked) {
            if (isRevoked) {
                _revokedBitmap[tokenContract][bucket] = current | mask;
                revokedCount[tokenContract]++;
            } else {
                _revokedBitmap[tokenContract][bucket] = current & ~mask;
                revokedCount[tokenContract]--;
            }
            emit RevocationSet(tokenContract, tokenId, isRevoked);
        }
    }
}
