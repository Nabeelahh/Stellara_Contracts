const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("RevocationRegistry (Optimized)", function () {
  let owner, user, tokenContract;
  let registry;

  beforeEach(async () => {
    [owner, user] = await ethers.getSigners();
    tokenContract = ethers.Wallet.createRandom().address;

    const Registry = await ethers.getContractFactory("RevocationRegistry");
    registry = await Registry.deploy();
    await registry.waitForDeployment();
  });

  describe("Single operations", function () {
    it("should set and read revocation status", async () => {
      await registry.setRevoked(tokenContract, 1, true);
      expect(await registry.isRevoked(tokenContract, 1)).to.equal(true);
      expect(await registry.revokedCount(tokenContract)).to.equal(1n);
    });

    it("should unrevoke a token", async () => {
      await registry.setRevoked(tokenContract, 1, true);
      await registry.setRevoked(tokenContract, 1, false);
      expect(await registry.isRevoked(tokenContract, 1)).to.equal(false);
      expect(await registry.revokedCount(tokenContract)).to.equal(0n);
    });

    it("should not emit event if status unchanged", async () => {
      await expect(registry.setRevoked(tokenContract, 1, false))
        .to.not.emit(registry, "RevocationSet");
    });

    it("should revert non-owner calls", async () => {
      await expect(
        registry.connect(user).setRevoked(tokenContract, 1, true)
      ).to.be.revertedWith("Ownable: caller is not the owner");
    });
  });

  describe("Bitmap storage packing", function () {
    it("should store 256 tokens in one storage slot", async () => {
      for (let i = 0; i < 256; i++) {
        await registry.setRevoked(tokenContract, i, true);
      }
      expect(await registry.revokedCount(tokenContract)).to.equal(256n);
      expect(await registry.getRevokedBitmap(tokenContract, 0)).to.equal(
        ethers.MaxUint256
      );
    });

    it("should handle tokens across multiple buckets", async () => {
      await registry.setRevoked(tokenContract, 0, true);
      await registry.setRevoked(tokenContract, 256, true);
      await registry.setRevoked(tokenContract, 512, true);
      expect(await registry.getRevokedBitmap(tokenContract, 0)).to.equal(1n);
      expect(await registry.getRevokedBitmap(tokenContract, 1)).to.equal(1n);
      expect(await registry.getRevokedBitmap(tokenContract, 2)).to.equal(1n);
      expect(await registry.revokedCount(tokenContract)).to.equal(3n);
    });
  });

  describe("Batch operations", function () {
    it("should batch revoke tokens", async () => {
      const ids = [1, 2, 3, 4, 5];
      await registry.batchRevoke(tokenContract, ids);
      for (const id of ids) {
        expect(await registry.isRevoked(tokenContract, id)).to.equal(true);
      }
      expect(await registry.revokedCount(tokenContract)).to.equal(5n);
    });

    it("should batch unrevoke tokens", async () => {
      const ids = [1, 2, 3];
      await registry.batchRevoke(tokenContract, ids);
      await registry.batchUnrevoke(tokenContract, [1, 3]);
      expect(await registry.isRevoked(tokenContract, 1)).to.equal(false);
      expect(await registry.isRevoked(tokenContract, 2)).to.equal(true);
      expect(await registry.isRevoked(tokenContract, 3)).to.equal(false);
      expect(await registry.revokedCount(tokenContract)).to.equal(1n);
    });

    it("should batch set with array params", async () => {
      const ids = [10, 20, 30];
      const statuses = [true, false, true];
      await registry.batchSetRevoked(tokenContract, ids, statuses);
      expect(await registry.isRevoked(tokenContract, 10)).to.equal(true);
      expect(await registry.isRevoked(tokenContract, 20)).to.equal(false);
      expect(await registry.isRevoked(tokenContract, 30)).to.equal(true);
    });

    it("should revert on array length mismatch", async () => {
      await expect(
        registry.batchSetRevoked(tokenContract, [1, 2], [true])
      ).to.be.revertedWith("array length mismatch");
    });

    it("should batch check revocation status", async () => {
      await registry.setRevoked(tokenContract, 1, true);
      await registry.setRevoked(tokenContract, 3, true);
      const results = await registry.batchIsRevoked(tokenContract, [1, 2, 3]);
      expect(results).to.deep.equal([true, false, true]);
    });

    it("should batch revoke in range", async () => {
      await registry.batchSetRevokedInRange(tokenContract, 0, 9, true);
      for (let i = 0; i < 10; i++) {
        expect(await registry.isRevoked(tokenContract, i)).to.equal(true);
      }
      expect(await registry.revokedCount(tokenContract)).to.equal(10n);
    });

    it("should revert on invalid range", async () => {
      await expect(
        registry.batchSetRevokedInRange(tokenContract, 5, 3, true)
      ).to.be.revertedWith("invalid range");
    });
  });

  describe("Gas benchmarks", function () {
    it("single setRevoked gas cost", async () => {
      const tx = await registry.setRevoked(tokenContract, 1, true);
      const receipt = await tx.wait();
      const gasUsed = receipt.gasUsed;
      expect(gasUsed).to.be.below(60000n);
    });

    it("batchRevoke 10 tokens is more efficient than 10 single calls", async () => {
      const ids = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

      const singleGas = [];
      for (const id of ids) {
        const tx = await registry.setRevoked(tokenContract, id, true);
        const receipt = await tx.wait();
        singleGas.push(receipt.gasUsed);
      }
      const singleTotal = singleGas.reduce((a, b) => a + b, 0n);

      const batchTx = await registry.batchRevoke(tokenContract, ids);
      const batchReceipt = await batchTx.wait();
      const batchTotal = batchReceipt.gasUsed;

      expect(batchTotal).to.be.below(singleTotal);
    });
  });
});
