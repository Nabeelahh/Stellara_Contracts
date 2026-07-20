const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("SoulboundCredential", function () {
  let owner, alice, bob;
  let sbt;

  const TOKEN_ID = 1;
  const FUTURE = Math.floor(Date.now() / 1000) + 86400 * 365;
  const ZERO = 0;
  const PAST = Math.floor(Date.now() / 1000) - 1;

  beforeEach(async () => {
    [owner, alice, bob] = await ethers.getSigners();
    const SBT = await ethers.getContractFactory("SoulboundCredential");
    sbt = await SBT.deploy("SoulboundCredential", "SBT");
    await sbt.waitForDeployment();
  });

  // ── Issuance ──────────────────────────────────────────────────────────

  describe("Issuance", function () {
    it("should issue a credential with expiration", async () => {
      await sbt.issue(alice.address, TOKEN_ID, FUTURE);
      expect(await sbt.ownerOf(TOKEN_ID)).to.equal(alice.address);
      expect(await sbt.expiration(TOKEN_ID)).to.equal(FUTURE);
      await expect(sbt.issue(alice.address, TOKEN_ID, FUTURE))
        .to.be.revertedWith("SBT: token already exists");
    });

    it("should emit CredentialIssued", async () => {
      await expect(sbt.issue(alice.address, TOKEN_ID, FUTURE))
        .to.emit(sbt, "CredentialIssued")
        .withArgs(alice.address, TOKEN_ID, FUTURE);
    });

    it("should issue with no expiration (0)", async () => {
      await sbt.issue(alice.address, TOKEN_ID, ZERO);
      expect(await sbt.expiration(TOKEN_ID)).to.equal(ZERO);
      expect(await sbt.valid(TOKEN_ID)).to.equal(true);
    });

    it("should only allow owner to issue", async () => {
      await expect(
        sbt.connect(alice).issue(alice.address, TOKEN_ID, FUTURE)
      ).to.be.revertedWith("Ownable: caller is not the owner");
    });
  });

  // ── Revocation ────────────────────────────────────────────────────────

  describe("Revocation", function () {
    it("should revoke a credential and mark it invalid", async () => {
      await sbt.issue(alice.address, TOKEN_ID, FUTURE);
      await sbt.revoke(TOKEN_ID);
      expect(await sbt.valid(TOKEN_ID)).to.equal(false);
      expect(await sbt.isRevoked(TOKEN_ID)).to.equal(true);
    });

    it("should emit CredentialRevoked", async () => {
      await sbt.issue(alice.address, TOKEN_ID, FUTURE);
      await expect(sbt.revoke(TOKEN_ID))
        .to.emit(sbt, "CredentialRevoked")
        .withArgs(TOKEN_ID);
    });

    it("should revert revoke on non-existent token", async () => {
      await expect(sbt.revoke(TOKEN_ID))
        .to.be.revertedWith("SBT: token does not exist");
    });

    it("should revert revoke on already revoked token", async () => {
      await sbt.issue(alice.address, TOKEN_ID, FUTURE);
      await sbt.revoke(TOKEN_ID);
      await expect(sbt.revoke(TOKEN_ID))
        .to.be.revertedWith("SBT: credential revoked");
    });

    it("should revert revoke from non-owner", async () => {
      await sbt.issue(alice.address, TOKEN_ID, FUTURE);
      await expect(sbt.connect(alice).revoke(TOKEN_ID))
        .to.be.revertedWith("Ownable: caller is not the owner");
    });
  });

  // ── Expiration ────────────────────────────────────────────────────────

  describe("Expiration", function () {
    it("should report expired credential as invalid", async () => {
      await sbt.issue(alice.address, TOKEN_ID, PAST);
      expect(await sbt.valid(TOKEN_ID)).to.equal(false);
      expect(await sbt.isExpired(TOKEN_ID)).to.equal(true);
    });

    it("should report valid credential before expiry", async () => {
      await sbt.issue(alice.address, TOKEN_ID, FUTURE);
      expect(await sbt.valid(TOKEN_ID)).to.equal(true);
      expect(await sbt.isExpired(TOKEN_ID)).to.equal(false);
    });

    it("should report valid credential with no expiry (0)", async () => {
      await sbt.issue(alice.address, TOKEN_ID, ZERO);
      expect(await sbt.valid(TOKEN_ID)).to.equal(true);
      expect(await sbt.isExpired(TOKEN_ID)).to.equal(false);
    });

    it("should not allow renew on expired credential", async () => {
      await sbt.issue(alice.address, TOKEN_ID, PAST);
      await expect(sbt.renew(TOKEN_ID, FUTURE))
        .to.be.revertedWith("SBT: credential expired");
    });
  });

  // ── Renewal ───────────────────────────────────────────────────────────

  describe("Renewal", function () {
    it("should renew expiration", async () => {
      await sbt.issue(alice.address, TOKEN_ID, FUTURE);
      const newExpiry = FUTURE + 86400;
      await sbt.renew(TOKEN_ID, newExpiry);
      expect(await sbt.expiration(TOKEN_ID)).to.equal(newExpiry);
    });

    it("should emit CredentialRenewed", async () => {
      await sbt.issue(alice.address, TOKEN_ID, FUTURE);
      const newExpiry = FUTURE + 86400;
      await expect(sbt.renew(TOKEN_ID, newExpiry))
        .to.emit(sbt, "CredentialRenewed")
        .withArgs(TOKEN_ID, newExpiry);
    });

    it("should not allow renew on revoked credential", async () => {
      await sbt.issue(alice.address, TOKEN_ID, FUTURE);
      await sbt.revoke(TOKEN_ID);
      await expect(sbt.renew(TOKEN_ID, FUTURE))
        .to.be.revertedWith("SBT: credential revoked");
    });

    it("should revert renew from non-owner", async () => {
      await sbt.issue(alice.address, TOKEN_ID, FUTURE);
      await expect(sbt.connect(alice).renew(TOKEN_ID, FUTURE))
        .to.be.revertedWith("Ownable: caller is not the owner");
    });
  });

  // ── Reissuance ────────────────────────────────────────────────────────

  describe("Reissuance", function () {
    it("should reissue by burning old and minting new", async () => {
      await sbt.issue(alice.address, TOKEN_ID, FUTURE);
      const newTokenId = 2;
      await sbt.reissue(bob.address, TOKEN_ID, newTokenId, FUTURE);
      expect(await sbt.ownerOf(newTokenId)).to.equal(bob.address);
      expect(await sbt.expiration(newTokenId)).to.equal(FUTURE);
      await expect(sbt.ownerOf(TOKEN_ID)).to.be.reverted;
    });

    it("should emit CredentialReissued", async () => {
      await sbt.issue(alice.address, TOKEN_ID, FUTURE);
      const newTokenId = 2;
      await expect(sbt.reissue(bob.address, TOKEN_ID, newTokenId, FUTURE))
        .to.emit(sbt, "CredentialReissued")
        .withArgs(bob.address, newTokenId, FUTURE);
    });

    it("should reissue even when old credential was revoked", async () => {
      await sbt.issue(alice.address, TOKEN_ID, FUTURE);
      await sbt.revoke(TOKEN_ID);
      const newTokenId = 2;
      await sbt.reissue(bob.address, TOKEN_ID, newTokenId, FUTURE);
      expect(await sbt.valid(newTokenId)).to.equal(true);
    });

    it("should reissue even when old credential was expired", async () => {
      await sbt.issue(alice.address, TOKEN_ID, PAST);
      const newTokenId = 2;
      await sbt.reissue(bob.address, TOKEN_ID, newTokenId, FUTURE);
      expect(await sbt.valid(newTokenId)).to.equal(true);
    });

    it("should reissue when old token does not exist (new issuance only)", async () => {
      const newTokenId = 3;
      await sbt.reissue(alice.address, 999, newTokenId, FUTURE);
      expect(await sbt.ownerOf(newTokenId)).to.equal(alice.address);
    });

    it("should revert if new token id already exists", async () => {
      await sbt.issue(alice.address, TOKEN_ID, FUTURE);
      await sbt.issue(alice.address, 2, FUTURE);
      await expect(sbt.reissue(bob.address, TOKEN_ID, 2, FUTURE))
        .to.be.revertedWith("SBT: new token already exists");
    });

    it("should revert reissue from non-owner", async () => {
      await expect(sbt.connect(alice).reissue(alice.address, 1, 2, FUTURE))
        .to.be.revertedWith("Ownable: caller is not the owner");
    });
  });

  // ── Transfers blocked ─────────────────────────────────────────────────

  describe("Non-transferable", function () {
    it("should block safeTransferFrom", async () => {
      await sbt.issue(alice.address, TOKEN_ID, FUTURE);
      await expect(
        sbt.connect(alice)["safeTransferFrom(address,address,uint256)"](
          alice.address, bob.address, TOKEN_ID
        )
      ).to.be.revertedWith("SBT: non-transferable");
    });

    it("should block safeTransferFrom with data", async () => {
      await sbt.issue(alice.address, TOKEN_ID, FUTURE);
      await expect(
        sbt.connect(alice)["safeTransferFrom(address,address,uint256,bytes)"](
          alice.address, bob.address, TOKEN_ID, "0x"
        )
      ).to.be.revertedWith("SBT: non-transferable");
    });

    it("should block approve", async () => {
      await sbt.issue(alice.address, TOKEN_ID, FUTURE);
      await expect(sbt.connect(alice).approve(bob.address, TOKEN_ID))
        .to.be.revertedWith("SBT: approvals disabled");
    });

    it("should block setApprovalForAll", async () => {
      await expect(sbt.connect(alice).setApprovalForAll(bob.address, true))
        .to.be.revertedWith("SBT: approvals disabled");
    });
  });

  // ── Validity checks ──────────────────────────────────────────────────

  describe("Validity helper", function () {
    it("should return false for non-existent token", async () => {
      expect(await sbt.valid(999)).to.equal(false);
    });

    it("should return true for valid credential", async () => {
      await sbt.issue(alice.address, TOKEN_ID, FUTURE);
      expect(await sbt.valid(TOKEN_ID)).to.equal(true);
    });

    it("should return false for revoked credential", async () => {
      await sbt.issue(alice.address, TOKEN_ID, FUTURE);
      await sbt.revoke(TOKEN_ID);
      expect(await sbt.valid(TOKEN_ID)).to.equal(false);
    });

    it("should return false for expired credential", async () => {
      await sbt.issue(alice.address, TOKEN_ID, PAST);
      expect(await sbt.valid(TOKEN_ID)).to.equal(false);
    });
  });
});
