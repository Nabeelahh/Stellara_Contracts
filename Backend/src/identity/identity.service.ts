import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { IssueCredentialDto } from './dto/issue-credential.dto';
import { ethers } from 'ethers';
import { createVerifiableCredential } from './vc.util';

@Injectable()
export class IdentityService {
  private readonly logger = new Logger(IdentityService.name);
  private provider: ethers.providers.JsonRpcProvider | null = null;
  private signer: ethers.Wallet | null = null;

  constructor(private readonly config: ConfigService) {
    const rpc = this.config.get<string>('ETH_RPC_URL');
    const pk = this.config.get<string>('SBT_ISSUER_PRIVATE_KEY');
    if (rpc && pk) {
      this.provider = new ethers.providers.JsonRpcProvider(rpc);
      this.signer = new ethers.Wallet(pk, this.provider);
    }
  }

  async issueOnChain(
    contractAddress: string,
    tokenId: number,
    recipient: string,
    expiresAtUnix: number,
  ) {
    if (!this.signer) throw new Error('Blockchain signer not configured');
    const abi = ['function issue(address to, uint256 tokenId, uint64 expiresAt) external'];
    const contract = new ethers.Contract(contractAddress, abi, this.signer);
    const tx = await contract.issue(recipient, tokenId, expiresAtUnix);
    this.logger.log(`Issued SBT tx: ${tx.hash}`);
    await tx.wait();
    return tx.hash;
  }

  async issueCredential(dto: IssueCredentialDto) {
    // 1) Create a W3C-style VC
    const issuer = this.config.get<string>('SBT_ISSUER_DID') ?? 'did:stellara:issuer';
    const subject = `did:ethr:${dto.recipientWallet}`;
    const vc = createVerifiableCredential(
      issuer,
      subject,
      dto.attributes,
      new Date().toISOString(),
      dto.expiresAt,
    );

    // 2) Optionally mint on-chain SBT (if configured)
    const contractAddr = this.config.get<string>('SBT_CONTRACT_ADDRESS');
    let onchainTx: string | null = null;
    if (contractAddr) {
      const tokenId = Math.floor(Math.random() * 1e9);
      const expiresAtUnix = dto.expiresAt
        ? Math.floor(new Date(dto.expiresAt).getTime() / 1000)
        : 0;
      onchainTx = await this.issueOnChain(
        contractAddr,
        tokenId,
        dto.recipientWallet,
        expiresAtUnix,
      );
      // attach on-chain reference
      vc.credentialSubject._sbt = { contract: contractAddr, tokenId };
    }

    // 3) Sign the VC with issuer key and embed W3C proof
    const signingKey = this.signer;
    let proof: any = null;
    if (signingKey) {
      const payload = JSON.stringify(vc);
      const digest = ethers.utils.keccak256(ethers.utils.toUtf8Bytes(payload));
      const sig = await signingKey.signMessage(ethers.utils.arrayify(digest));
      proof = {
        type: 'EcdsaSecp256k1Signature2019',
        created: new Date().toISOString(),
        proofPurpose: 'assertionMethod',
        verificationMethod: issuer,
        jws: sig,
      };
      vc.proof = proof;
    }

    return { vc, proof, onchainTx };
  }

  async revokeOnChain(contractAddress: string, tokenId: number) {
    if (!this.signer) throw new Error('Blockchain signer not configured');
    const abi = ['function revoke(uint256 tokenId) external'];
    const contract = new ethers.Contract(contractAddress, abi, this.signer);
    const tx = await contract.revoke(tokenId);
    await tx.wait();
    return tx.hash;
  }

  async renewOnChain(contractAddress: string, tokenId: number, newExpiresAtUnix: number) {
    if (!this.signer) throw new Error('Blockchain signer not configured');
    const abi = ['function renew(uint256 tokenId, uint64 expiresAt) external'];
    const contract = new ethers.Contract(contractAddress, abi, this.signer);
    const tx = await contract.renew(tokenId, newExpiresAtUnix);
    await tx.wait();
    return tx.hash;
  }
}
