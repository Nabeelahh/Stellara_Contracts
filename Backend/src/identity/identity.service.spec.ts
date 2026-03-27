import { Test, TestingModule } from '@nestjs/testing';
import { IdentityService } from './identity.service';
import { ConfigModule } from '@nestjs/config';
import { ethers } from 'ethers';

describe('IdentityService', () => {
  let service: IdentityService;

  beforeAll(async () => {
    process.env.SBT_ISSUER_PRIVATE_KEY = ethers.Wallet.createRandom().privateKey;
    process.env.ETH_RPC_URL = 'http://localhost:8545';

    const module: TestingModule = await Test.createTestingModule({
      imports: [ConfigModule.forRoot()],
      providers: [IdentityService],
    }).compile();

    service = module.get<IdentityService>(IdentityService);
  });

  it('creates a valid verifiable credential with proof', async () => {
    const dto: any = {
      userId: 'user-1',
      recipientWallet: '0x' + ethers.Wallet.createRandom().address.slice(2),
      attributes: { kyc: { age: 30, country: 'US' } },
    };

    const result = await service.issueCredential(dto);
    expect(result).toBeDefined();
    expect(result.vc).toBeDefined();
    expect(result.vc.credentialSubject).toBeDefined();
    expect(result.vc.proof).toBeDefined();
    expect(result.vc.proof.jws).toBeDefined();
  });
});
