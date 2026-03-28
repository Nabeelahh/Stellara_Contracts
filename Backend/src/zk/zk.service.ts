import { Injectable, Logger } from '@nestjs/common';
import { existsSync, readFileSync } from 'fs';
import { join } from 'path';
import * as snarkjs from 'snarkjs';

@Injectable()
export class ZkService {
  private readonly logger = new Logger(ZkService.name);
  private circuitDirectory = join(__dirname, 'circuits');

  async generateSolvencyProof(balances: Record<string, string>, threshold: string) {
    return this.generateProof('solvency', { balances, threshold });
  }

  async verifyProof(circuitName: string, proof: any, publicSignals: any[]): Promise<boolean> {
    const vkeyPath = join(this.circuitDirectory, `${circuitName}_verification_key.json`);
    if (!existsSync(vkeyPath)) {
      throw new Error(`Verification key for circuit '${circuitName}' is missing`);
    }

    const vKey = JSON.parse(readFileSync(vkeyPath, 'utf8'));
    return snarkjs.groth16.verify(vKey, publicSignals, proof);
  }

  private async generateProof(circuitName: string, input: Record<string, any>) {
    const circuitDir = join(this.circuitDirectory, circuitName);
    const wasmPath = join(circuitDir, `${circuitName}.wasm`);
    const zkeyPath = join(circuitDir, `${circuitName}.zkey`);

    if (!existsSync(wasmPath) || !existsSync(zkeyPath)) {
      throw new Error(`Circuit artifacts for '${circuitName}' are not available. Run the trusted setup first.`);
    }

    this.logger.log(`Generating proof for circuit ${circuitName}`);

    const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, wasmPath, zkeyPath);

    return {
      proof,
      publicSignals,
    };
  }
}
