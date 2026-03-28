import { Injectable, Logger } from '@nestjs/common';
import { ethers } from 'ethers';
import { 
  SmartContractIntegration,
  ExecutionStatus,
  Agent,
  Transaction,
  NegotiationTerms
} from '../interfaces/agent.interface';

@Injectable()
export class SmartContractIntegrationService {
  private readonly logger = new Logger(SmartContractIntegrationService.name);
  private providers = new Map<string, ethers.JsonRpcProvider>();
  private contracts = new Map<string, ethers.Contract>();

  constructor() {
    this.initializeProviders();
  }

  private initializeProviders(): void {
    // Initialize providers for different networks
    this.providers.set('ethereum', new ethers.JsonRpcProvider(
      process.env.ETHEREUM_RPC_URL || 'https://mainnet.infura.io/v3/your-project-id'
    ));
    
    this.providers.set('polygon', new ethers.JsonRpcProvider(
      process.env.POLYGON_RPC_URL || 'https://polygon-rpc.com'
    ));
    
    this.providers.set('arbitrum', new ethers.JsonRpcProvider(
      process.env.ARBITRUM_RPC_URL || 'https://arb1.arbitrum.io/rpc'
    ));
  }

  async executeTrade(
    agentId: string,
    terms: NegotiationTerms,
    network: string = 'ethereum'
  ): Promise<SmartContractIntegration> {
    try {
      this.logger.log(`Executing trade for agent ${agentId} on ${network}`);
      
      const provider = this.providers.get(network);
      if (!provider) {
        throw new Error(`Provider for network ${network} not found`);
      }

      // Get contract based on asset
      const contract = await this.getContractForAsset(terms.asset, network);
      
      // Prepare transaction data
      const txData = await this.prepareTradeTransaction(contract, terms);
      
      // Estimate gas
      const gasEstimate = await provider.estimateGas(txData);
      
      // Execute transaction
      const txHash = await this.sendTransaction(txData, gasEstimate);
      
      const integration: SmartContractIntegration = {
        contractAddress: contract.target,
        abi: contract.interface.fragments,
        functionName: txData.data.slice(0, 10), // Extract function signature
        parameters: txData.args,
        gasEstimate: Number(gasEstimate),
        executionStatus: ExecutionStatus.PENDING
      };

      // Wait for confirmation
      const receipt = await provider.waitForTransaction(txHash);
      integration.executionStatus = receipt.status === 1 ? 
        ExecutionStatus.SUCCESS : ExecutionStatus.FAILED;

      this.logger.log(`Trade executed successfully: ${txHash}`);
      
      return integration;
    } catch (error) {
      this.logger.error(`Failed to execute trade for agent ${agentId}:`, error);
      
      return {
        contractAddress: '',
        abi: [],
        functionName: '',
        parameters: [],
        gasEstimate: 0,
        executionStatus: ExecutionStatus.FAILED
      };
    }
  }

  async executeLiquidityProvision(
    agentId: string,
    terms: NegotiationTerms,
    network: string = 'ethereum'
  ): Promise<SmartContractIntegration> {
    try {
      this.logger.log(`Executing liquidity provision for agent ${agentId} on ${network}`);
      
      const provider = this.providers.get(network);
      if (!provider) {
        throw new Error(`Provider for network ${network} not found`);
      }

      // Get Uniswap V3 Router contract
      const routerAddress = '0xE592427A0AEce92De3Edee1F18E0157C05861564';
      const routerAbi = [
        'function exactInputSingle(tuple(address tokenIn, address tokenOut, uint24 fee, address recipient, uint256 deadline, uint256 amountIn, uint256 amountOutMinimum, uint160 sqrtPriceLimitX96)) external payable returns (uint256 amountOut)',
        'function addLiquidity(address tokenA, address tokenB, uint256 amountADesired, uint256 amountBDesired, uint256 amountAMin, uint256 amountBMin, address to, uint256 deadline) external returns (uint256 amountA, uint256 amountB, uint256 liquidity)'
      ];

      const contract = new ethers.Contract(routerAddress, routerAbi, provider);
      
      // Prepare liquidity provision transaction
      const tokenA = this.getTokenAddress(terms.asset);
      const tokenB = this.getTokenAddress(terms.currency);
      
      const deadline = Math.floor(Date.now() / 1000) + 1800; // 30 minutes
      
      const txData = await contract.addLiquidity.populateTransaction([
        tokenA,
        tokenB,
        ethers.parseEther(terms.quantity.toString()),
        ethers.parseEther(terms.quantity.toString()),
        ethers.parseEther((terms.quantity * 0.99).toString()), // 1% slippage tolerance
        ethers.parseEther((terms.quantity * 0.99).toString()),
        await this.getAgentWallet(agentId),
        deadline
      ]);

      const gasEstimate = await provider.estimateGas(txData);
      const txHash = await this.sendTransaction(txData, gasEstimate);
      
      const integration: SmartContractIntegration = {
        contractAddress: routerAddress,
        abi: routerAbi,
        functionName: 'addLiquidity',
        parameters: txData.args,
        gasEstimate: Number(gasEstimate),
        executionStatus: ExecutionStatus.PENDING
      };

      // Wait for confirmation
      const receipt = await provider.waitForTransaction(txHash);
      integration.executionStatus = receipt.status === 1 ? 
        ExecutionStatus.SUCCESS : ExecutionStatus.FAILED;

      this.logger.log(`Liquidity provision executed successfully: ${txHash}`);
      
      return integration;
    } catch (error) {
      this.logger.error(`Failed to execute liquidity provision for agent ${agentId}:`, error);
      
      return {
        contractAddress: '',
        abi: [],
        functionName: '',
        parameters: [],
        gasEstimate: 0,
        executionStatus: ExecutionStatus.FAILED
      };
    }
  }

  async executeLoan(
    agentId: string,
    terms: NegotiationTerms,
    network: string = 'ethereum'
  ): Promise<SmartContractIntegration> {
    try {
      this.logger.log(`Executing loan for agent ${agentId} on ${network}`);
      
      const provider = this.providers.get(network);
      if (!provider) {
        throw new Error(`Provider for network ${network} not found`);
      }

      // Get lending protocol contract (e.g., Aave)
      const lendingPoolAddress = '0x7d2768dE32b0b80b7a3904eFdb063412e34f';
      const lendingPoolAbi = [
        'function deposit(address asset, uint256 amount, address onBehalfOf, uint16 referralCode) external',
        'function borrow(address asset, uint256 amount, uint256 interestRateMode, uint16 referralCode, address onBehalfOf) external returns (uint256)',
        'function repay(address asset, uint256 amount, uint256 interestRateMode, address onBehalfOf) external returns (uint256)'
      ];

      const contract = new ethers.Contract(lendingPoolAddress, lendingPoolAbi, provider);
      
      const assetAddress = this.getTokenAddress(terms.asset);
      const amount = ethers.parseEther(terms.quantity.toString());
      
      let txData;
      if (terms.collateral) {
        // Borrow with collateral
        txData = await contract.borrow.populateTransaction([
          assetAddress,
          amount,
          2, // Variable interest rate
          0,
          await this.getAgentWallet(agentId)
        ]);
      } else {
        // Simple deposit/lend
        txData = await contract.deposit.populateTransaction([
          assetAddress,
          amount,
          await this.getAgentWallet(agentId),
          0
        ]);
      }

      const gasEstimate = await provider.estimateGas(txData);
      const txHash = await this.sendTransaction(txData, gasEstimate);
      
      const integration: SmartContractIntegration = {
        contractAddress: lendingPoolAddress,
        abi: lendingPoolAbi,
        functionName: txData.data.slice(0, 10),
        parameters: txData.args,
        gasEstimate: Number(gasEstimate),
        executionStatus: ExecutionStatus.PENDING
      };

      // Wait for confirmation
      const receipt = await provider.waitForTransaction(txHash);
      integration.executionStatus = receipt.status === 1 ? 
        ExecutionStatus.SUCCESS : ExecutionStatus.FAILED;

      this.logger.log(`Loan executed successfully: ${txHash}`);
      
      return integration;
    } catch (error) {
      this.logger.error(`Failed to execute loan for agent ${agentId}:`, error);
      
      return {
        contractAddress: '',
        abi: [],
        functionName: '',
        parameters: [],
        gasEstimate: 0,
        executionStatus: ExecutionStatus.FAILED
      };
    }
  }

  async executeArbitrage(
    agentId: string,
    buyTerms: NegotiationTerms,
    sellTerms: NegotiationTerms,
    network: string = 'ethereum'
  ): Promise<SmartContractIntegration[]> {
    this.logger.log(`Executing arbitrage for agent ${agentId} on ${network}`);
    
    try {
      // Execute buy transaction
      const buyIntegration = await this.executeTrade(agentId, buyTerms, network);
      
      // Execute sell transaction
      const sellIntegration = await this.executeTrade(agentId, sellTerms, network);
      
      return [buyIntegration, sellIntegration];
    } catch (error) {
      this.logger.error(`Failed to execute arbitrage for agent ${agentId}:`, error);
      
      return [{
        contractAddress: '',
        abi: [],
        functionName: '',
        parameters: [],
        gasEstimate: 0,
        executionStatus: ExecutionStatus.FAILED
      }];
    }
  }

  private async getContractForAsset(asset: string, network: string): Promise<ethers.Contract> {
    const contractKey = `${asset}_${network}`;
    
    if (this.contracts.has(contractKey)) {
      return this.contracts.get(contractKey)!;
    }

    let contractAddress: string;
    let abi: any[];

    switch (asset.toLowerCase()) {
      case 'eth':
        contractAddress = '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2';
        abi = [
          'function balanceOf(address account) external view returns (uint256)',
          'function transfer(address to, uint256 amount) external returns (bool)',
          'function approve(address spender, uint256 amount) external returns (bool)'
        ];
        break;
      
      case 'usdc':
        contractAddress = '0xA0b86a33E6441b8e8C7C7b0b8e8e8e8e8e8e8e8e8e';
        abi = [
          'function balanceOf(address account) external view returns (uint256)',
          'function transfer(address to, uint256 amount) external returns (bool)',
          'function approve(address spender, uint256 amount) external returns (bool)'
        ];
        break;
      
      default:
        throw new Error(`No contract found for asset: ${asset}`);
    }

    const provider = this.providers.get(network);
    if (!provider) {
      throw new Error(`Provider for network ${network} not found`);
    }

    const contract = new ethers.Contract(contractAddress, abi, provider);
    this.contracts.set(contractKey, contract);
    
    return contract;
  }

  private getTokenAddress(tokenSymbol: string): string {
    const tokenAddresses: { [key: string]: string } = {
      'ETH': '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2',
      'USDC': '0xA0b86a33E6441b8e8C7C7b0b8e8e8e8e8e8e8e8e8e8e',
      'USDT': '0xdAC17F958D2ee523a2206206994597C13D831ec7',
      'WBTC': '0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599'
    };
    
    return tokenAddresses[tokenSymbol] || tokenAddresses['ETH'];
  }

  private async prepareTradeTransaction(
    contract: ethers.Contract,
    terms: NegotiationTerms
  ): Promise<ethers.TransactionRequest> {
    // This would prepare the specific transaction based on the contract
    // For now, return a generic transaction request
    
    return {
      to: contract.target as string,
      data: contract.interface.encodeFunctionData('transfer', [
        await this.getAgentWallet('default'),
        ethers.parseEther(terms.quantity.toString())
      ]),
      value: '0'
    };
  }

  private async sendTransaction(
    txData: ethers.TransactionRequest,
    gasEstimate: bigint
  ): Promise<string> {
    const provider = this.providers.get('ethereum');
    if (!provider) {
      throw new Error('Ethereum provider not found');
    }

    const wallet = await this.getAgentWalletWithPrivateKey('default');
    const connectedWallet = wallet.connect(provider);

    const transaction = {
      ...txData,
      gasLimit: gasEstimate,
      gasPrice: await provider.getFeeData()
    };

    const tx = await connectedWallet.sendTransaction(transaction);
    return tx.hash;
  }

  private async getAgentWallet(agentId: string): Promise<string> {
    // This would fetch the agent's wallet address from database
    // For now, return a default address
    const agentWallets: { [key: string]: string } = {
      'default': '0x742d35Cc6634C0532925a3b844Bc9e7598f0f1',
      'agent1': '0x8ba1f109551bD432803012645Hac136c26C',
      'agent2': '0x1234567890123456789012345678901234'
    };
    
    return agentWallets[agentId] || agentWallets['default'];
  }

  private async getAgentWalletWithPrivateKey(agentId: string): Promise<ethers.Wallet> {
    // This would securely fetch the agent's private key from secure storage
    // For now, return a test wallet (NEVER use in production!)
    const agentWallets: { [key: string]: string } = {
      'default': '0x01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789'
    };
    
    const privateKey = agentWallets[agentId] || agentWallets['default'];
    return new ethers.Wallet(privateKey);
  }

  async getTransactionStatus(txHash: string, network: string = 'ethereum'): Promise<ExecutionStatus> {
    try {
      const provider = this.providers.get(network);
      if (!provider) {
        throw new Error(`Provider for network ${network} not found`);
      }

      const receipt = await provider.getTransactionReceipt(txHash);
      
      if (!receipt) {
        return ExecutionStatus.PENDING;
      }
      
      return receipt.status === 1 ? ExecutionStatus.SUCCESS : ExecutionStatus.FAILED;
    } catch (error) {
      this.logger.error(`Failed to get transaction status for ${txHash}:`, error);
      return ExecutionStatus.FAILED;
    }
  }

  async getContractBalance(
    contractAddress: string,
    agentId: string,
    network: string = 'ethereum'
  ): Promise<string> {
    try {
      const provider = this.providers.get(network);
      if (!provider) {
        throw new Error(`Provider for network ${network} not found`);
      }

      const contract = this.contracts.get(`${contractAddress}_${network}`);
      if (!contract) {
        throw new Error(`Contract ${contractAddress} not found`);
      }

      const walletAddress = await this.getAgentWallet(agentId);
      const balance = await contract.balanceOf(walletAddress);
      
      return ethers.formatEther(balance);
    } catch (error) {
      this.logger.error(`Failed to get contract balance:`, error);
      return '0';
    }
  }

  async approveToken(
    tokenAddress: string,
    spenderAddress: string,
    amount: string,
    agentId: string,
    network: string = 'ethereum'
  ): Promise<SmartContractIntegration> {
    try {
      this.logger.log(`Approving token for agent ${agentId}`);
      
      const provider = this.providers.get(network);
      if (!provider) {
        throw new Error(`Provider for network ${network} not found`);
      }

      const tokenContract = this.contracts.get(`${tokenAddress}_${network}`);
      if (!tokenContract) {
        const erc20Abi = [
          'function approve(address spender, uint256 amount) external returns (bool)',
          'function balanceOf(address account) external view returns (uint256)'
        ];
        const contract = new ethers.Contract(tokenAddress, erc20Abi, provider);
        this.contracts.set(`${tokenAddress}_${network}`, contract);
      }

      const wallet = await this.getAgentWalletWithPrivateKey(agentId);
      const connectedContract = tokenContract.connect(wallet);
      
      const txData = await connectedContract.approve.populateTransaction([
        spenderAddress,
        ethers.parseEther(amount)
      ]);

      const gasEstimate = await provider.estimateGas(txData);
      const txHash = await wallet.sendTransaction({
        ...txData,
        gasLimit: gasEstimate
      });

      const integration: SmartContractIntegration = {
        contractAddress: tokenAddress,
        abi: tokenContract.interface.fragments,
        functionName: 'approve',
        parameters: txData.args,
        gasEstimate: Number(gasEstimate),
        executionStatus: ExecutionStatus.PENDING
      };

      // Wait for confirmation
      const receipt = await provider.waitForTransaction(txHash);
      integration.executionStatus = receipt.status === 1 ? 
        ExecutionStatus.SUCCESS : ExecutionStatus.FAILED;

      return integration;
    } catch (error) {
      this.logger.error(`Failed to approve token:`, error);
      
      return {
        contractAddress: '',
        abi: [],
        functionName: '',
        parameters: [],
        gasEstimate: 0,
        executionStatus: ExecutionStatus.FAILED
      };
    }
  }

  async batchExecute(
    agentId: string,
    transactions: Array<{ terms: NegotiationTerms; type: string }>,
    network: string = 'ethereum'
  ): Promise<SmartContractIntegration[]> {
    this.logger.log(`Executing batch of ${transactions.length} transactions for agent ${agentId}`);
    
    const results: SmartContractIntegration[] = [];
    
    for (const tx of transactions) {
      let result: SmartContractIntegration;
      
      switch (tx.type) {
        case 'trade':
          result = await this.executeTrade(agentId, tx.terms, network);
          break;
        
        case 'liquidity':
          result = await this.executeLiquidityProvision(agentId, tx.terms, network);
          break;
        
        case 'loan':
          result = await this.executeLoan(agentId, tx.terms, network);
          break;
        
        default:
          result = {
            contractAddress: '',
            abi: [],
            functionName: '',
            parameters: [],
            gasEstimate: 0,
            executionStatus: ExecutionStatus.FAILED
          };
      }
      
      results.push(result);
      
      // Add delay between transactions to avoid nonce conflicts
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
    
    return results;
  }

  getContractABI(contractAddress: string, network: string = 'ethereum'): any[] {
    const contract = this.contracts.get(`${contractAddress}_${network}`);
    return contract ? contract.interface.fragments : [];
  }

  async monitorTransaction(
    txHash: string,
    callback: (status: ExecutionStatus) => void,
    network: string = 'ethereum'
  ): Promise<void> {
    const provider = this.providers.get(network);
    if (!provider) {
      throw new Error(`Provider for network ${network} not found`);
    }

    // Poll for transaction status
    const checkStatus = async () => {
      const status = await this.getTransactionStatus(txHash, network);
      callback(status);
      
      if (status === ExecutionStatus.SUCCESS || status === ExecutionStatus.FAILED) {
        return;
      }
      
      // Check again in 5 seconds
      setTimeout(checkStatus, 5000);
    };

    await checkStatus();
  }
}
