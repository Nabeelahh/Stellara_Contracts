import { Injectable, Logger } from '@nestjs/common';
import { 
  RLModel,
  RLAlgorithm,
  RLHyperparameters,
  RLPerformance,
  ReinforcementLearningState,
  Agent,
  AgentState,
  MarketConditions
} from '../interfaces/agent.interface';

@Injectable()
export class ReinforcementLearningService {
  private readonly logger = new Logger(ReinforcementLearningService.name);
  private models = new Map<string, RLModel>();
  private experienceBuffers = new Map<string, ReinforcementLearningState[]>();

  async createRLModel(
    agentId: string,
    algorithm: RLAlgorithm,
    hyperparameters: RLHyperparameters
  ): Promise<RLModel> {
    const model: RLModel = {
      id: `rl_${agentId}_${Date.now()}`,
      agentId,
      algorithm,
      hyperparameters,
      performance: {
        averageReward: 0,
        maxReward: -Infinity,
        minReward: Infinity,
        convergenceRate: 0,
        explorationRate: hyperparameters.explorationRate,
        totalEpisodes: 0
      },
      trainingData: [],
      modelState: this.initializeModel(algorithm, hyperparameters)
    };

    this.models.set(model.id, model);
    this.experienceBuffers.set(agentId, []);

    this.logger.log(`Created RL model ${model.id} for agent ${agentId} using ${algorithm}`);
    
    return model;
  }

  private initializeModel(algorithm: RLAlgorithm, hyperparameters: RLHyperparameters): any {
    switch (algorithm) {
      case RLAlgorithm.Q_LEARNING:
        return this.initializeQLearning(hyperparameters);
      
      case RLAlgorithm.DEEP_Q_NETWORK:
        return this.initializeDeepQNetwork(hyperparameters);
      
      case RLAlgorithm.ACTOR_CRITIC:
        return this.initializeActorCritic(hyperparameters);
      
      case RLAlgorithm.PPO:
        return this.initializePPO(hyperparameters);
      
      default:
        return this.initializeQLearning(hyperparameters);
    }
  }

  private initializeQLearning(hyperparameters: RLHyperparameters): any {
    // Initialize Q-table
    const stateSpace = 100; // Discretized state space
    const actionSpace = 10; // Number of possible actions
    
    const qTable = Array(stateSpace).fill(null).map(() => 
      Array(actionSpace).fill(0).map(() => Math.random() * 0.1)
    );
    
    return {
      type: 'q_table',
      qTable,
      stateSpace,
      actionSpace
    };
  }

  private initializeDeepQNetwork(hyperparameters: RLHyperparameters): any {
    // Initialize neural network
    return {
      type: 'neural_network',
      layers: [
        { size: hyperparameters.hiddenLayers?.[0] || 128, activation: 'relu' },
        { size: hyperparameters.hiddenLayers?.[1] || 64, activation: 'relu' },
        { size: hyperparameters.hiddenLayers?.[2] || 32, activation: 'relu' },
        { size: 10, activation: 'linear' } // Output layer
      ],
      weights: this.initializeWeights(hyperparameters.hiddenLayers || [128, 64, 32])
    };
  }

  private initializeActorCritic(hyperparameters: RLHyperparameters): any {
    return {
      type: 'actor_critic',
      actor: this.initializeDeepQNetwork(hyperparameters),
      critic: this.initializeDeepQNetwork(hyperparameters)
    };
  }

  private initializePPO(hyperparameters: RLHyperparameters): any {
    return {
      type: 'ppo',
      policy: this.initializeDeepQNetwork(hyperparameters),
      value: this.initializeDeepQNetwork(hyperparameters),
      clipRatio: 0.2
    };
  }

  private initializeWeights(hiddenLayers: number[]): any[] {
    const weights = [];
    let inputSize = 50; // State representation size
    
    for (const layerSize of hiddenLayers) {
      const layerWeights = Array(layerSize).fill(0).map(() => 
        Array(inputSize).fill(0).map(() => (Math.random() - 0.5) * 0.1)
      );
      weights.push(layerWeights);
      inputSize = layerSize;
    }
    
    return weights;
  }

  async trainModel(
    modelId: string,
    experiences: ReinforcementLearningState[],
    epochs: number = 10
  ): Promise<RLPerformance> {
    const model = this.models.get(modelId);
    if (!model) {
      throw new Error(`Model ${modelId} not found`);
    }

    this.logger.log(`Training model ${modelId} with ${experiences.length} experiences`);

    let totalReward = 0;
    let maxReward = -Infinity;
    let minReward = Infinity;

    for (const experience of experiences) {
      totalReward += experience.reward;
      maxReward = Math.max(maxReward, experience.reward);
      minReward = Math.min(minReward, experience.reward);
    }

    // Update experience buffer
    const buffer = this.experienceBuffers.get(model.agentId) || [];
    buffer.push(...experiences);
    
    // Keep buffer size limited
    const maxSize = model.hyperparameters.memorySize;
    if (buffer.length > maxSize) {
      buffer.splice(0, buffer.length - maxSize);
    }
    
    this.experienceBuffers.set(model.agentId, buffer);

    // Train based on algorithm
    switch (model.algorithm) {
      case RLAlgorithm.Q_LEARNING:
        await this.trainQLearning(model, buffer, epochs);
        break;
      
      case RLAlgorithm.DEEP_Q_NETWORK:
        await this.trainDeepQNetwork(model, buffer, epochs);
        break;
      
      case RLAlgorithm.ACTOR_CRITIC:
        await this.trainActorCritic(model, buffer, epochs);
        break;
      
      case RLAlgorithm.PPO:
        await this.trainPPO(model, buffer, epochs);
        break;
    }

    // Update performance metrics
    const averageReward = totalReward / experiences.length;
    const convergenceRate = this.calculateConvergenceRate(model, buffer);
    
    model.performance = {
      averageReward,
      maxReward,
      minReward,
      convergenceRate,
      explorationRate: this.updateExplorationRate(model),
      totalEpisodes: model.performance.totalEpisodes + experiences.length
    };

    return model.performance;
  }

  private async trainQLearning(
    model: RLModel,
    experiences: ReinforcementLearningState[],
    epochs: number
  ): Promise<void> {
    const { qTable, stateSpace, actionSpace } = model.modelState;
    const { learningRate, discountFactor } = model.hyperparameters;

    for (let epoch = 0; epoch < epochs; epoch++) {
      for (const experience of experiences) {
        const stateIndex = this.discretizeState(experience.state, stateSpace);
        const actionIndex = this.discretizeAction(experience.action, actionSpace);
        const nextStateIndex = this.discretizeState(experience.nextState, stateSpace);
        
        const currentQ = qTable[stateIndex][actionIndex];
        
        // Q-learning update rule
        const maxNextQ = Math.max(...qTable[nextStateIndex]);
        const target = experience.reward + discountFactor * maxNextQ;
        const newQ = currentQ + learningRate * (target - currentQ);
        
        qTable[stateIndex][actionIndex] = newQ;
      }
    }
  }

  private async trainDeepQNetwork(
    model: RLModel,
    experiences: ReinforcementLearningState[],
    epochs: number
  ): Promise<void> {
    const { learningRate, discountFactor, batchSize } = model.hyperparameters;
    
    for (let epoch = 0; epoch < epochs; epoch++) {
      // Sample random batch
      const batch = this.sampleBatch(experiences, batchSize);
      
      for (const experience of batch) {
        // Forward pass
        const currentQ = this.predictQValue(model, experience.state, experience.action);
        const maxNextQ = this.predictMaxQValue(model, experience.nextState);
        
        // Target Q-value
        const target = experience.done ? 
          experience.reward : 
          experience.reward + discountFactor * maxNextQ;
        
        // Backward pass (simplified gradient descent)
        this.updateNetworkWeights(model, experience.state, experience.action, target, learningRate);
      }
    }
  }

  private async trainActorCritic(
    model: RLModel,
    experiences: ReinforcementLearningState[],
    epochs: number
  ): Promise<void> {
    const { learningRate, discountFactor } = model.hyperparameters;
    
    for (let epoch = 0; epoch < epochs; epoch++) {
      for (const experience of experiences) {
        // Update actor
        const actionProbabilities = this.predictActionProbabilities(model.actor, experience.state);
        const advantage = this.calculateAdvantage(model, experience);
        
        // Actor gradient update
        this.updateActorWeights(model.actor, experience.state, experience.action, advantage, learningRate);
        
        // Critic update
        const value = this.predictValue(model.critic, experience.state);
        const target = experience.reward + discountFactor * 
          (experience.done ? 0 : this.predictValue(model.critic, experience.nextState));
        
        this.updateCriticWeights(model.critic, experience.state, target, learningRate);
      }
    }
  }

  private async trainPPO(
    model: RLModel,
    experiences: ReinforcementLearningState[],
    epochs: number
  ): Promise<void> {
    // Proximal Policy Optimization implementation
    const { learningRate, clipRatio } = model.hyperparameters;
    
    for (let epoch = 0; epoch < epochs; epoch++) {
      const batch = this.sampleBatch(experiences, 64);
      
      // Calculate policy and value losses
      const { policyLoss, valueLoss } = this.calculatePPOLosses(model, batch);
      
      // Update policy and value networks
      this.updateNetworkWeights(model.policy, null, null, policyLoss, learningRate);
      this.updateNetworkWeights(model.value, null, null, valueLoss, learningRate);
    }
  }

  async selectAction(
    modelId: string,
    state: number[],
    availableActions: string[]
  ): Promise<{ action: string; confidence: number }> {
    const model = this.models.get(modelId);
    if (!model) {
      throw new Error(`Model ${modelId} not found`);
    }

    // Epsilon-greedy exploration
    if (Math.random() < model.performance.explorationRate) {
      const randomAction = availableActions[Math.floor(Math.random() * availableActions.length)];
      return { action: randomAction, confidence: 0.1 };
    }

    switch (model.algorithm) {
      case RLAlgorithm.Q_LEARNING:
        return this.selectActionQLearning(model, state, availableActions);
      
      case RLAlgorithm.DEEP_Q_NETWORK:
        return this.selectActionDeepQNetwork(model, state, availableActions);
      
      case RLAlgorithm.ACTOR_CRITIC:
        return this.selectActionActorCritic(model, state, availableActions);
      
      case RLAlgorithm.PPO:
        return this.selectActionPPO(model, state, availableActions);
      
      default:
        return this.selectActionQLearning(model, state, availableActions);
    }
  }

  private selectActionQLearning(
    model: RLModel,
    state: number[],
    availableActions: string[]
  ): { action: string; confidence: number } {
    const { qTable, stateSpace, actionSpace } = model.modelState;
    const stateIndex = this.discretizeState(state, stateSpace);
    
    let bestActionIndex = 0;
    let bestQValue = qTable[stateIndex][0];
    
    for (let i = 1; i < Math.min(actionSpace, availableActions.length); i++) {
      if (qTable[stateIndex][i] > bestQValue) {
        bestQValue = qTable[stateIndex][i];
        bestActionIndex = i;
      }
    }
    
    const action = availableActions[bestActionIndex];
    const confidence = this.softmax([bestQValue])[0];
    
    return { action, confidence };
  }

  private selectActionDeepQNetwork(
    model: RLModel,
    state: number[],
    availableActions: string[]
  ): { action: string; confidence: number } {
    const qValues = availableActions.map(action => 
      this.predictQValue(model, state, action)
    );
    
    const maxQ = Math.max(...qValues);
    const maxIndex = qValues.indexOf(maxQ);
    const confidence = this.softmax(qValues)[maxIndex];
    
    return { 
      action: availableActions[maxIndex], 
      confidence 
    };
  }

  private selectActionActorCritic(
    model: RLModel,
    state: number[],
    availableActions: string[]
  ): { action: string; confidence: number } {
    const actionProbabilities = this.predictActionProbabilities(model.actor, state);
    const actionIndex = this.sampleFromDistribution(actionProbabilities);
    
    return {
      action: availableActions[actionIndex],
      confidence: actionProbabilities[actionIndex]
    };
  }

  private selectActionPPO(
    model: RLModel,
    state: number[],
    availableActions: string[]
  ): { action: string; confidence: number } {
    // Use policy network to select action
    const actionProbabilities = this.predictActionProbabilities(model.policy, state);
    const actionIndex = this.sampleFromDistribution(actionProbabilities);
    
    return {
      action: availableActions[actionIndex],
      confidence: actionProbabilities[actionIndex]
    };
  }

  async updateModel(
    modelId: string,
    experience: ReinforcementLearningState
  ): Promise<void> {
    const model = this.models.get(modelId);
    if (!model) return;

    // Add experience to buffer
    const buffer = this.experienceBuffers.get(model.agentId) || [];
    buffer.push(experience);
    
    // Keep buffer size limited
    const maxSize = model.hyperparameters.memorySize;
    if (buffer.length > maxSize) {
      buffer.splice(0, buffer.length - maxSize);
    }
    
    this.experienceBuffers.set(model.agentId, buffer);
    
    // Online learning update
    if (model.algorithm === RLAlgorithm.Q_LEARNING) {
      await this.trainQLearning(model, [experience], 1);
    }
  }

  private discretizeState(state: number[], stateSpace: number): number {
    // Convert continuous state to discrete index
    let index = 0;
    let multiplier = 1;
    
    for (let i = 0; i < state.length; i++) {
      const discretizedValue = Math.floor(state[i] * 10); // 10 bins per dimension
      index += discretizedValue * multiplier;
      multiplier *= 10;
    }
    
    return Math.min(index, stateSpace - 1);
  }

  private discretizeAction(action: string, actionSpace: number): number {
    // Convert action string to index
    const actionMap: { [key: string]: number } = {
      'buy': 0,
      'sell': 1,
      'hold': 2,
      'increase_price': 3,
      'decrease_price': 4,
      'add_liquidity': 5,
      'remove_liquidity': 6,
      'borrow': 7,
      'lend': 8,
      'hedge': 9
    };
    
    return Math.min(actionMap[action] || 0, actionSpace - 1);
  }

  private sampleBatch(experiences: ReinforcementLearningState[], batchSize: number): ReinforcementLearningState[] {
    const batch: ReinforcementLearningState[] = [];
    
    for (let i = 0; i < Math.min(batchSize, experiences.length); i++) {
      const randomIndex = Math.floor(Math.random() * experiences.length);
      batch.push(experiences[randomIndex]);
    }
    
    return batch;
  }

  private predictQValue(model: RLModel, state: number[], action: string): number {
    // Simplified neural network forward pass
    const { weights } = model.modelState;
    let input = state;
    
    for (let i = 0; i < weights.length; i++) {
      const layerWeights = weights[i];
      const output = [];
      
      for (let j = 0; j < layerWeights.length; j++) {
        let sum = 0;
        for (let k = 0; k < input.length; k++) {
          sum += input[k] * layerWeights[j][k];
        }
        output.push(Math.tanh(sum)); // Activation function
      }
      
      input = output;
    }
    
    return input[0] || 0; // Return Q-value
  }

  private predictMaxQValue(model: RLModel, state: number[]): number {
    // Predict maximum Q-value for all actions in given state
    const actions = ['buy', 'sell', 'hold', 'increase_price', 'decrease_price'];
    const qValues = actions.map(action => this.predictQValue(model, state, action));
    return Math.max(...qValues);
  }

  private predictActionProbabilities(model: any, state: number[]): number[] {
    // Predict action probabilities using policy network
    const logits = actions.map(action => this.predictQValue(model, state, action));
    return this.softmax(logits);
  }

  private predictValue(model: any, state: number[]): number {
    // Predict state value using critic/value network
    return this.predictQValue(model, state, 'hold'); // Simplified
  }

  private calculateAdvantage(model: RLModel, experience: ReinforcementLearningState): number {
    const value = this.predictValue(model.critic, experience.state);
    const nextValue = experience.done ? 0 : this.predictValue(model.critic, experience.nextState);
    const advantage = experience.reward + model.hyperparameters.discountFactor * nextValue - value;
    return advantage;
  }

  private calculatePPOLosses(model: RLModel, batch: ReinforcementLearningState[]): {
    policyLoss: number;
    valueLoss: number;
  } {
    let policyLoss = 0;
    let valueLoss = 0;
    
    for (const experience of batch) {
      const value = this.predictValue(model.value, experience.state);
      const target = experience.reward + model.hyperparameters.discountFactor * 
        (experience.done ? 0 : this.predictValue(model.value, experience.nextState));
      
      valueLoss += Math.pow(target - value, 2);
      
      // Policy loss (simplified)
      const actionProbabilities = this.predictActionProbabilities(model.policy, experience.state);
      const advantage = this.calculateAdvantage(model, experience);
      policyLoss -= advantage * Math.log(actionProbabilities[0] + 1e-8); // Add small epsilon
    }
    
    return {
      policyLoss: policyLoss / batch.length,
      valueLoss: valueLoss / batch.length
    };
  }

  private updateNetworkWeights(
    model: any,
    state: number[] | null,
    action: string | null,
    target: number,
    learningRate: number
  ): void {
    // Simplified weight update
    const { weights } = model;
    
    for (let i = 0; i < weights.length; i++) {
      for (let j = 0; j < weights[i].length; j++) {
        // Gradient descent update (simplified)
        weights[i][j] += learningRate * 0.01 * (target - Math.random()); // Simplified gradient
      }
    }
  }

  private updateActorWeights(
    model: any,
    state: number[],
    action: string,
    advantage: number,
    learningRate: number
  ): void {
    // Update actor network weights
    this.updateNetworkWeights(model, state, action, advantage, learningRate);
  }

  private updateCriticWeights(
    model: any,
    state: number[],
    target: number,
    learningRate: number
  ): void {
    // Update critic network weights
    this.updateNetworkWeights(model, state, null, target, learningRate);
  }

  private softmax(values: number[]): number[] {
    const max = Math.max(...values);
    const expValues = values.map(v => Math.exp(v - max));
    const sum = expValues.reduce((a, b) => a + b, 0);
    return expValues.map(v => v / sum);
  }

  private sampleFromDistribution(probabilities: number[]): number {
    const random = Math.random();
    let cumulative = 0;
    
    for (let i = 0; i < probabilities.length; i++) {
      cumulative += probabilities[i];
      if (random < cumulative) {
        return i;
      }
    }
    
    return probabilities.length - 1;
  }

  private updateExplorationRate(model: RLModel): number {
    // Decay exploration rate
    const decayRate = 0.995;
    const minExploration = 0.01;
    return Math.max(minExploration, model.performance.explorationRate * decayRate);
  }

  private calculateConvergenceRate(model: RLModel, experiences: ReinforcementLearningState[]): number {
    if (experiences.length < 100) return 0;
    
    const recent = experiences.slice(-100);
    const rewards = recent.map(exp => exp.reward);
    
    // Calculate moving average
    const movingAverage = rewards.reduce((sum, r) => sum + r, 0) / rewards.length;
    
    // Calculate variance
    const variance = rewards.reduce((sum, r) => sum + Math.pow(r - movingAverage, 2), 0) / rewards.length;
    
    // Convergence rate based on variance (lower variance = higher convergence)
    return 1 / (1 + variance);
  }

  getModelPerformance(modelId: string): RLPerformance | null {
    const model = this.models.get(modelId);
    return model ? model.performance : null;
  }

  getAllModels(): RLModel[] {
    return Array.from(this.models.values());
  }

  async saveModel(modelId: string): Promise<void> {
    const model = this.models.get(modelId);
    if (!model) return;

    // Save model state to database or file system
    this.logger.log(`Saving model ${modelId} with performance:`, model.performance);
    
    // This would integrate with your persistence layer
    // For now, just log the save
  }

  async loadModel(modelId: string): Promise<RLModel | null> {
    // Load model from database or file system
    // For now, return null
    return null;
  }
}
