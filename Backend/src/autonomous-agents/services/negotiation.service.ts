import { Injectable, Logger } from '@nestjs/common';
import { 
  Negotiation,
  NegotiationMessage,
  NegotiationProtocol,
  NegotiationType,
  NegotiationStatus,
  MessageType,
  MessageContent,
  NegotiationTerms,
  NegotiationOutcome,
  OutcomeType,
  Agent,
  DecisionRationale
} from '../interfaces/agent.interface';

@Injectable()
export class NegotiationService {
  private readonly logger = new Logger(NegotiationService.name);
  private activeNegotiations = new Map<string, Negotiation>();
  private messageQueue = new Map<string, NegotiationMessage[]>();

  async initiateNegotiation(
    initiatorId: string,
    participantId: string,
    type: NegotiationType,
    protocol: NegotiationProtocol,
    initialTerms: NegotiationTerms
  ): Promise<Negotiation> {
    const negotiationId = `neg_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    
    const negotiation: Negotiation = {
      id: negotiationId,
      participants: [initiatorId, participantId],
      type,
      status: NegotiationStatus.INITIATED,
      protocol,
      messages: [],
      startTime: new Date()
    };

    this.activeNegotiations.set(negotiationId, negotiation);
    
    // Send initial offer
    const initialMessage: NegotiationMessage = {
      id: `msg_${Date.now()}`,
      senderId: initiatorId,
      receiverId: participantId,
      type: MessageType.OFFER,
      content: {
        terms: initialTerms,
        expiration: new Date(Date.now() + 300000) // 5 minutes
      },
      timestamp: new Date()
    };

    await this.sendMessage(initialMessage);
    
    negotiation.status = NegotiationStatus.IN_PROGRESS;
    negotiation.messages.push(initialMessage);

    this.logger.log(`Initiated negotiation ${negotiationId} between ${initiatorId} and ${participantId}`);
    
    return negotiation;
  }

  async sendMessage(message: NegotiationMessage): Promise<void> {
    // Queue message for processing
    if (!this.messageQueue.has(message.receiverId)) {
      this.messageQueue.set(message.receiverId, []);
    }
    
    this.messageQueue.get(message.receiverId)!.push(message);
    
    // Process message based on negotiation protocol
    await this.processMessage(message);
  }

  private async processMessage(message: NegotiationMessage): Promise<void> {
    const negotiation = this.findNegotiationForMessage(message);
    if (!negotiation) {
      this.logger.warn(`No negotiation found for message ${message.id}`);
      return;
    }

    switch (message.type) {
      case MessageType.OFFER:
        await this.handleOffer(message, negotiation);
        break;
      
      case MessageType.COUNTER_OFFER:
        await this.handleCounterOffer(message, negotiation);
        break;
      
      case MessageType.ACCEPT:
        await this.handleAccept(message, negotiation);
        break;
      
      case MessageType.REJECT:
        await this.handleReject(message, negotiation);
        break;
      
      case MessageType.QUERY:
        await this.handleQuery(message, negotiation);
        break;
      
      default:
        this.logger.warn(`Unknown message type: ${message.type}`);
    }
  }

  private async handleOffer(message: NegotiationMessage, negotiation: Negotiation): Promise<void> {
    const receiverAgent = await this.getAgent(message.receiverId);
    if (!receiverAgent) return;

    // Evaluate offer against agent's utility function
    const utility = await this.evaluateOfferUtility(message.content.terms, receiverAgent);
    
    // Generate decision rationale
    const rationale = await this.generateDecisionRationale(
      message.content.terms,
      receiverAgent,
      utility
    );

    // Decide whether to accept, counter, or reject
    const decision = await this.makeNegotiationDecision(utility, rationale);
    
    let responseType: MessageType;
    let responseTerms: NegotiationTerms | undefined;

    switch (decision) {
      case 'accept':
        responseType = MessageType.ACCEPT;
        break;
      
      case 'counter':
        responseType = MessageType.COUNTER_OFFER;
        responseTerms = await this.generateCounterOffer(message.content.terms, receiverAgent);
        break;
      
      case 'reject':
        responseType = MessageType.REJECT;
        break;
      
      default:
        responseType = MessageType.REJECT;
    }

    const responseMessage: NegotiationMessage = {
      id: `msg_${Date.now()}`,
      senderId: message.receiverId,
      receiverId: message.senderId,
      type: responseType,
      content: {
        terms: responseTerms || message.content.terms,
        rationale
      },
      timestamp: new Date(),
      utility,
      confidence: rationale.confidence
    };

    await this.sendMessage(responseMessage);
    negotiation.messages.push(responseMessage);
  }

  private async handleCounterOffer(message: NegotiationMessage, negotiation: Negotiation): Promise<void> {
    // Similar to handleOffer but with counter-offer logic
    await this.handleOffer(message, negotiation);
  }

  private async handleAccept(message: NegotiationMessage, negotiation: Negotiation): Promise<void> {
    negotiation.status = NegotiationStatus.ACCEPTED;
    negotiation.endTime = new Date();
    
    // Create outcome
    const outcome: NegotiationOutcome = {
      type: OutcomeType.AGREEMENT,
      terms: message.content.terms!,
      utility: await this.calculateUtilitiesForAllParticipants(negotiation),
      timestamp: new Date(),
      rationale: message.content.rationale
    };

    negotiation.outcome = outcome;
    
    // Execute the agreed terms
    await this.executeNegotiationOutcome(negotiation, outcome);
    
    this.logger.log(`Negotiation ${negotiation.id} accepted and executed`);
  }

  private async handleReject(message: NegotiationMessage, negotiation: Negotiation): Promise<void> {
    negotiation.status = NegotiationStatus.REJECTED;
    negotiation.endTime = new Date();
    
    const outcome: NegotiationOutcome = {
      type: OutcomeType.DISAGREEMENT,
      terms: message.content.terms!,
      utility: {},
      timestamp: new Date(),
      rationale: message.content.rationale
    };

    negotiation.outcome = outcome;
    
    this.logger.log(`Negotiation ${negotiation.id} rejected`);
  }

  private async handleQuery(message: NegotiationMessage, negotiation: Negotiation): Promise<void> {
    // Handle information requests during negotiation
    const responseMessage: NegotiationMessage = {
      id: `msg_${Date.now()}`,
      senderId: message.receiverId,
      receiverId: message.senderId,
      type: MessageType.INFO,
      content: {
        terms: message.content.terms,
        rationale: {
          primaryFactor: 'Information request',
          factors: [],
          confidence: 1.0,
          ethicalConsiderations: [],
          alternatives: [],
          reasoning: 'Providing requested information'
        }
      },
      timestamp: new Date()
    };

    await this.sendMessage(responseMessage);
    negotiation.messages.push(responseMessage);
  }

  private findNegotiationForMessage(message: NegotiationMessage): Negotiation | null {
    for (const negotiation of this.activeNegotiations.values()) {
      if (negotiation.participants.includes(message.senderId) && 
          negotiation.participants.includes(message.receiverId)) {
        return negotiation;
      }
    }
    return null;
  }

  private async evaluateOfferUtility(terms: NegotiationTerms, agent: Agent): Promise<number> {
    // This would integrate with the utility function service
    // For now, provide a basic implementation
    
    let utility = 0;
    
    // Price utility (lower is better for buyer, higher for seller)
    if (terms.price) {
      utility += agent.type === 'buyer' ? -terms.price : terms.price;
    }
    
    // Quantity utility (more is better)
    utility += terms.quantity * 0.1;
    
    // Duration utility (shorter is better for most cases)
    if (terms.duration) {
      utility -= terms.duration * 0.01;
    }
    
    // Interest rate utility (lower is better)
    if (terms.interestRate) {
      utility -= terms.interestRate * 100;
    }
    
    return utility;
  }

  private async generateDecisionRationale(
    terms: NegotiationTerms,
    agent: Agent,
    utility: number
  ): Promise<DecisionRationale> {
    return {
      primaryFactor: utility > 0 ? 'Positive utility' : 'Negative utility',
      factors: [
        {
          name: 'Price evaluation',
          weight: 0.4,
          value: terms.price || 0,
          impact: terms.price && terms.price > 1000 ? 'negative' : 'positive'
        },
        {
          name: 'Quantity assessment',
          weight: 0.3,
          value: terms.quantity,
          impact: terms.quantity > 100 ? 'positive' : 'neutral'
        },
        {
          name: 'Risk consideration',
          weight: 0.3,
          value: 0.5, // Placeholder risk score
          impact: 'neutral'
        }
      ],
      confidence: Math.min(Math.abs(utility) / 10, 1),
      ethicalConsiderations: [
        {
          type: 'fairness',
          constraint: 'Price must be within market range',
          satisfied: true,
          impact: 0.8
        }
      ],
      alternatives: [
        {
          description: 'Wait for better offer',
          expectedUtility: utility + 0.1,
          risk: 0.2,
          rejected: false,
          reason: 'Current offer not optimal'
        }
      ],
      reasoning: `Offer evaluated with utility score of ${utility}. Decision based on weighted factors including price, quantity, and risk considerations.`
    };
  }

  private async makeNegotiationDecision(
    utility: number,
    rationale: DecisionRationale
  ): Promise<'accept' | 'counter' | 'reject'> {
    // Decision threshold based on utility and confidence
    const adjustedUtility = utility * rationale.confidence;
    
    if (adjustedUtility > 5) {
      return 'accept';
    } else if (adjustedUtility > 2) {
      return 'counter';
    } else {
      return 'reject';
    }
  }

  private async generateCounterOffer(
    originalTerms: NegotiationTerms,
    agent: Agent
  ): Promise<NegotiationTerms> {
    // Generate a counter offer based on agent's preferences
    const counterTerms: NegotiationTerms = { ...originalTerms };
    
    // Adjust price based on agent type
    if (originalTerms.price) {
      const priceAdjustment = agent.type === 'buyer' ? -0.05 : 0.05; // 5% adjustment
      counterTerms.price = originalTerms.price * (1 + priceAdjustment);
    }
    
    // Adjust quantity
    if (originalTerms.quantity > 100) {
      counterTerms.quantity = originalTerms.quantity * 0.9; // Reduce by 10%
    }
    
    return counterTerms;
  }

  private async calculateUtilitiesForAllParticipants(
    negotiation: Negotiation
  ): Promise<{ [agentId: string]: number }> {
    const utilities: { [agentId: string]: number } = {};
    
    for (const participantId of negotiation.participants) {
      const agent = await this.getAgent(participantId);
      if (agent && negotiation.outcome) {
        utilities[participantId] = await this.evaluateOfferUtility(
          negotiation.outcome.terms,
          agent
        );
      }
    }
    
    return utilities;
  }

  private async executeNegotiationOutcome(
    negotiation: Negotiation,
    outcome: NegotiationOutcome
  ): Promise<void> {
    // This would integrate with smart contracts for actual execution
    this.logger.log(`Executing negotiation outcome for ${negotiation.id}:`, outcome);
    
    // Remove from active negotiations
    this.activeNegotiations.delete(negotiation.id);
  }

  private async getAgent(agentId: string): Promise<Agent | null> {
    // This would fetch agent from database or agent service
    // For now, return a mock agent
    return {
      id: agentId,
      name: `Agent ${agentId}`,
      type: 'market_maker',
      status: 'active',
      utilityFunction: {} as any,
      strategies: [],
      resources: [],
      constraints: [],
      reputation: 0.8,
      createdAt: new Date(),
      lastActive: new Date()
    };
  }

  getActiveNegotiations(agentId?: string): Negotiation[] {
    const negotiations = Array.from(this.activeNegotiations.values());
    
    if (agentId) {
      return negotiations.filter(neg => neg.participants.includes(agentId));
    }
    
    return negotiations;
  }

  getNegotiationHistory(agentId: string): Negotiation[] {
    // This would fetch from database
    return [];
  }

  getMessagesForAgent(agentId: string): NegotiationMessage[] {
    return this.messageQueue.get(agentId) || [];
  }

  async timeoutNegotiation(negotiationId: string): Promise<void> {
    const negotiation = this.activeNegotiations.get(negotiationId);
    if (!negotiation) return;

    negotiation.status = NegotiationStatus.EXPIRED;
    negotiation.endTime = new Date();

    const outcome: NegotiationOutcome = {
      type: OutcomeType.TIMEOUT,
      terms: negotiation.messages[negotiation.messages.length - 1]?.content.terms || {} as NegotiationTerms,
      utility: {},
      timestamp: new Date()
    };

    negotiation.outcome = outcome;
    this.activeNegotiations.delete(negotiationId);

    this.logger.log(`Negotiation ${negotiationId} timed out`);
  }

  // Advanced negotiation protocols

  async mediatedNegotiation(
    participants: string[],
    mediatorId: string,
    type: NegotiationType,
    initialTerms: NegotiationTerms
  ): Promise<Negotiation> {
    const negotiationId = `med_neg_${Date.now()}`;
    
    const negotiation: Negotiation = {
      id: negotiationId,
      participants: [...participants, mediatorId],
      type,
      status: NegotiationStatus.INITIATED,
      protocol: NegotiationProtocol.MEDIATED,
      messages: [],
      startTime: new Date()
    };

    this.activeNegotiations.set(negotiationId, negotiation);

    // Send initial terms to mediator
    const mediatorMessage: NegotiationMessage = {
      id: `msg_${Date.now()}`,
      senderId: participants[0], // First participant as initiator
      receiverId: mediatorId,
      type: MessageType.OFFER,
      content: {
        terms: initialTerms
      },
      timestamp: new Date()
    };

    await this.sendMessage(mediatorMessage);
    negotiation.messages.push(mediatorMessage);

    return negotiation;
  }

  async auctionNegotiation(
    auctioneerId: string,
    bidders: string[],
    asset: string,
    startingPrice: number,
    duration: number
  ): Promise<Negotiation> {
    const negotiationId = `auc_neg_${Date.now()}`;
    
    const negotiation: Negotiation = {
      id: negotiationId,
      participants: [auctioneerId, ...bidders],
      type: NegotiationType.TRADE,
      status: NegotiationStatus.IN_PROGRESS,
      protocol: NegotiationProtocol.AUCTION,
      messages: [],
      startTime: new Date()
    };

    this.activeNegotiations.set(negotiationId, negotiation);

    // Send auction announcement to all bidders
    for (const bidderId of bidders) {
      const auctionMessage: NegotiationMessage = {
        id: `msg_${Date.now()}_${bidderId}`,
        senderId: auctioneerId,
        receiverId: bidderId,
        type: MessageType.INFO,
        content: {
          terms: {
            asset,
            quantity: 1,
            price: startingPrice,
            currency: 'USD',
            conditions: [`Auction duration: ${duration}ms`]
          }
        },
        timestamp: new Date()
      };

      await this.sendMessage(auctionMessage);
      negotiation.messages.push(auctionMessage);
    }

    // Set timeout for auction end
    setTimeout(() => {
      this.finalizeAuction(negotiationId);
    }, duration);

    return negotiation;
  }

  private async finalizeAuction(negotiationId: string): Promise<void> {
    const negotiation = this.activeNegotiations.get(negotiationId);
    if (!negotiation) return;

    // Find highest bid
    const bids = negotiation.messages.filter(msg => msg.type === MessageType.OFFER);
    let highestBid = bids[0];
    
    for (const bid of bids) {
      if (bid.content.terms.price && (!highestBid || 
          bid.content.terms.price > highestBid.content.terms.price!)) {
        highestBid = bid;
      }
    }

    if (highestBid) {
      // Accept highest bid
      await this.handleAccept(highestBid, negotiation);
    } else {
      // No bids received
      negotiation.status = NegotiationStatus.EXPIRED;
      negotiation.endTime = new Date();
    }
  }
}
