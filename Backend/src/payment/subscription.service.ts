import { Injectable, Logger, NotFoundException, BadRequestException } from '@nestjs/common';
import { PrismaService } from '../prisma.service';
import { StripeService } from './stripe.service';
import { PaymentService } from './payment.service';
import { FraudService } from '../fraud/fraud.service';
import { SubscriptionStatus, PaymentEventType } from '@prisma/client';
import Stripe from 'stripe';

@Injectable()
export class SubscriptionService {
  private readonly logger = new Logger(SubscriptionService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly stripeService: StripeService,
    private readonly paymentService: PaymentService,
    private readonly fraudService: FraudService,
  ) {}

  async createSubscription(
    tenantId: string,
    planId: string,
    email: string,
    name: string,
    paymentMethodId?: string,
  ) {
    const existing = await this.prisma.subscription.findUnique({
      where: { tenantId },
    });

    if (existing) {
      throw new BadRequestException('Tenant already has a subscription');
    }

    const plan = await this.prisma.subscriptionPlan.findUnique({
      where: { id: planId },
    });

    if (!plan) {
      throw new NotFoundException('Subscription plan not found');
    }

    // Evaluate fraud score before creating customer/subscription
    try {
      const fraudResult = await this.fraudService.scorePayment({
        tenantId,
        email,
        paymentMethodId: paymentMethodId || null,
        planId,
        isNewTenant: !existing,
      });

      if (fraudResult.action === 'block') {
        this.logger.warn(
          `Fraud block for tenant ${tenantId}: ${fraudResult.reasons.join(', ')}`,
        );
        throw new BadRequestException('Payment blocked due to suspected fraud');
      }

      if (fraudResult.action === 'challenge') {
        this.logger.warn(
          `Fraud challenge for tenant ${tenantId}: ${fraudResult.reasons.join(', ')}`,
        );
        throw new BadRequestException('Payment requires additional verification');
      }
    } catch (err) {
      // If the fraud service throws unexpectedly, log and proceed conservatively by denying
      if (!(err instanceof BadRequestException)) {
        this.logger.error('Fraud scoring failed: ' + (err?.message || err));
        throw new BadRequestException('Payment blocked due to fraud scoring failure');
      }
      throw err;
    }

    // Create or get Stripe customer
    let customerId: string;
    try {
      const customer = await this.stripeService.createCustomer(email, name, { tenantId });
      customerId = customer.id;
    } catch (error) {
      this.logger.error(`Failed to create Stripe customer: ${error.message}`);
      throw new BadRequestException('Failed to create customer');
    }

    // Attach payment method if provided
    if (paymentMethodId) {
      await this.stripeService.attachPaymentMethod(customerId, paymentMethodId);
      await this.stripeService.setDefaultPaymentMethod(customerId, paymentMethodId);
    }

    // Create Stripe subscription
    let stripeSubscription: Stripe.Subscription;
    try {
      stripeSubscription = await this.stripeService.createSubscription(
        customerId,
        plan.stripePriceId,
        { tenantId, planId },
      );
    } catch (error) {
      this.logger.error(`Failed to create Stripe subscription: ${error.message}`);
      throw new BadRequestException('Failed to create subscription');
    }

    // Create local subscription record
    const subscription = await this.prisma.subscription.create({
      data: {
        tenantId,
        planId,
        stripeSubscriptionId: stripeSubscription.id,
        stripeCustomerId: customerId,
        status: this.mapStripeStatus(stripeSubscription.status),
        currentPeriodStart: new Date(stripeSubscription.current_period_start * 1000),
        currentPeriodEnd: new Date(stripeSubscription.current_period_end * 1000),
        trialStart: stripeSubscription.trial_start
          ? new Date(stripeSubscription.trial_start * 1000)
          : null,
        trialEnd: stripeSubscription.trial_end
          ? new Date(stripeSubscription.trial_end * 1000)
          : null,
      },
    });

    // Log the event
    await this.paymentService.logPaymentEvent(
      tenantId,
      PaymentEventType.SUBSCRIPTION_CREATED,
      subscription.id,
      { planId, stripeSubscriptionId: stripeSubscription.id },
    );

    this.logger.log(`Created subscription ${subscription.id} for tenant ${tenantId}`);
    return subscription;
  }

  async updateSubscription(subscriptionId: string, planId?: string, cancelAtPeriodEnd?: boolean) {
    const subscription = await this.prisma.subscription.findUnique({
      where: { id: subscriptionId },
    });

    if (!subscription) {
      throw new NotFoundException('Subscription not found');
    }

    const updateData: Stripe.SubscriptionUpdateParams = {};

    if (planId && planId !== subscription.planId) {
      const plan = await this.prisma.subscriptionPlan.findUnique({
        where: { id: planId },
      });

      if (!plan) {
        throw new NotFoundException('Subscription plan not found');
      }

      updateData.items = [{ price: plan.stripePriceId }];
    }

    if (typeof cancelAtPeriodEnd === 'boolean') {
      updateData.cancel_at_period_end = cancelAtPeriodEnd;
    }

    // Update Stripe subscription
    const stripeSubscription = await this.stripeService.updateSubscription(
      subscription.stripeSubscriptionId,
      updateData,
    );

    // Update local record
    const updated = await this.prisma.subscription.update({
      where: { id: subscriptionId },
      data: {
        ...(planId && { planId }),
        ...(typeof cancelAtPeriodEnd === 'boolean' && {
          cancelAtPeriodEnd,
        }),
        status: this.mapStripeStatus(stripeSubscription.status),
        currentPeriodStart: new Date(stripeSubscription.current_period_start * 1000),
        currentPeriodEnd: new Date(stripeSubscription.current_period_end * 1000),
      },
    });

    await this.paymentService.logPaymentEvent(
      subscription.tenantId,
      PaymentEventType.SUBSCRIPTION_UPDATED,
      subscriptionId,
      { planId, cancelAtPeriodEnd },
    );

    return updated;
  }

  async cancelSubscription(subscriptionId: string, immediate: boolean = false) {
    const subscription = await this.prisma.subscription.findUnique({
      where: { id: subscriptionId },
    });

    if (!subscription) {
      throw new NotFoundException('Subscription not found');
    }

    // Cancel in Stripe
    await this.stripeService.cancelSubscription(
      subscription.stripeSubscriptionId,
      !immediate,
    );

    // Update local record
    const updated = await this.prisma.subscription.update({
      where: { id: subscriptionId },
      data: {
        status: immediate ? SubscriptionStatus.CANCELLED : subscription.status,
        cancelAtPeriodEnd: !immediate,
        canceledAt: immediate ? new Date() : null,
      },
    });

    await this.paymentService.logPaymentEvent(
      subscription.tenantId,
      PaymentEventType.SUBSCRIPTION_CANCELLED,
      subscriptionId,
      { immediate },
    );

    this.logger.log(`Cancelled subscription ${subscriptionId} (immediate: ${immediate})`);
    return updated;
  }

  async getSubscription(subscriptionId: string) {
    const subscription = await this.prisma.subscription.findUnique({
      where: { id: subscriptionId },
      include: {
        plan: true,
        invoices: {
          orderBy: { createdAt: 'desc' },
          take: 12,
        },
        usageRecords: {
          orderBy: { timestamp: 'desc' },
          take: 100,
        },
      },
    });

    if (!subscription) {
      throw new NotFoundException('Subscription not found');
    }

    return subscription;
  }

  async getSubscriptionByTenant(tenantId: string) {
    return this.prisma.subscription.findUnique({
      where: { tenantId },
      include: {
        plan: true,
      },
    });
  }

  async listSubscriptionPlans() {
    return this.prisma.subscriptionPlan.findMany({
      where: { isActive: true },
      orderBy: { amount: 'asc' },
    });
  }

  async syncSubscriptionFromStripe(stripeSubscriptionId: string) {
    const stripeSubscription =
      await this.stripeService.getClient().subscriptions.retrieve(stripeSubscriptionId);

    const subscription = await this.prisma.subscription.findUnique({
      where: { stripeSubscriptionId },
    });

    if (!subscription) {
      this.logger.warn(`Subscription ${stripeSubscriptionId} not found in database`);
      return null;
    }

    return this.prisma.subscription.update({
      where: { id: subscription.id },
      data: {
        status: this.mapStripeStatus(stripeSubscription.status),
        currentPeriodStart: new Date(stripeSubscription.current_period_start * 1000),
        currentPeriodEnd: new Date(stripeSubscription.current_period_end * 1000),
        cancelAtPeriodEnd: stripeSubscription.cancel_at_period_end,
        canceledAt: stripeSubscription.canceled_at
          ? new Date(stripeSubscription.canceled_at * 1000)
          : null,
      },
    });
  }

  private mapStripeStatus(stripeStatus: Stripe.Subscription.Status): SubscriptionStatus {
    const statusMap: Record<string, SubscriptionStatus> = {
      active: SubscriptionStatus.ACTIVE,
      canceled: SubscriptionStatus.CANCELLED,
      incomplete: SubscriptionStatus.UNPAID,
      incomplete_expired: SubscriptionStatus.UNPAID,
      past_due: SubscriptionStatus.PAST_DUE,
      paused: SubscriptionStatus.PAUSED,
      trialing: SubscriptionStatus.TRIALING,
      unpaid: SubscriptionStatus.UNPAID,
    };

    return statusMap[stripeStatus] || SubscriptionStatus.UNPAID;
  }
}
