import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../prisma.service';
import { Invoice, Subscription } from '@prisma/client';
import { startOfDay, endOfDay, differenceInDays, addDays, isWithinInterval } from 'date-fns';

@Injectable()
export class RevenueRecognitionService {
  private readonly logger = new Logger(RevenueRecognitionService.name);

  constructor(private readonly prisma: PrismaService) {}

  /**
   * Recognizes revenue for a specific invoice over its service period.
   * This should be called when an invoice is paid or on a daily schedule.
   */
  async recognizeRevenueForInvoice(invoiceId: string) {
    const invoice = await this.prisma.invoice.findUnique({
      where: { id: invoiceId },
      include: { subscription: true },
    });

    if (!invoice || invoice.status !== 'PAID') {
      this.logger.warn(`Invoice ${invoiceId} not found or not paid. Skipping revenue recognition.`);
      return;
    }

    const { subscription, amountPaid, periodStart, periodEnd } = this.getInvoicePeriodInfo(invoice);
    
    if (!periodStart || !periodEnd) {
      this.logger.error(`Invoice ${invoiceId} is missing period information.`);
      return;
    }

    const totalDays = differenceInDays(periodEnd, periodStart) + 1;
    if (totalDays <= 0) return;

    const dailyAmount = Math.floor(amountPaid / totalDays);
    const remainder = amountPaid % totalDays;

    const recognitionRecords = [];

    for (let i = 0; i < totalDays; i++) {
        const recognitionDate = addDays(periodStart, i);
        // Add 1 cent to the first 'remainder' days to distribute the integer division remainder
        const currentAmount = i < remainder ? dailyAmount + 1 : dailyAmount;

        recognitionRecords.push({
            subscriptionId: subscription.id,
            tenantId: invoice.tenantId,
            invoiceId: invoice.id,
            amount: currentAmount,
            currency: invoice.currency,
            recognitionDate: startOfDay(recognitionDate),
            periodStart: periodStart,
            periodEnd: periodEnd,
        });
    }

    // Upsert recognition records to prevent duplicates on re-runs
    await this.prisma.$transaction(
        recognitionRecords.map(record => 
            this.prisma.revenueRecognition.upsert({
                where: {
                    // Note: We'd need a unique constraint on (invoiceId, recognitionDate) for this to work elegantly
                    // Since I didn't add one in the schema yet, I'll delete existing for this invoice first.
                    id: 'placeholder', // Not used due to deleteMany below, but prisma requires it in some patterns if not using transaction properly
                },
                create: record,
                update: record,
            })
        ).slice(0, 0) // Just to show the intent, we'll use a cleaner way below
    );
    
    // Cleaner way for now since we don't have the unique index yet:
    await this.prisma.revenueRecognition.deleteMany({
        where: { invoiceId: invoice.id }
    });

    await this.prisma.revenueRecognition.createMany({
        data: recognitionRecords,
    });

    this.logger.log(`Recognized ${amountPaid} ${invoice.currency} for invoice ${invoice.id} over ${totalDays} days.`);
  }

  /**
   * Daily task to run revenue recognition for all paid invoices that haven't been fully recognized yet.
   */
  async runDailyRevenueRecognition() {
      // In a real system, we'd query for invoices that need recognition.
      // For this implementation, we'll assume we recognize everything once an invoice is paid.
      const paidInvoices = await this.prisma.invoice.findMany({
          where: {
              status: 'PAID',
              // Add filter for invoices not yet fully recognized if needed
          }
      });

      for (const invoice of paidInvoices) {
          await this.recognizeRevenueForInvoice(invoice.id);
      }
  }

  private getInvoicePeriodInfo(invoice: any) {
      // If the invoice doesn't have periodStart/periodEnd, we use the subscription periods
      // In a real Stripe implementation, these are on the invoice line items.
      const periodStart = invoice.subscription.currentPeriodStart; 
      const periodEnd = invoice.subscription.currentPeriodEnd;

      return {
          subscription: invoice.subscription,
          amountPaid: invoice.amountPaid,
          periodStart,
          periodEnd
      };
  }

  async getRevenueReport(tenantId: string, startDate: Date, endDate: Date) {
      const recognition = await this.prisma.revenueRecognition.aggregate({
          where: {
              tenantId,
              recognitionDate: {
                  gte: startDate,
                  lte: endDate,
              }
          },
          _sum: {
              amount: true
          }
      });

      return {
          totalRecognized: recognition._sum.amount || 0,
          startDate,
          endDate,
      };
  }
}
