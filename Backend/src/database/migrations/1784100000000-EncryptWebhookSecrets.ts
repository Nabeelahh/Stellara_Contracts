import { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Widens the webhook_consumers.secret column to 512 chars to accommodate
 * AES-256-GCM encrypted values stored as `<iv_hex>:<tag_hex>:<ciphertext_hex>`.
 * The column was previously 100 chars (plaintext); now secrets are always
 * encrypted at rest and never returned from API responses.
 */
export class EncryptWebhookSecrets1784100000000 implements MigrationInterface {
  name = 'EncryptWebhookSecrets1784100000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE "webhook_consumers" ALTER COLUMN "secret" TYPE varchar(512)`,
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE "webhook_consumers" ALTER COLUMN "secret" TYPE varchar(100)`,
    );
  }
}
