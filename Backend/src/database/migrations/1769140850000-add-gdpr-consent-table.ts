import { MigrationInterface, QueryRunner, Table, TableIndex } from "typeorm";

export class AddGdprConsentTable1769140850000 implements MigrationInterface {
    name = 'AddGdprConsentTable1769140850000';
    version = '1.0.0';
    description = 'Add GDPR consent management table for tracking user consents';

    async up(queryRunner: QueryRunner): Promise<void> {
        // Create consents table
        await queryRunner.createTable(new Table({
            name: 'consents',
            columns: [
                {
                    name: 'id',
                    type: 'uuid',
                    isPrimary: true,
                    default: 'uuid_generate_v4()'
                },
                {
                    name: 'userId',
                    type: 'uuid',
                    isNullable: false
                },
                {
                    name: 'consentType',
                    type: 'varchar',
                    length: '50',
                    isNullable: false
                },
                {
                    name: 'status',
                    type: 'varchar',
                    length: '20',
                    default: "'granted'",
                    isNullable: false
                },
                {
                    name: 'version',
                    type: 'varchar',
                    length: '50',
                    isNullable: false
                },
                {
                    name: 'consentText',
                    type: 'text',
                    isNullable: true
                },
                {
                    name: 'grantedAt',
                    type: 'timestamp',
                    default: 'NOW()',
                    isNullable: false
                },
                {
                    name: 'withdrawnAt',
                    type: 'timestamp',
                    isNullable: true
                },
                {
                    name: 'expiresAt',
                    type: 'timestamp',
                    isNullable: true
                },
                {
                    name: 'updatedAt',
                    type: 'timestamp',
                    default: 'NOW()',
                    isNullable: false
                }
            ]
        }), true);

        // Create indexes
        await queryRunner.createIndex('consents', new TableIndex({
            name: 'IDX_CONSENTS_USER_CONSENT',
            columnNames: ['userId', 'consentType'],
            isUnique: true
        }));

        await queryRunner.createIndex('consents', new TableIndex({
            name: 'IDX_CONSENTS_USER_ID',
            columnNames: ['userId']
        }));

        await queryRunner.createIndex('consents', new TableIndex({
            name: 'IDX_CONSENTS_CONSENT_TYPE',
            columnNames: ['consentType']
        }));

        await queryRunner.createIndex('consents', new TableIndex({
            name: 'IDX_CONSENTS_STATUS',
            columnNames: ['status']
        }));
    }

    async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.dropTable('consents');
    }
}