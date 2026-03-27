import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { IdentityService } from './identity.service';
import { IdentityController } from './identity.controller';

@Module({
  imports: [ConfigModule],
  providers: [IdentityService],
  controllers: [IdentityController],
  exports: [IdentityService],
})
export class IdentityModule {}
