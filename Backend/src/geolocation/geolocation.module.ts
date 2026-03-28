import { Module, Global } from '@nestjs/common';
import { CircuitBreakerModule } from '../circuit-breaker/circuit-breaker.module';
import { GeolocationService } from './geolocation.service';
import { PrismaService } from '../prisma.service';

@Global()
@Module({
  imports: [CircuitBreakerModule],
  providers: [GeolocationService, PrismaService],
  exports: [GeolocationService],
})
export class GeolocationModule {}
