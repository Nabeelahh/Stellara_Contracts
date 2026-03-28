import { Controller, Get, ServiceUnavailableException } from '@nestjs/common';
import { SkipRateLimit } from '../common/decorators/skip-rate-limit.decorator';
import { ApplicationStateService } from './application-state.service';

@Controller()
@SkipRateLimit()
export class HealthController {
  constructor(private readonly appState: ApplicationStateService) {}

  @Get('health')
  getHealth(): any {
    return this.appState.getHealthSnapshot();
  }

  @Get('health/deployment')
  getDeploymentHealth(): any {
    return this.appState.getHealthSnapshot().deployment;
  }

  @Get('health/live')
  getLiveness(): any {
    return this.appState.getLivenessSnapshot();
  }

  @Get('health/ready')
  getReadiness(): any {
    if (!this.appState.isReady()) {
      throw new ServiceUnavailableException(this.appState.getReadinessSnapshot());
    }

    return this.appState.getReadinessSnapshot();
  }
}
