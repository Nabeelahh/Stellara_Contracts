import { CanActivate, ExecutionContext, Injectable, ForbiddenException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { GeolocationService } from '../geolocation.service';

@Injectable()
export class GeolocationGuard implements CanActivate {
  constructor(
    private reflector: Reflector,
    private geoService: GeolocationService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const ip = request.ip || request.socket.remoteAddress || '127.0.0.1';

    const location = await this.geoService.getLocation(ip);
    
    if (this.geoService.isSanctioned(location.country)) {
      throw new ForbiddenException('Access from your location is restricted');
    }

    // Check for specific route restrictions if any
    const restrictedCountries = this.reflector.get<string[]>('restricted_countries', context.getHandler());
    if (restrictedCountries && restrictedCountries.includes(location.country)) {
      throw new ForbiddenException(`Access to this resource is restricted in ${location.country}`);
    }

    // Optional: Block high risk connections if configured
    const blockHighRisk = this.reflector.get<boolean>('block_high_risk', context.getHandler());
    if (blockHighRisk && (location.isVpn || location.isTor || location.isProxy)) {
      throw new ForbiddenException('High-risk connection detected. Please disable VPN/Tor/Proxy.');
    }

    return true;
  }
}
