import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import axios from 'axios';
import { CircuitBreakerService } from '../circuit-breaker/circuit-breaker.service';
import { PrismaService } from '../prisma.service';

@Injectable()
export class GeolocationService {
  private readonly logger = new Logger(GeolocationService.name);
  private readonly ipInfoToken: string;
  private readonly sanctionedCountries: string[];

  constructor(
    private configService: ConfigService,
    private prisma: PrismaService,
    private readonly circuitBreakerService: CircuitBreakerService,
  ) {
    this.ipInfoToken = this.configService.get<string>('IPINFO_TOKEN');
    this.sanctionedCountries = this.configService.get<string[]>('SANCTIONED_COUNTRIES', [
      'CU', 'IR', 'KP', 'SY', 'RU', 'BY'
    ]);
    this.circuitBreakerService.register('ip-geolocation-provider', {
      failureThreshold: 5,
      failureWindowMs: 10_000,
      openTimeoutMs: 30_000,
      halfOpenMaxCalls: 10,
      halfOpenSuccessThreshold: 3,
    });
  }

  async getLocation(ip: string) {
    if (ip === '::1' || ip === '127.0.0.1' || ip.startsWith('192.168.') || ip.startsWith('10.')) {
      return {
        country: 'US',
        region: 'California',
        city: 'Mountain View',
        latitude: 37.422,
        longitude: -122.084,
        isp: 'Localhost',
        isVpn: false,
        isTor: false,
        isProxy: false,
      };
    }

    try {
      const response = await this.circuitBreakerService.execute('ip-geolocation-provider', () =>
        axios.get(`https://ipinfo.io/${ip}?token=${this.ipInfoToken}`),
      );
      const [lat, lng] = (response.data.loc || '0,0').split(',').map(Number);
      
      return {
        country: response.data.country,
        region: response.data.region,
        city: response.data.city,
        latitude: lat,
        longitude: lng,
        isp: response.data.org,
        isVpn: response.data.privacy?.vpn || false,
        isTor: response.data.privacy?.tor || false,
        isProxy: response.data.privacy?.proxy || false,
      };
    } catch (error) {
      this.logger.error(`Failed to get location for IP ${ip}: ${error.message}`);
      // Fallback for demo/development if token is missing
      return {
        country: 'US',
        region: 'Unknown',
        city: 'Unknown',
        latitude: 0,
        longitude: 0,
        isp: 'Unknown',
        isVpn: false,
        isTor: false,
        isProxy: false,
      };
    }
  }

  async trackUserLocation(userId: string, ip: string, userAgent?: string) {
    const location = await this.getLocation(ip);
    if (!location) return null;

    const entry = await this.prisma.userLocation.create({
      data: {
        userId,
        ipAddress: ip,
        country: location.country,
        region: location.region,
        city: location.city,
        latitude: location.latitude,
        longitude: location.longitude,
        isp: location.isp,
        isVpn: location.isVpn,
        isTor: location.isTor,
        isProxy: location.isProxy,
        userAgent,
      },
    });

    return { ...location, id: entry.id };
  }

  isSanctioned(countryCode: string): boolean {
    return this.sanctionedCountries.includes(countryCode);
  }

  async checkImpossibleTravel(userId: string, currentLat: number, currentLng: number) {
    const lastLocation = await this.prisma.userLocation.findFirst({
      where: { userId },
      orderBy: { createdAt: 'desc' },
      skip: 1, // Skip the one we just created
    });

    if (!lastLocation || !lastLocation.latitude || !lastLocation.longitude) return false;

    const distance = this.calculateDistance(
      lastLocation.latitude,
      lastLocation.longitude,
      currentLat,
      currentLng
    );

    const timeDiffHours = (Date.now() - lastLocation.createdAt.getTime()) / (1000 * 60 * 60);
    
    // If distance is more than 500km and speed would be > 800km/h (speed of a plane)
    if (distance > 500 && distance / Math.max(timeDiffHours, 0.01) > 800) {
      return true;
    }

    return false;
  }

  private calculateDistance(lat1: number, lon1: number, lat2: number, lon2: number): number {
    const R = 6371; // Earth radius in km
    const dLat = (lat2 - lat1) * Math.PI / 180;
    const dLon = (lon2 - lon1) * Math.PI / 180;
    const a = 
      Math.sin(dLat/2) * Math.sin(dLat/2) +
      Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) * 
      Math.sin(dLon/2) * Math.sin(dLon/2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
    return R * c;
  }
}
