import { Injectable, CanActivate, ExecutionContext, ForbiddenException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ROLES_KEY } from '../auth/decorators/roles.decorator';
import { Role } from '@prisma/client';

@Injectable()
export class SupportGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<Role[]>(ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (!requiredRoles) {
      return true;
    }

    const { user } = context.switchToHttp().getRequest();
    
    if (!user) {
      throw new ForbiddenException('User not authenticated');
    }

    const hasSupportRole = requiredRoles.some(role => 
      user.roles.includes(role) || 
      user.roles.includes(Role.SUPPORT_AGENT) || 
      user.roles.includes(Role.SUPPORT_MANAGER) ||
      user.roles.includes(Role.SUPER_ADMIN)
    );

    if (!hasSupportRole) {
      throw new ForbiddenException('Insufficient permissions. Support role required.');
    }

    return true;
  }
}
