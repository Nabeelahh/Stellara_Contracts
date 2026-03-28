import { Injectable, CanActivate, ExecutionContext, ForbiddenException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Role, Permission } from '@prisma/client';
import { ROLES_KEY } from '../decorators/roles.decorator';
import { PERMISSIONS_KEY } from '../decorators/permissions.decorator';
import { RolePermissions } from '../constants/role-permissions';

@Injectable()
export class PermissionsGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<Role[]>(ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    const requiredPermissions = this.reflector.getAllAndOverride<Permission[]>(PERMISSIONS_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (!requiredRoles && !requiredPermissions) {
      return true;
    }

    const { user } = context.switchToHttp().getRequest();
    if (!user || !user.roles) {
      throw new ForbiddenException('User session missing roles');
    }

    // Role-based check (Hierarchical or Simple)
    const hasRole = !requiredRoles || requiredRoles.some((role) => user.roles.includes(role));

    // Permission-based check
    let hasPermission = true;
    if (requiredPermissions) {
      const userPermissions = user.roles.flatMap((role: Role) => RolePermissions[role] || []);
      hasPermission = requiredPermissions.every((permission) =>
        userPermissions.includes(permission),
      );
    }

    if (hasRole && hasPermission) {
      return true;
    }

    throw new ForbiddenException(
      'You do not have the required permissions to access this resource',
    );
  }
}
