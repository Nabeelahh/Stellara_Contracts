import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import {
  ForbiddenError,
  InsufficientRoleError,
} from '../../common/exceptions/api-error.exception';

export const ROLES_KEY = 'roles';

export const Roles = (...roles: string[]) => {
  return (
    target: any,
    propertyKey?: string,
    descriptor?: PropertyDescriptor,
  ) => {
    if (propertyKey && descriptor) {
      Reflect.defineMetadata(ROLES_KEY, roles, descriptor.value);
      return descriptor;
    }
    Reflect.defineMetadata(ROLES_KEY, roles, target);
    return target;
  };
};

/**
 * Guard that enforces role-based access control for auth-module routes.
 *
 * Throws typed `ApiError` sub-classes so the `HttpExceptionFilter` can
 * render the standard error envelope:
 *
 * - No user / no role → `ForbiddenError`     (403, FORBIDDEN)
 * - Wrong role        → `InsufficientRoleError` (403, INSUFFICIENT_ROLE)
 */
@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.get<string[]>(
      ROLES_KEY,
      context.getHandler(),
    );

    if (!requiredRoles || requiredRoles.length === 0) {
      return true; // No roles required
    }

    const request = context.switchToHttp().getRequest();
    const user = request.user;

    if (!user || !user.role) {
      throw new ForbiddenError('User role not found');
    }

    const hasRole = requiredRoles.includes(user.role);

    if (!hasRole) {
      throw new InsufficientRoleError(requiredRoles, user.role);
    }

    return true;
  }
}
