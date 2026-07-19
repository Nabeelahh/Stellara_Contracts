import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ROLES_KEY } from '../decorators/roles.decorator';
import { Role } from '../auth/roles.enum';
import {
  ForbiddenError,
  InsufficientRoleError,
} from '../common/exceptions/api-error.exception';

/**
 * Guard that enforces role-based access control (RBAC) on routes decorated
 * with `@Roles(Role.ADMIN)` (or similar).
 *
 * Throws typed `ApiError` sub-classes so the `HttpExceptionFilter` can
 * render the standard error envelope:
 *
 * - No user / no role attached to the request → `ForbiddenError` (403, FORBIDDEN)
 * - User role not in the required list        → `InsufficientRoleError` (403, INSUFFICIENT_ROLE)
 */
@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<Role[]>(ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (!requiredRoles || requiredRoles.length === 0) {
      return true;
    }

    const request = context.switchToHttp().getRequest();
    const user = request.user;

    if (!user || !user.role) {
      throw new ForbiddenError('User role not found');
    }

    if (!requiredRoles.includes(user.role)) {
      throw new InsufficientRoleError(requiredRoles, user.role);
    }

    return true;
  }
}
