import { Permission, Role } from '@prisma/client';

export const RolePermissions: Record<Role, Permission[]> = {
  [Role.SUPER_ADMIN]: [
    Permission.CREATE_PROJECT,
    Permission.UPDATE_PROJECT,
    Permission.DELETE_PROJECT,
    Permission.VIEW_PROJECT,
    Permission.MAKE_CONTRIBUTION,
    Permission.VIEW_CONTRIBUTION,
    Permission.MANAGE_USERS,
    Permission.MANAGE_ROLES,
    Permission.VIEW_SENSITIVE_DATA,
    Permission.MANAGE_SYSTEM,
  ],
  [Role.TENANT_ADMIN]: [
    Permission.CREATE_PROJECT,
    Permission.UPDATE_PROJECT,
    Permission.VIEW_PROJECT,
    Permission.MAKE_CONTRIBUTION,
    Permission.VIEW_CONTRIBUTION,
    Permission.MANAGE_USERS,
    Permission.VIEW_SENSITIVE_DATA,
  ],
  [Role.USER]: [
    Permission.CREATE_PROJECT,
    Permission.UPDATE_PROJECT,
    Permission.VIEW_PROJECT,
    Permission.MAKE_CONTRIBUTION,
    Permission.VIEW_CONTRIBUTION,
  ],
  [Role.VIEWER]: [Permission.VIEW_PROJECT, Permission.VIEW_CONTRIBUTION],
};
