import { SetMetadata } from '@nestjs/common';
import { Role } from '@prisma/client';

export const UseRole = (role: Role) => SetMetadata('role', role);
