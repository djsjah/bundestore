import { Injectable } from '@nestjs/common';
import { PrismaClient, Role } from '@prisma/client';
import { ITXClientDenyList } from '@prisma/client/runtime/library';

import { PrismaService } from '@/database/prisma';
import { UserSignUpDTO, TokenVerifDTO } from '@/domain/auth';

@Injectable()
export class UserAggregate {
  constructor(private readonly prismaService: PrismaService) {}

  public async applySignupTransaction(userSignupData: UserSignUpDTO, verifData: TokenVerifDTO): Promise<void> {
    await this.prismaService.$transaction(async (prisma: Omit<PrismaClient, ITXClientDenyList>) => {
      const newUser = await prisma.user.create({
        data: {
          email: userSignupData.email,
          password: userSignupData.password,
          role: Role.CUSTOMER,
        },
      });

      await prisma.emailVerification.create({
        data: {
          verifToken: verifData.token,
          userId: newUser.id,
        },
      });

      const customer = await prisma.customer.create({
        data: {
          firstName: userSignupData.firstName,
          lastName: userSignupData.lastName,
          birthDate: userSignupData.birthDate,
          phoneNumber: userSignupData.phoneNumber,
          userId: newUser.id,
        },
      });

      await prisma.cart.create({
        data: {
          customerId: customer.id,
        },
      });
    });
  }
}
