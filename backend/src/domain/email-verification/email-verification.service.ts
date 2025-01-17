import { Injectable, NotFoundException } from '@nestjs/common';
import { Prisma, EmailVerification } from '@prisma/client';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';

import { PrismaService } from '@/database/prisma';

import { EmailVerifCreateDTO, EmailVerifUpdateDTO } from './dto';

@Injectable()
export class EmailVerifService {
  constructor(private readonly prismaService: PrismaService) { }

  public async getMany(params: Prisma.EmailVerificationFindManyArgs) {
    const emailVerifications = await this.prismaService.emailVerification.findMany(params);
    return emailVerifications;
  }

  public async getByUniqueParams(uniqueParams: Prisma.EmailVerificationFindUniqueArgs): Promise<EmailVerification> {
    const emailVerif = await this.prismaService.emailVerification.findUnique(uniqueParams);

    if (!emailVerif) {
      throw new NotFoundException('Requested verification record not found');
    }

    return emailVerif;
  }

  public async create(emailVerifCreateData: EmailVerifCreateDTO): Promise<EmailVerification> {
    const newEmailVerif = await this.prismaService.emailVerification.create({
      data: emailVerifCreateData,
    });

    return newEmailVerif;
  }

  public async update(emailVerifId: string, emailVerifUpdateData: EmailVerifUpdateDTO): Promise<EmailVerification> {
    try {
      const updatedEmailVerif = await this.prismaService.emailVerification.update({
        where: {
          id: emailVerifId,
        },
        data: emailVerifUpdateData,
      });

      return updatedEmailVerif;
    }
    catch (err) {
      if (err instanceof PrismaClientKnownRequestError && err.code === 'P2025') {
        throw new NotFoundException("Email verification to update not found");
      }

      throw err;
    }
  }
}
