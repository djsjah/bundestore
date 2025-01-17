import { Controller, Get, Param, Res, UseGuards } from '@nestjs/common';
import { Response } from 'express';
import { ApiTags, ApiOperation, ApiParam, ApiResponse } from '@nestjs/swagger';
import { Role } from '@prisma/client';

import { UseRole } from '@/utils';

import { AuthGuard, RoleGuard } from '../auth/guards';

import { EmailVerifService } from './email-verification.service';

@ApiTags('Email Verification')
@Controller('api/email-verification')
@UseGuards(AuthGuard, RoleGuard)
@UseRole(Role.ADMINISTRATOR)
export class EmailVerifController {
  constructor(private readonly emailVerifService: EmailVerifService) {}

  @ApiOperation({ summary: 'Get all Verification Records' })
  @ApiResponse({ status: 200, description: 'Successful Response' })
  @ApiResponse({ status: 401, description: 'Not Authorized' })
  @ApiResponse({ status: 403, description: 'Not Authorized as Administrator' })
  @ApiResponse({ status: 500, description: 'Internal Server Error' })
  @Get()
  public async getAll(@Res() res: Response): Promise<void> {
    const emailVerifications = await this.emailVerifService.getMany({});
    res.status(200).json(emailVerifications);
  }

  @ApiOperation({ summary: 'Get Verification Record By Id' })
  @ApiParam({
    name: 'emailVerifId',
    type: 'string',
    format: 'uuid',
    required: true,
    description: 'Veriificaton record Id',
  })
  @ApiResponse({ status: 200, description: 'Successful Response' })
  @ApiResponse({ status: 401, description: 'Not Authorized' })
  @ApiResponse({ status: 403, description: 'Not Authorized as Administrator' })
  @ApiResponse({ status: 404, description: 'Not Found' })
  @ApiResponse({ status: 500, description: 'Internal Server Error' })
  @Get(':emailVerifId')
  public async getUniqueById(@Param('emailVerifId') emailVerifId: string, @Res() res: Response): Promise<void> {
    const emailVerification = await this.emailVerifService.getByUniqueParams({
      where: {
        id: emailVerifId,
      },
    });

    res.status(200).json(emailVerification);
  }
}
