import { Controller, Post, Get, Param, Body, Res, UseGuards } from '@nestjs/common';
import { Response } from 'express';
import { Role } from '@prisma/client';
import { ApiTags, ApiOperation, ApiParam, ApiBody, ApiResponse } from '@nestjs/swagger';

import { AuthGuard, RoleGuard } from '@/domain/auth/guards';
import { UseRole } from '@/utils';

import { UserService } from '../../service/user.service';
import { AdminService } from '../administrator';

import { ModeratorService } from './moderator.service';
import { ModeratorCreateDTO, ModeratorGetDTO } from './dto';

@ApiTags('Moderators')
@Controller('api/moderators')
@UseGuards(AuthGuard, RoleGuard)
@UseRole(Role.ADMINISTRATOR)
export class ModeratorController {
  constructor(
    private readonly moderatorService: ModeratorService,
    private readonly userService: UserService,
    private readonly adminService: AdminService,
  ) {}

  @ApiOperation({ summary: 'Get all Moderators' })
  @ApiResponse({ status: 200, description: 'Successful Response', type: [ModeratorGetDTO] })
  @ApiResponse({ status: 401, description: 'The user is not authorized in the system' })
  @ApiResponse({ status: 403, description: 'The user is not authorized in the system as an administrator' })
  @ApiResponse({ status: 500, description: 'Internal Server Error' })
  @Get()
  public async getAll(): Promise<ModeratorGetDTO[]> {
    const moderators = await this.moderatorService.getMany({});
    return moderators;
  }

  @ApiOperation({ summary: 'Get Moderator by Id' })
  @ApiParam({
    name: 'moderatorId',
    type: 'string',
    format: 'uuid',
    required: true,
    description: 'Moderator Id',
  })
  @ApiResponse({ status: 200, description: 'Moderator details', type: ModeratorGetDTO })
  @ApiResponse({ status: 401, description: 'The user is not authorized in the system' })
  @ApiResponse({ status: 403, description: 'The user is not authorized in the system as an administrator' })
  @ApiResponse({ status: 404, description: 'Not Found' })
  @ApiResponse({ status: 500, description: 'Internal Server Error' })
  @Get(':moderatorId')
  public async getUniqueById(@Param('moderatorId') moderatorId: string): Promise<ModeratorGetDTO> {
    const moderator = await this.moderatorService.getByUniqueParams({
      where: {
        id: moderatorId,
      },
    });

    return moderator;
  }

  @ApiOperation({ summary: 'Register Moderator' })
  @ApiBody({
    type: ModeratorCreateDTO,
    examples: {
      'User - Moderator': {
        value: {
          userId: '43062bf6-ac66-4c37-8d39-bf212f62aec3',
          administratorId: '9a7e5c92-e0b1-4fda-a8c3-1f2d3c4e5f67',
        },
      },
    },
  })
  @ApiResponse({ status: 200, description: 'Moderator Successfully Registered' })
  @ApiResponse({ status: 401, description: 'The user is not authorized in the system' })
  @ApiResponse({ status: 403, description: 'The user is not authorized in the system as an administrator' })
  @ApiResponse({ status: 404, description: 'Not Found' })
  @ApiResponse({ status: 500, description: 'Internal Server Error' })
  @Post()
  public async create(@Body() moderatorCreateData: ModeratorCreateDTO, @Res() res: Response): Promise<void> {
    await this.userService.getByUniqueParams({
      where: {
        id: moderatorCreateData.userId,
      },
    });

    await this.adminService.getByUniqueParams({
      where: {
        id: moderatorCreateData.administratorId,
      },
    });

    const newModerator = await this.moderatorService.create(moderatorCreateData);
    res.status(200).json({
      data: newModerator,
      message: 'Moderator successfully registered',
    });
  }
}
