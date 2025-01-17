import { Controller, Post, Patch, Res, Param, Body, UseGuards } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiBody, ApiResponse } from '@nestjs/swagger';
import { Response } from 'express';
import { Role } from '@prisma/client';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';

import { AuthGuard, RoleGuard } from '@/domain/auth';
import { UseRole } from '@/utils';

import { AccessoryCreateDTO } from './dto/accessory.create.dto';
import { AccessoryUpdateDTO } from './dto/accessory.update.dto';
import { AccessoryService } from './accessory.service';

@ApiTags('Accessory')
@Controller('api/products/accessory')
@UseGuards(AuthGuard, RoleGuard)
@UseRole(Role.MODERATOR)
export class AccessoryController {
  constructor(private readonly accessoryService: AccessoryService) {}

  @ApiOperation({ summary: 'Create new clothing' })
  @ApiBody({
    type: AccessoryCreateDTO,
    examples: {
      'Moderator - Product - Accessory': {
        value: {
          stockQuantity: 100,
          productId: '2882d168-7f50-4a4f-8faa-a7074b407bb0',
        },
      },
    },
  })
  @ApiResponse({ status: 200, description: 'Accessory Successfully Created' })
  @ApiResponse({ status: 400, description: 'Bad Request' })
  @ApiResponse({ status: 401, description: 'Not Authorized' })
  @ApiResponse({ status: 403, description: 'Not Authorized as Moderator' })
  @ApiResponse({ status: 409, description: 'Accessory Conflict' })
  @ApiResponse({ status: 500, description: 'Internal Server Error' })
  @Post()
  public async create(@Body() accessoryCreateData: AccessoryCreateDTO, @Res() res: Response): Promise<Response | void> {
    try {
      const accessory = await this.accessoryService.create(accessoryCreateData);
      res.status(200).json(accessory);
    } catch (err) {
      if (err instanceof PrismaClientKnownRequestError && err.code === 'P2002') {
        return res.status(409).send('An accessory with this product id already exists');
      }

      throw err;
    }
  }

  @ApiOperation({ summary: 'Update accessory' })
  @ApiBody({
    type: AccessoryUpdateDTO,
    examples: {
      'Moderator - Product - Accessory': {
        value: {
          stockQuantity: 100,
        },
      },
    },
  })
  @ApiResponse({ status: 200, description: 'Accessory Successfully Updated' })
  @ApiResponse({ status: 400, description: 'Bad Request' })
  @ApiResponse({ status: 401, description: 'Not Authorized' })
  @ApiResponse({ status: 403, description: 'Not Authorized as Moderator' })
  @ApiResponse({ status: 404, description: 'Accessory Not Found' })
  @ApiResponse({ status: 500, description: 'Internal Server Error' })
  @Patch(':accessoryId')
  public async updateById(
    @Param('accessoryId') accessoryId: string,
    @Body() accessoryUpdateData: AccessoryUpdateDTO,
    @Res() res: Response,
  ): Promise<Response | void> {
    const accessory = await this.accessoryService.update({
      where: {
        id: accessoryId,
      },
      data: accessoryUpdateData,
    });

    res.status(200).json(accessory);
  }
}
