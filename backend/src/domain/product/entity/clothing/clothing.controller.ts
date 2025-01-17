import { Controller, Post, Patch, Res, Param, Body, UseGuards } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiBody, ApiResponse } from '@nestjs/swagger';
import { Response } from 'express';
import { Role } from '@prisma/client';

import { AuthGuard, RoleGuard } from '@/domain/auth';
import { UseRole } from '@/utils';

import { ClothingCreateDTO } from './dto/clothing.create.dto';
import { ClothingUpdateDTO } from './dto/clothing.update.dto';
import { ClothingService } from './clothing.service';

@ApiTags('Clothing')
@Controller('api/products/clothing')
@UseGuards(AuthGuard, RoleGuard)
@UseRole(Role.MODERATOR)
export class ClothingController {
  constructor(private readonly clothingService: ClothingService) {}

  @ApiOperation({ summary: 'Create new clothing' })
  @ApiBody({
    type: ClothingCreateDTO,
    examples: {
      'Moderator - Product - Clothing': {
        value: {
          size: 'SIZE_S',
          stockQuantity: 100,
          productId: '2882d168-7f50-4a4f-8faa-a7074b407bb0',
        },
      },
    },
  })
  @ApiResponse({ status: 200, description: 'Clothing Successfully Created' })
  @ApiResponse({ status: 400, description: 'Bad Request' })
  @ApiResponse({ status: 401, description: 'Not Authorized' })
  @ApiResponse({ status: 403, description: 'Not Authorized as Moderator' })
  @ApiResponse({ status: 500, description: 'Internal Server Error' })
  @Post()
  public async create(@Body() clothingCreateData: ClothingCreateDTO, @Res() res: Response): Promise<Response | void> {
    const clothing = await this.clothingService.create(clothingCreateData);
    res.status(200).json(clothing);
  }

  @ApiOperation({ summary: 'Update clothing' })
  @ApiBody({
    type: ClothingUpdateDTO,
    examples: {
      'Moderator - Product - Clothing': {
        value: {
          stockQuantity: 100,
        },
      },
    },
  })
  @ApiResponse({ status: 200, description: 'Clothing Successfully Updated' })
  @ApiResponse({ status: 400, description: 'Bad Request' })
  @ApiResponse({ status: 401, description: 'Not Authorized' })
  @ApiResponse({ status: 403, description: 'Not Authorized as Moderator' })
  @ApiResponse({ status: 404, description: 'Clothing Not Found' })
  @ApiResponse({ status: 500, description: 'Internal Server Error' })
  @Patch(':clothingId')
  public async updateById(
    @Param('clothingId') clothingId: string,
    @Body() clothingUpdateData: ClothingUpdateDTO,
    @Res() res: Response,
  ): Promise<Response | void> {
    const clothing = await this.clothingService.update({
      where: {
        id: clothingId,
      },
      data: clothingUpdateData,
    });

    res.status(200).json(clothing);
  }
}
