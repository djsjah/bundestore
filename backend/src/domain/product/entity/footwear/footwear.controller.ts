import { Controller, Post, Patch, Res, Param, Body, UseGuards } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiBody, ApiResponse } from '@nestjs/swagger';
import { Response } from 'express';
import { Role } from '@prisma/client';

import { AuthGuard, RoleGuard } from '@/domain/auth';
import { UseRole } from '@/utils';

import { FootwearCreateDTO } from './dto/footwear.create.dto';
import { FootwearUpdateDTO } from './dto/footwear.update.dto';
import { FootwearService } from './footwear.service';

@ApiTags('Footwear')
@Controller('api/products/footwear')
@UseGuards(AuthGuard, RoleGuard)
@UseRole(Role.MODERATOR)
export class FootwearController {
  constructor(private readonly footwearService: FootwearService) {}

  @ApiOperation({ summary: 'Create new footwear' })
  @ApiBody({
    type: FootwearCreateDTO,
    examples: {
      'Moderator - Product - Footwear': {
        value: {
          size: 'SIZE_33',
          stockQuantity: 100,
          productId: '2882d168-7f50-4a4f-8faa-a7074b407bb0',
        },
      },
    },
  })
  @ApiResponse({ status: 200, description: 'Footwear Successfully Created' })
  @ApiResponse({ status: 400, description: 'Bad Request' })
  @ApiResponse({ status: 401, description: 'Not Authorized' })
  @ApiResponse({ status: 403, description: 'Not Authorized as Moderator' })
  @ApiResponse({ status: 500, description: 'Internal Server Error' })
  @Post()
  public async create(@Body() footwearCreateData: FootwearCreateDTO, @Res() res: Response): Promise<Response | void> {
    const footwear = await this.footwearService.create(footwearCreateData);
    res.status(200).json(footwear);
  }

  @ApiOperation({ summary: 'Update footwear' })
  @ApiBody({
    type: FootwearUpdateDTO,
    examples: {
      'Moderator - Product - Footwear': {
        value: {
          stockQuantity: 100,
        },
      },
    },
  })
  @ApiResponse({ status: 200, description: 'Footwear Successfully Updated' })
  @ApiResponse({ status: 400, description: 'Bad Request' })
  @ApiResponse({ status: 401, description: 'Not Authorized' })
  @ApiResponse({ status: 403, description: 'Not Authorized as Moderator' })
  @ApiResponse({ status: 404, description: 'Footwear Not Found' })
  @ApiResponse({ status: 500, description: 'Internal Server Error' })
  @Patch(':footwearId')
  public async updateById(
    @Param('footwearId') footwearId: string,
    @Body() footwearUpdateData: FootwearUpdateDTO,
    @Res() res: Response,
  ): Promise<Response | void> {
    const footwear = await this.footwearService.update({
      where: {
        id: footwearId,
      },
      data: footwearUpdateData,
    });

    res.status(200).json(footwear);
  }
}
