import { Controller, Req, Res, Get, Post, Patch, Query, Param, Body, UseGuards } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiBody, ApiResponse } from '@nestjs/swagger';
import { Request, Response } from 'express';
import { Role, ProductCategory, Club, AgeCategory, Gender } from '@prisma/client';

import { UseRole } from '@/utils';

import { AuthGuard, RoleGuard } from '../auth';
import { IUserPayload, ModeratorService } from '../user';

import { ProductCreateDTO, ProductUpdateDTO, ProductFilterDTO } from './dto';
import { ProductService } from './service/product.service';
import { ProductFilter } from './service/product.filter';

@ApiTags('Products')
@Controller('api/products')
export class ProductController {
  constructor(
    private readonly productService: ProductService,
    private readonly productFilter: ProductFilter,
    private readonly moderatorService: ModeratorService,
  ) {}

  @ApiOperation({ summary: 'Find All Products by Filter' })
  @ApiResponse({ status: 200, description: 'Products List' })
  @ApiResponse({ status: 400, description: 'Bad Request' })
  @ApiResponse({ status: 404, description: 'Products Not Found' })
  @ApiResponse({ status: 500, description: 'Internal Server Error' })
  @Get()
  public async getAll(@Query() queryParams: ProductFilterDTO, @Res() res: Response): Promise<Response | void> {
    const products = await this.productFilter.querySQLFilter(queryParams);
    if (products.length === 0) {
      return res.status(404).send('Products were not found');
    }

    res.status(200).json(products);
  }

  @ApiOperation({ summary: 'Get Product by Id' })
  @ApiResponse({ status: 200, description: 'Product Details' })
  @ApiResponse({ status: 404, description: 'Product Not Found' })
  @ApiResponse({ status: 500, description: 'Internal Server Error' })
  @Get(':id')
  public async getById(@Param('id') productId: string, @Res() res: Response): Promise<Response | void> {
    const product = await this.productFilter.querySQLFilter({
      id: productId,
    });

    if (!product[0]) {
      return res.status(404).send('Product were not found');
    }

    res.status(200).json(product[0]);
  }

  @ApiOperation({ summary: 'Create new clothing' })
  @ApiBody({
    type: ProductCreateDTO,
    examples: {
      'Moderator - Product': {
        value: {
          name: 'FC Bayern Main T-shirt',
          description: 'T-shirt for adults (women)',
          price: 3200,
          imageUrl: './src/public/img/bayern/clothing/upper',
          category: ProductCategory.LOWER_CLOTHING,
          club: Club.BAYERN_MUNICH,
          age: AgeCategory.ADULT,
          gender: Gender.WOMEN,
        },
      },
    },
  })
  @ApiResponse({ status: 200, description: 'Product Successfully Created' })
  @ApiResponse({ status: 400, description: 'Bad Request' })
  @ApiResponse({ status: 401, description: 'Not Authorized' })
  @ApiResponse({ status: 403, description: 'Not Authorized as Moderator' })
  @ApiResponse({ status: 500, description: 'Internal Server Error' })
  @UseGuards(AuthGuard, RoleGuard)
  @UseRole(Role.MODERATOR)
  @Post()
  public async create(@Req() req: Request, @Body() productCreateData: ProductCreateDTO, @Res() res: Response) {
    const userPayload = req.user as IUserPayload;
    const moderator = await this.moderatorService.getByUniqueParams({
      where: {
        userId: userPayload.id,
      },
    });

    const product = await this.productService.create({
      data: {
        ...productCreateData,
        moderatorId: moderator.id,
      },
    });

    res.status(200).json(product);
  }

  @ApiOperation({ summary: 'Update Existing Product by Id' })
  @ApiBody({
    type: ProductUpdateDTO,
    examples: {
      'Moderator - Product': {
        value: {
          name: 'FC Bayern Main T-shirt',
          description: 'T-shirt for adults (women)',
          price: 3200,
          imageUrl: '',
          club: Club.BAYERN_MUNICH,
          age: AgeCategory.ADULT,
          gender: Gender.WOMEN,
        },
      },
    },
  })
  @ApiResponse({ status: 200, description: 'Product Successfully Updated' })
  @ApiResponse({ status: 400, description: 'Bad Request' })
  @ApiResponse({ status: 401, description: 'Not Authorized' })
  @ApiResponse({ status: 403, description: 'Not Authorized as Moderator' })
  @ApiResponse({ status: 404, description: 'Product Not Found' })
  @ApiResponse({ status: 500, description: 'Internal Server Error' })
  @UseGuards(AuthGuard, RoleGuard)
  @UseRole(Role.MODERATOR)
  @Patch(':productId')
  public async update(
    @Param('productId') productId: string,
    @Body() productUpdateData: ProductUpdateDTO,
    @Res() res: Response,
  ): Promise<Response | void> {
    const product = await this.productService.update({
      where: {
        id: productId,
      },
      data: productUpdateData,
    });

    res.status(200).json(product);
  }
}
