import { Controller, Param, Body, Req, Res, Get, Patch, UseGuards } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiParam, ApiBody, ApiResponse } from '@nestjs/swagger';
import { Role } from '@prisma/client';
import { Request, Response } from 'express';

import { AuthGuard, RoleGuard } from '@/domain/auth/guards';
import { AuthService } from '@/domain/auth/service/auth.service';
import { UseRole } from '@/utils';

import { IUserPayload } from '../../types';
import { UserService } from '../../service/user.service';

import { CustomerService } from './customer.service';
import { CustomerDTO, CustomerUpdateDTO } from './dto';

@ApiTags('Customers')
@Controller('api/customers')
@UseGuards(AuthGuard)
export class CustomerController {
  constructor(
    private readonly authService: AuthService,
    private readonly userService: UserService,
    private readonly customerService: CustomerService,
  ) {}

  @ApiOperation({ summary: 'Get all Customers' })
  @ApiResponse({ status: 200, description: 'Successful Response', type: [CustomerDTO] })
  @ApiResponse({ status: 401, description: 'Not Authorized' })
  @ApiResponse({ status: 403, description: 'Not Authorized as Administrator' })
  @ApiResponse({ status: 500, description: 'Internal Server Error' })
  @UseGuards(RoleGuard)
  @UseRole(Role.ADMINISTRATOR)
  @Get()
  public async getAll(): Promise<CustomerDTO[]> {
    const customers = await this.customerService.getMany({});
    return customers;
  }

  @ApiOperation({ summary: 'Get Customer by Id' })
  @ApiResponse({ status: 200, description: 'Successful Response', type: CustomerDTO })
  @ApiResponse({ status: 401, description: 'Not Authorized' })
  @ApiResponse({ status: 403, description: 'Not Authorized as Administrator' })
  @ApiResponse({ status: 404, description: 'Not Found' })
  @ApiResponse({ status: 500, description: 'Internal Server Error' })
  @ApiParam({
    name: 'customerId',
    type: 'string',
    format: 'uuid',
    required: true,
    description: 'User id',
  })
  @UseGuards(RoleGuard)
  @UseRole(Role.ADMINISTRATOR)
  @Get(':customerId')
  public async getUniqueById(@Param('customerId') customerId: string): Promise<CustomerDTO> {
    const customer = await this.customerService.getByUniqueParams({
      where: {
        id: customerId,
      },
    });

    return customer;
  }

  @ApiOperation({ summary: 'Update Customer Data' })
  @ApiResponse({ status: 200, description: 'Successful Update' })
  @ApiResponse({ status: 400, description: 'Bad Request' })
  @ApiResponse({ status: 401, description: 'Not Authorized' })
  @ApiResponse({ status: 403, description: 'Not Authorized as Customer' })
  @ApiResponse({ status: 404, description: 'Customer Not Found' })
  @ApiResponse({ status: 500, description: 'Internal Server Error' })
  @ApiBody({
    type: CustomerUpdateDTO,
    examples: {
      'User - Customer Patch Update': {
        value: {
          firstName: 'Богдан',
          lastName: 'Егоров',
          phoneNumber: '+ 7(982) 408 31-75',
        },
      },
    },
  })
  @UseGuards(RoleGuard)
  @UseRole(Role.CUSTOMER)
  @Patch('me')
  public async update(
    @Req() req: Request,
    @Body() customerUpdateData: CustomerUpdateDTO,
    @Res() res: Response,
  ): Promise<Response | void> {
    const userPayload = req.user as IUserPayload;
    await this.customerService.update(
      {
        userId: userPayload.id,
      },
      customerUpdateData,
    );

    const user = await this.userService.getByUniqueParams({
      where: {
        id: userPayload.id,
      },
    });

    const { refresh } = await this.authService.setJWTCookie(user, res);
    await this.userService.update(user.id, {
      refreshToken: refresh,
    });

    res.status(200).send('Customer updated successfully');
  }
}
