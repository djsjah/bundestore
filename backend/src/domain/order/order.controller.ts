import { Controller, Get, Post, Res, Req, UseGuards } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Request, Response } from 'express';
import { ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { Role } from '@prisma/client';

import { UseRole, MailerProvider } from '@/utils';

import { AuthGuard } from '../auth/guards/auth.guard';
import { RoleGuard } from '../auth/guards/role.guard';
import { IUserPayload } from '../user';
import { CustomerService } from '../user/entity/customer/customer.service';
import { CartRelations } from '../cart/types';
import { CartService } from '../cart';

import { OrderEmailSubject } from './types/order.email.subject.enum';
import { OrderFilter } from './service/order.filter';
import { OrderAggregate } from './service/order.aggregate';
import { OrderEmailTemplate } from './service/order.email.template';

@ApiTags('Orders')
@Controller('api/orders')
@UseGuards(AuthGuard, RoleGuard)
@UseRole(Role.CUSTOMER)
export class OrderController {
  constructor(
    private readonly configService: ConfigService,
    private readonly orderFilter: OrderFilter,
    private readonly orderAggregate: OrderAggregate,
    private readonly orderEmailTemplate: OrderEmailTemplate,
    private readonly customerService: CustomerService,
    private readonly cartService: CartService,
    private readonly mailer: MailerProvider,
  ) {}

  @ApiOperation({ summary: 'Get user orders' })
  @ApiResponse({ status: 200, description: 'User orders' })
  @ApiResponse({ status: 401, description: 'Not Authorized' })
  @ApiResponse({ status: 403, description: 'Not Authorized as Customer' })
  @ApiResponse({ status: 404, description: 'Orders Not Found' })
  @ApiResponse({ status: 500, description: 'Internal Server Error' })
  @Get('me')
  public async getAll(@Req() req: Request, @Res() res: Response): Promise<Response | void> {
    const user = req.user as IUserPayload;
    const customer = await this.customerService.getByUniqueParams({
      where: {
        userId: user.id,
      },
    });

    const orders = await this.orderFilter.querySQLFilter(customer.id);

    if (orders.length === 0) {
      return res.status(404).send('Orders were not found');
    }

    res.status(200).json(orders);
  }

  @ApiOperation({ summary: 'Create new user order' })
  @ApiResponse({ status: 200, description: 'Order Successfully Created' })
  @ApiResponse({ status: 401, description: 'Not Authorized' })
  @ApiResponse({ status: 403, description: 'Not Authorized as Customer' })
  @ApiResponse({ status: 404, description: 'Cart Items Not Found' })
  @ApiResponse({ status: 500, description: 'Internal Server Error' })
  @Post('me')
  public async create(@Req() req: Request, @Res() res: Response): Promise<Response | void> {
    const user = req.user as IUserPayload;
    const customer = await this.customerService.getByUniqueParams({
      where: {
        userId: user.id,
      },
    });

    const cart = (await this.cartService.getByUniqueParams({
      where: {
        customerId: customer.id,
      },
      include: {
        orderItems: {
          select: {
            id: true,
            total: true,
            quantity: true,
            size: true,
            productId: true,
          },
        },
      },
    })) as CartRelations;

    if (!cart.orderItems || (cart.orderItems && cart.orderItems.length === 0)) {
      return res.status(404).send('Cart is empty');
    }

    const order = await this.orderAggregate.applyCreateOrderTransaction(cart, {
      total: Number(cart.total),
      quantity: cart.quantity,
      customerId: customer.id,
    });

    await this.mailer.getTransporter().sendMail({
      to: this.configService.get('MANAGER_EMAIL'),
      subject: this.orderEmailTemplate.getEmailSubject(OrderEmailSubject.purchase),
      html: this.orderEmailTemplate.createPurchaseEmail({
        orderId: order.id,
        total: order.total,
        quantity: order.quantity,
        status: order.status,
        createdAt: order.createdAt,
        userId: user.id,
        customerId: customer.id,
        customerFullName: `${customer.firstName} ${customer.lastName}`,
        customerEmail: user.email,
        customerPhoneNumber: customer.phoneNumber,
        customerBirthDate: customer.birthDate,
        orderItems: cart.orderItems,
      }),
    });

    res.status(200).send('New order successfully created');
  }
}
