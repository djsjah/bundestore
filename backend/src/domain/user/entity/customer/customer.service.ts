import { Injectable, NotFoundException } from '@nestjs/common';
import { Prisma, Customer } from '@prisma/client';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';

import { PrismaService } from '@/database/prisma';

@Injectable()
export class CustomerService {
  constructor(private readonly prismaService: PrismaService) { }

  public async getMany(params: Prisma.CustomerFindManyArgs): Promise<Customer[]> {
    const customers = await this.prismaService.customer.findMany(params);
    return customers;
  }

  public async getByUniqueParams(uniqueParams: Prisma.CustomerFindUniqueArgs): Promise<Customer> {
    const customer = await this.prismaService.customer.findUnique(uniqueParams);

    if (!customer) {
      throw new NotFoundException('Customer Not Found');
    }

    return customer;
  }

  public async update(
    customer: Prisma.CustomerWhereUniqueInput,
    customerUpdateData: Prisma.CustomerUpdateInput,
  ): Promise<Customer> {
    try {
      const updatedCustomer = await this.prismaService.customer.update({
        where: customer,
        data: customerUpdateData,
      });

      return updatedCustomer;
    }
    catch (err) {
      if (err instanceof PrismaClientKnownRequestError && err.code === 'P2025') {
        throw new NotFoundException("Customer to update not found");
      }

      throw err;
    }
  }
}
