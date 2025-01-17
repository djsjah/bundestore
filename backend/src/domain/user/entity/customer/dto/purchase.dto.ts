import { IsNotEmpty, IsArray, ArrayNotEmpty, ValidateNested } from 'class-validator';
import { Type } from 'class-transformer';
import { ApiProperty } from '@nestjs/swagger';

import { OrderCreateDTO } from '@/domain/order';
import { OrderItemCreateDTO } from '@/domain/order-item';

export class PurchaseDTO {
  @ApiProperty({
    type: OrderCreateDTO,
    description: 'Order params',
    required: true,
  })
  @IsNotEmpty()
  @ValidateNested()
  @Type(() => OrderCreateDTO)
  public order: OrderCreateDTO;

  @ApiProperty({
    type: [OrderItemCreateDTO],
    description: 'Products',
    isArray: true,
    required: false,
  })
  @IsArray()
  @ArrayNotEmpty()
  @ValidateNested({ each: true })
  @Type(() => OrderItemCreateDTO)
  public orderItems: OrderItemCreateDTO[];
}
