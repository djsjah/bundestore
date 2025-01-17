import { IsNotEmpty, IsDecimal, IsInt, IsUUID } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class CartCreateDTO {
  @ApiProperty({
    type: 'decimal',
    description: 'Total amount',
    required: true,
  })
  @IsNotEmpty()
  @IsDecimal()
  public total: number;

  @ApiProperty({
    type: 'int',
    description: 'Quantity of products',
    required: true,
  })
  @IsNotEmpty()
  @IsInt()
  public quantity: number;

  @ApiProperty({
    type: 'string',
    format: 'uuid',
    description: 'Customer id',
    required: true,
  })
  @IsNotEmpty()
  @IsUUID()
  public customerId: string;
}
