import { IsNotEmpty, IsUUID, IsString, IsInt, IsDecimal, Min } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class OrderCreateDTO {
  @ApiProperty({
    type: 'decimal',
    description: 'Total order amount',
    required: true,
  })
  @IsNotEmpty()
  @IsDecimal()
  public total: number;

  @ApiProperty({
    type: 'int',
    description: 'Product quantity',
    required: true,
  })
  @IsNotEmpty()
  @IsInt()
  @Min(1)
  public quantity: number;

  @ApiProperty({
    type: 'string',
    format: 'uuid',
    description: 'Customer id',
    required: true,
  })
  @IsNotEmpty()
  @IsString()
  @IsUUID()
  public customerId: string;
}
