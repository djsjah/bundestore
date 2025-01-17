import { IsNotEmpty, IsInt, Min } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class OrderItemUpdateDTO {
  @ApiProperty({
    type: 'number',
    format: 'byte',
    description: 'Product quantity',
    required: true,
  })
  @IsNotEmpty()
  @IsInt()
  @Min(1)
  public quantity: number;
}
