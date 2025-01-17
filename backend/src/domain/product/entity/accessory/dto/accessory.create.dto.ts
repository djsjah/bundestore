import { IsNotEmpty, IsString, IsUUID, IsInt, Min } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class AccessoryCreateDTO {
  @ApiProperty({
    type: 'number',
    format: 'byte',
    description: 'Stock quantity',
    required: true,
  })
  @IsNotEmpty()
  @IsInt()
  @Min(1)
  public stockQuantity: number;

  @ApiProperty({
    type: 'string',
    format: 'uuid',
    description: 'Product id',
    required: true,
  })
  @IsNotEmpty()
  @IsString()
  @IsUUID()
  public productId: string;
}
