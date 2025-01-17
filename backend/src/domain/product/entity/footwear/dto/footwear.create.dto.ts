import { IsNotEmpty, IsString, IsUUID, IsInt, IsEnum, Min } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { FootwearSize } from '@prisma/client';

export class FootwearCreateDTO {
  @ApiProperty({
    type: 'enum',
    enum: FootwearSize,
    description: 'Footwear size',
    required: true,
  })
  @IsNotEmpty()
  @IsEnum(FootwearSize)
  public size: FootwearSize;

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
