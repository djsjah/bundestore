import { IsNotEmpty, IsString, IsUUID, IsInt, IsEnum, Min } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { ClothingSize } from '@prisma/client';

export class ClothingCreateDTO {
  @ApiProperty({
    type: 'enum',
    enum: ClothingSize,
    description: 'Clothing size',
    required: true,
  })
  @IsNotEmpty()
  @IsEnum(ClothingSize)
  public size: ClothingSize;

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
