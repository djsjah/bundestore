import { IsNotEmpty, IsOptional, IsString, IsUUID, IsEnum } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { ClothingSize, FootwearSize } from '@prisma/client';

export class OrderItemCreateDTO {
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

  @ApiProperty({
    enum: [ClothingSize, FootwearSize],
    description: 'Product size',
    required: false,
  })
  @IsOptional()
  @IsEnum({
    ...ClothingSize,
    ...FootwearSize,
  })
  public size?: ClothingSize | FootwearSize;
}
