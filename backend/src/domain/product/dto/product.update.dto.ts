import { IsOptional, IsString, IsDecimal, IsEnum } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { Club, AgeCategory, Gender } from '@prisma/client';

export class ProductUpdateDTO {
  @ApiProperty({
    type: 'string',
    description: 'Product name',
    required: false,
  })
  @IsOptional()
  @IsString()
  public name?: string;

  @ApiProperty({
    type: 'string',
    description: 'Product description',
    required: false,
  })
  @IsOptional()
  @IsString()
  public description?: string;

  @ApiProperty({
    type: 'number',
    description: 'Product price',
    required: false,
  })
  @IsOptional()
  @IsDecimal()
  public price?: number;

  @ApiProperty({
    type: 'string',
    description: 'Product image url',
    required: false,
  })
  @IsOptional()
  @IsString()
  public imageUrl?: string;

  @ApiProperty({
    type: 'enum',
    enum: Club,
    description: 'The Football Club associated with the product',
    required: false,
  })
  @IsOptional()
  @IsEnum(Club)
  public club?: Club;

  @ApiProperty({
    type: 'enum',
    enum: AgeCategory,
    description: 'The target age group for the product',
    required: false,
  })
  @IsOptional()
  @IsEnum(AgeCategory)
  public age?: AgeCategory;

  @ApiProperty({
    type: 'enum',
    enum: Gender,
    description: 'The gender category for which the product is designed',
    required: false,
  })
  @IsOptional()
  @IsEnum(Gender)
  public gender?: Gender;
}
