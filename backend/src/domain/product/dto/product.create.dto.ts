import { IsNotEmpty, IsString, IsNumber, IsEnum } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { ProductCategory, AgeCategory, Gender, Club } from '@prisma/client';

export class ProductCreateDTO {
  @ApiProperty({
    type: 'string',
    description: 'Product name',
    required: true,
  })
  @IsNotEmpty()
  @IsString()
  name: string;

  @ApiProperty({
    type: 'string',
    description: 'Product description',
    required: true,
  })
  @IsNotEmpty()
  @IsString()
  description: string;

  @ApiProperty({
    type: 'number',
    description: 'Product price',
    required: true,
  })
  @IsNotEmpty()
  @IsNumber()
  price: number;

  @ApiProperty({
    type: 'string',
    description: 'Product image url',
    required: true,
  })
  @IsNotEmpty()
  @IsString()
  public imageUrl: string;

  @ApiProperty({
    type: 'enum',
    description: 'Product category',
    enum: ProductCategory,
    example: ProductCategory.UPPER_CLOTHING,
    required: true,
  })
  @IsNotEmpty()
  @IsEnum(ProductCategory)
  category: ProductCategory;

  @ApiProperty({
    type: 'enum',
    description: 'The Football Club associated with the product',
    enum: Club,
    example: Club.BAYERN_MUNICH,
    required: true,
  })
  @IsNotEmpty()
  @IsEnum(Club)
  club: Club;

  @ApiProperty({
    type: 'enum',
    description: 'The target age group for the product',
    enum: AgeCategory,
    example: AgeCategory.ADULT,
    required: true,
  })
  @IsNotEmpty()
  @IsEnum(AgeCategory)
  age: AgeCategory;

  @ApiProperty({
    type: 'enum',
    description: 'The gender category for which the product is designed',
    enum: Gender,
    example: Gender.UNISEX,
    required: true,
  })
  @IsNotEmpty()
  @IsEnum(Gender)
  gender: Gender;
}
