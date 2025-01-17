import { IsNotEmpty, IsInt, Min } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class FootwearUpdateDTO {
  @ApiProperty({
    type: 'number',
    format: 'byte',
    description: 'Stock quantity',
    required: true,
  })
  @IsNotEmpty()
  @IsInt()
  @Min(0)
  public stockQuantity: number;
}
