import { IsOptional, IsString } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class CustomerUpdateDTO {
  @ApiProperty({
    type: 'string',
    description: 'User first name',
    required: false,
  })
  @IsOptional()
  @IsString()
  public firstName?: string;

  @ApiProperty({
    type: 'string',
    description: 'User last name',
    required: false,
  })
  @IsOptional()
  @IsString()
  public lastName?: string;

  @ApiProperty({
    type: 'string',
    description: 'User phone number',
    required: false,
  })
  @IsOptional()
  public phoneNumber?: string;
}
