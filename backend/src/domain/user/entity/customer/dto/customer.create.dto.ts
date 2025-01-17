import { IsNotEmpty, IsOptional, IsUUID, IsDate, IsString } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class CustomerCreateDTO {
  @ApiProperty({
    type: 'string',
    description: 'User first name',
    required: true,
  })
  @IsNotEmpty()
  @IsString()
  public firstName: string;

  @ApiProperty({
    type: 'string',
    description: 'User last name',
    required: true,
  })
  @IsNotEmpty()
  @IsString()
  public lastName: string;

  @ApiProperty({
    type: 'string',
    format: 'date',
    description: 'User birth date',
    required: false,
  })
  @IsOptional()
  @IsDate()
  public birthDate?: string;

  @ApiProperty({
    type: 'string',
    description: 'User phone number',
    required: false,
  })
  @IsOptional()
  public phoneNumber?: string;

  @ApiProperty({
    type: 'string',
    description: 'User id',
    required: true,
  })
  @IsNotEmpty()
  @IsString()
  @IsUUID()
  public userId: string;
}
