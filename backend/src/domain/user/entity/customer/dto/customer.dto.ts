import { IsNotEmpty, IsOptional, IsUUID, IsDate, IsString, IsPhoneNumber } from 'class-validator';
import { Type } from 'class-transformer';
import { ApiProperty } from '@nestjs/swagger';

export class CustomerDTO {
  @ApiProperty({
    type: 'string',
    format: 'uuid',
    description: 'Customer id',
    required: true,
  })
  @IsNotEmpty()
  @IsUUID()
  public id: string;

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
  @Type(() => Date)
  @IsDate()
  public birthDate?: Date | null;

  @ApiProperty({
    type: 'string',
    description: 'User phone number',
    required: false,
  })
  @IsOptional()
  @IsPhoneNumber()
  public phoneNumber?: string | null;

  @ApiProperty({
    type: 'string',
    format: 'uuid',
    description: 'User id',
    required: true,
  })
  @IsNotEmpty()
  @IsUUID()
  public userId: string;
}
