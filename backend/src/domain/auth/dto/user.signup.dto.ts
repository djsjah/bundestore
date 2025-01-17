import { IsNotEmpty, IsDate, IsString, IsEmail, Matches } from 'class-validator';
import { Type } from 'class-transformer';
import { ApiProperty } from '@nestjs/swagger';

import { userCreateConfig } from '@/domain/user';

export class UserSignUpDTO {
  @ApiProperty({
    type: 'string',
    description: 'User email',
    required: true,
  })
  @IsNotEmpty()
  @IsString()
  @IsEmail()
  public email: string;

  @ApiProperty({
    type: 'string',
    description: 'User password',
    required: true,
  })
  @IsNotEmpty()
  @IsString()
  public password: string;

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
  @IsNotEmpty()
  @Type(() => Date)
  @IsDate()
  public birthDate: Date;

  @ApiProperty({
    type: 'string',
    description: 'User phone number',
    required: false,
  })
  @IsNotEmpty()
  @Matches(userCreateConfig.phoneNummber.rule, {
    message: userCreateConfig.phoneNummber.message,
  })
  public phoneNumber: string;
}
