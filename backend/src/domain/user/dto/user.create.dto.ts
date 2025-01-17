import { IsNotEmpty, IsOptional, IsEnum, IsString, IsEmail, IsBoolean } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { Role } from '@prisma/client';

export class UserCreateDTO {
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
    type: 'enum',
    description: 'User role',
    enum: Role,
    required: true,
  })
  @IsNotEmpty()
  @IsEnum(Role)
  public role: Role;

  @ApiProperty({
    type: 'boolean',
    description: 'User verification status',
  })
  @IsOptional()
  @IsBoolean()
  public isVerified?: boolean;
}
