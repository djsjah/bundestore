import { IsNotEmpty, IsOptional, IsEnum, IsString, IsEmail, IsUUID, IsBoolean, IsDate } from 'class-validator';
import { Type } from 'class-transformer';
import { ApiProperty } from '@nestjs/swagger';
import { Role } from '@prisma/client';

export class UserDTO {
  @ApiProperty({
    type: 'string',
    format: 'uuid',
    description: 'User id',
    required: true,
  })
  @IsNotEmpty()
  @IsString()
  @IsUUID()
  public id: string;

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
    enum: Role,
    description: 'User role',
    required: true,
  })
  @IsNotEmpty()
  @IsEnum(Role)
  public role: Role;

  @ApiProperty({
    type: 'boolean',
    description: 'User verification status',
    required: false,
  })
  @IsOptional()
  @IsBoolean()
  public isVerified?: boolean;

  @ApiProperty({
    type: Date,
    description: 'User created at date',
    required: false,
  })
  @IsOptional()
  @Type(() => Date)
  @IsDate()
  public createdAt?: Date;

  @ApiProperty({
    type: Date,
    description: 'User updated at date',
    required: false,
  })
  @IsOptional()
  @Type(() => Date)
  @IsDate()
  public updatedAt?: Date;
}
