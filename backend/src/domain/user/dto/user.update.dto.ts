import { IsOptional, IsString, IsEmail } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class UserUpdateDTO {
  @ApiProperty({
    type: 'string',
    description: 'User email',
  })
  @IsOptional()
  @IsEmail()
  public email: string;

  @ApiProperty({
    type: 'string',
    description: 'User email',
  })
  @IsOptional()
  @IsString()
  public password: string;
}
