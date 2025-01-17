import { IsNotEmpty, IsString, IsEmail } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class UserSignInDTO {
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
}
