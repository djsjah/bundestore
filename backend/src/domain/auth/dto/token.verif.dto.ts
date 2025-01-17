import { IsNotEmpty, IsString, MinLength } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class TokenVerifDTO {
  @ApiProperty({
    type: 'string',
    description: 'Verification token',
    required: true,
  })
  @IsNotEmpty()
  @IsString()
  @MinLength(6)
  public token: string;
}
