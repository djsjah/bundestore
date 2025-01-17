import { IsOptional, IsBoolean, IsString } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class UserSystemUpdateDTO {
  @ApiProperty({
    type: 'string',
    description: 'User refresh token',
    required: false,
  })
  @IsOptional()
  @IsString()
  public refreshToken?: string | null;

  @ApiProperty({
    type: Date,
    description: 'User verification status',
    required: false,
  })
  @IsOptional()
  @IsBoolean()
  public isVerified?: boolean;
}
