import { IsOptional, IsString, IsDate } from 'class-validator';
import { Type } from 'class-transformer';
import { ApiProperty } from '@nestjs/swagger';

export class EmailVerifUpdateDTO {
  @ApiProperty({
    type: 'string',
    description: 'Verification token',
    required: false,
  })
  @IsOptional()
  @IsString()
  public verifToken?: string;

  @ApiProperty({
    type: 'string',
    format: 'date-time',
    description: 'Verification token expiration time',
    required: false,
  })
  @IsOptional()
  @Type(() => Date)
  @IsDate()
  public expiresAt?: Date;
}
