import { IsNotEmpty, IsUUID, IsString } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class EmailVerifCreateDTO {
  @ApiProperty({
    type: 'string',
    description: 'Verification token',
    required: true,
  })
  @IsNotEmpty()
  @IsString()
  public verifToken: string;

  @ApiProperty({
    type: 'string',
    format: 'uuid',
    description: 'User id',
    required: true,
  })
  @IsNotEmpty()
  @IsString()
  @IsUUID()
  public userId: string;
}
