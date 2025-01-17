import { IsNotEmpty, IsUUID, IsString } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class AdminCreateDTO {
  @ApiProperty({
    type: 'string',
    description: 'User id',
  })
  @IsNotEmpty()
  @IsString()
  @IsUUID()
  public userId: string;
}
