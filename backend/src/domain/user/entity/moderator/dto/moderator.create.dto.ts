import { IsNotEmpty, IsUUID, IsString } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class ModeratorCreateDTO {
  @ApiProperty({
    type: 'string',
    description: 'User id',
  })
  @IsNotEmpty()
  @IsString()
  @IsUUID()
  public userId: string;

  @ApiProperty({
    type: 'string',
    description: 'Administrator id',
  })
  @IsNotEmpty()
  @IsString()
  @IsUUID()
  public administratorId: string;
}
