import { ApiProperty } from '@nestjs/swagger';

export class ModeratorGetDTO {
  @ApiProperty({
    type: 'string',
    description: 'Administrator id',
  })
  public id: string;

  @ApiProperty({
    type: 'string',
    description: 'User id',
  })
  public userId: string;

  @ApiProperty({
    type: 'string',
    description: 'Administrator id',
  })
  public administratorId: string;
}
