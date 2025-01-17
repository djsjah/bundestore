import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

import { NodeENV } from './types';

@Injectable()
export class NodeConfig {
  private readonly nodeENV: NodeENV;

  constructor(private readonly configService: ConfigService) {
    this.nodeENV = this.configService.get('nodeENV') as NodeENV;
  }

  public getNodeENV(): NodeENV {
    return this.nodeENV;
  }
}
