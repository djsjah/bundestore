import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';

import { NodeConfig } from './node.config';

@Module({
  imports: [ConfigModule],
  providers: [NodeConfig],
  exports: [NodeConfig],
})
export class NodeModule {}
