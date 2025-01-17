import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';

import { NodeModule } from '@/utils/node/node.module';

import { MailerConfig } from './mailer.config';
import { MailerProvider } from './mailer.provider';
import { TransporterSettings } from './transporter.settings';

@Module({
  imports: [ConfigModule, NodeModule],
  providers: [TransporterSettings, MailerConfig, MailerProvider],
  exports: [MailerProvider],
})
export class MailerModule {}
