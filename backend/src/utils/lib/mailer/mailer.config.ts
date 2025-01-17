import { Injectable } from '@nestjs/common';
import SMTPTransport from 'nodemailer/lib/smtp-transport';

import { NodeConfig } from '@/utils/node/node.config';

import { TransporterSettings } from './transporter.settings';

@Injectable()
export class MailerConfig {
  constructor(
    private readonly transporterSettings: TransporterSettings,
    private readonly nodeConfig: NodeConfig,
  ) {}

  public getTransporterSettings(): SMTPTransport.Options {
    return this.transporterSettings.getSettings(this.nodeConfig.getNodeENV());
  }
}
