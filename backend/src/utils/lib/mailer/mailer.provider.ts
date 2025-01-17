import { Injectable } from '@nestjs/common';
import { Transporter, createTransport } from 'nodemailer';

import { MailerConfig } from './mailer.config';

@Injectable()
export class MailerProvider {
  private readonly mailerTransporter: Transporter;

  constructor(private readonly mailerConfig: MailerConfig) {
    this.mailerTransporter = createTransport(this.mailerConfig.getTransporterSettings());
  }

  public getTransporter(): Transporter {
    return this.mailerTransporter;
  }
}
