import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import SMTPTransport from 'nodemailer/lib/smtp-transport';

import { NodeENV } from '@/utils/node';

@Injectable()
export class TransporterSettings {
  private readonly settings: Record<NodeENV, SMTPTransport.Options> = {
    dev: {
      secure: false,
      requireTLS: true,
      tls: {
        rejectUnauthorized: false,
      },
    },
    prod: {
      secure: true,
      tls: {
        rejectUnauthorized: true,
      },
    },
  };

  constructor(private readonly configService: ConfigService) {}

  public getSettings(nodeENV: NodeENV): SMTPTransport.Options {
    return {
      ...this.settings[nodeENV],
      host: this.configService.get('EMAIL_HOST'),
      service: this.configService.get('EMAIL_SERVICE'),
      auth: {
        user: this.configService.get('EMAIL_USERNAME'),
        pass: this.configService.get('EMAIL_PASSWORD'),
      },
    };
  }
}
