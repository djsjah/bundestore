/* eslint-disable max-len */
import { Injectable } from '@nestjs/common';

import { EmailTemplate } from '@/abstract/email';

import { AuthEmailSubject } from '../types';
import { TokenVerifDTO } from '../dto';

@Injectable()
export class AuthEmailTemplate extends EmailTemplate {
  constructor() {
    super();
  }

  protected override readonly emailBasicSubjects: Record<AuthEmailSubject, string> = {
    activateAccount: 'Activate Account',
    recoverPassword: 'Recover Password',
  };

  public override getEmailSubject(emailSubject: AuthEmailSubject): string {
    return this.emailBasicSubjects[emailSubject];
  }

  public createActivationEmail(verifData: TokenVerifDTO): string {
    return this.emailConstructor(
      `<p>We are pleased to welcome you as a customer in our store!</p>
      <p>Please use this token to activate your account: <strong>${verifData.token}</strong></p>`,
    );
  }

  public createRecoverEmail(password: string): string {
    return this.emailConstructor(
      `<p>Please use this temporary password to log in: <strong>${password}</strong></p>
      <p><strong>We strongly recommend that you change your password immediately after you log in.</strong></p>`,
    );
  }
}
