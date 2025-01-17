import { Injectable } from '@nestjs/common';

import { EmailTemplate } from '@/abstract/email';
import { TokenVerifDTO } from '@/domain/auth';

import { UserEmailSubject } from '../types';

@Injectable()
export class UserEmailTemplate extends EmailTemplate {
  constructor() {
    super();
  }

  protected override readonly emailBasicSubjects: Record<UserEmailSubject, string> = {
    updateEmail: 'Update Email',
  };

  public override getEmailSubject(emailSubject: UserEmailSubject): string {
    return this.emailBasicSubjects[emailSubject];
  }

  public createModificationEmail(verifData: TokenVerifDTO): string {
    return this.emailConstructor(
      `<p>Please use this token to update your email: <strong>${verifData.token}</strong></p>`,
    );
  }
}
