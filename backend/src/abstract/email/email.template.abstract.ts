/* eslint-disable max-len */
import { EmailBasicSubjects, IEmailBasic } from './types';

export abstract class EmailTemplate {
  protected abstract emailBasicSubjects: EmailBasicSubjects;

  protected readonly emailBasicHTML: IEmailBasic = {
    greet: '<p>Hello, this is <strong>Bundestore!</strong></p><br>',
    warn: '<p><strong>If you do not understand why you received this email, please ignore it.</strong></p>',
  };

  public abstract getEmailSubject(emailSubject: string): string;

  protected emailConstructor(mainPart: string): string {
    return this.emailBasicHTML.greet + mainPart + this.emailBasicHTML.warn;
  }

  protected generateListHTML(listData: object, curString: string, listType = 'ul', marginBottom: number = 10) {
    curString += `<${listType} style="margin-bottom: ${marginBottom * 3}px;">`;

    Object.entries(listData).forEach(([key, value]) => {
      if (Array.isArray(value)) {
        curString += `<li style="margin-bottom: ${marginBottom}px;"><strong style="display: inline-block; margin-bottom: ${marginBottom + 5}px;">${key}</strong>: `;
        value.forEach(item => {
          curString += `${this.generateListHTML(item, '')}`;
        });

        curString += '</li>';
        return;
      } else if (value && value.constructor === Object) {
        curString += `<li style="margin-bottom: ${marginBottom}px;"><strong>${key}</strong>: ${this.generateListHTML(value, '')}</li>`;
        return;
      }

      curString += `<li style="margin-bottom: ${marginBottom}px;"><strong>${key}</strong>: ${value}</li>`;
    });

    return `${curString}</${listType}>`;
  }
}
