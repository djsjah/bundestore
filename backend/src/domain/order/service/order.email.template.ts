import { Injectable } from '@nestjs/common';

import { EmailTemplate } from '@/abstract/email';

import { IOrderData } from '../types/order.data.interface';
import { OrderEmailSubject } from '../types/order.email.subject.enum';

@Injectable()
export class OrderEmailTemplate extends EmailTemplate {
  constructor() {
    super();
  }

  protected override readonly emailBasicSubjects: Record<OrderEmailSubject, string> = {
    purchase: 'New Purchase',
  };

  public override getEmailSubject(emailSubject: OrderEmailSubject): string {
    return this.emailBasicSubjects[emailSubject];
  }

  public createPurchaseEmail(orderData: IOrderData): string {
    const purchaseEmail: string = `<p>The customer has placed a <strong>new order ${orderData.createdAt}</strong></p>
    <p><strong>Order Details</strong>:</p>`;

    return this.generateListHTML(orderData, purchaseEmail);
  }
}
