import type { GetOrderStatusDTO } from '@/api';

export const ORDER_STATUSES_LABELS: Record<GetOrderStatusDTO, string> = {
  CREATED: 'Created',
  REVIEW: 'On Review',
  CONFIRMED: 'Confirmed',
  REJECTED: 'Rejected',
  SHIPPED: 'Shipped',
  DELIVERED: 'Delivered',
};
