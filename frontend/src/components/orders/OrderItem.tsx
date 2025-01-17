import { useNavigate } from 'react-router-dom';

import { APP_ROUTER, ORDER_STATUSES_LABELS } from '@/constants';
import type { GetOrderDTO } from '@/api';
import { useGetProductsByIdsQuery } from '@/hooks';
import { formatDate } from '@/utils';

import { ErrorMessage } from '../common';
import { Card, CardTitle, CardContent, CardHeader, Skeleton } from '../shadcn';

type OrderItemProps = GetOrderDTO;

export const OrderItem: React.FC<OrderItemProps> = ({ id, total, quantity, status, orderItems, createdAt }) => {
  const navigate = useNavigate();

  const productIds = orderItems.map(item => item.productId);

  const {
    data: products,
    isLoading: isLoadingProducts,
    isError: isErrorProducts,
  } = useGetProductsByIdsQuery(productIds);

  return (
    <Card>
      <CardHeader className="flex flex-row justify-between mb-2">
        <div>
          <CardTitle className="text-xl mb-1">Order #{id.slice(0, 6)}</CardTitle>
          <p className="text-sm text-zinc-400">{formatDate(new Date(createdAt))}</p>
        </div>
        <p className="text-lg font-semibold border-2 border-zinc-900 py-2 px-4 rounded-md h-fit">
          {ORDER_STATUSES_LABELS[status]}
        </p>
      </CardHeader>
      <CardContent className="flex flex-col gap-10 lg:flex-row lg:gap-14 lg:justify-between">
        <div className="flex flex-wrap gap-4">
          {isLoadingProducts ? (
            Array.from({ length: 5 }).map((_, index) => <Skeleton key={index} className="w-16 h-20 rounded-md" />)
          ) : isErrorProducts || !products ? (
            <ErrorMessage>Error Loading Products</ErrorMessage>
          ) : (
            products.map((product, index) => (
              <img
                key={index}
                src={product.imageUrl}
                alt={product.name}
                className="w-16 h-20 object-cover cursor-pointer rounded-md"
                onClick={() => navigate(`${APP_ROUTER.CATALOG}/${product.id}`)}
              />
            ))
          )}
        </div>
        <div className="flex flex-col items-end gap-2">
          <p className="text-right">
            Items: <span className="font-semibold">{quantity}</span>
          </p>
          <p className="text-lg text-right">
            Total: <span className="font-semibold">${total.toFixed(2)}</span>
          </p>
        </div>
      </CardContent>
    </Card>
  );
};
