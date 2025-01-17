import { Skeleton } from '../shadcn';

type OrderSummaryProps = {
  totalPrice?: number;
  totalQuantity?: number;
};

export const OrderSummary: React.FC<OrderSummaryProps> = ({ totalPrice, totalQuantity }) => {
  return (
    <div>
      <h3 className="font-semibold text-xl mb-4">Order Summary</h3>
      <div className="flex justify-between mb-6 lg:mb-2">
        <span className="font-medium">Total Quantity:</span>
        {totalQuantity ? <span className="font-medium">{totalQuantity}</span> : <Skeleton className="h-5 w-10" />}
      </div>
      <div className="flex justify-between">
        <span className="font-medium">Total:</span>
        {totalPrice ? <span className="font-medium">${totalPrice.toFixed(2)}</span> : <Skeleton className="h-5 w-10" />}
      </div>
    </div>
  );
};
