import { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';

import { APP_ROUTER } from '@/constants';
import type { GetClothingSizeDTO, GetFootwearSizeDTO } from '@/api';
import { useDebounce, useGetProductQuery } from '@/hooks';
import { cn } from '@/utils';
import DeleteIcon from '@/assets/icons/delete.svg?react';

import { Button, Input, Skeleton } from '../shadcn';
import { SizeOption } from '../common';

type CartItemProps = {
  id: string;
  productId: string;
  total: number;
  size?: GetFootwearSizeDTO | GetClothingSizeDTO;
  quantity: number;
  stockQuantity: number;
  onQuantityChange: (id: string, quantity: number) => void;
  onDelete: (id: string) => void;
};

export const CartItem: React.FC<CartItemProps> = ({
  id,
  productId,
  total,
  size,
  quantity,
  stockQuantity,
  onQuantityChange,
  onDelete,
}) => {
  const navigate = useNavigate();

  const [updatedQuantity, setUpdatedQuantity] = useState(quantity);
  const debouncedQuantity = useDebounce(updatedQuantity);

  const { data: product, isLoading: isLoadingProduct } = useGetProductQuery(productId);

  useEffect(() => {
    if (debouncedQuantity !== quantity) {
      onQuantityChange(id, debouncedQuantity);
    }
  }, [debouncedQuantity, id, onQuantityChange, quantity]);

  const handleQuantityInput = useCallback(
    (value: number) => {
      if (value <= 1) {
        setUpdatedQuantity(1);
      } else if (value >= stockQuantity) {
        setUpdatedQuantity(stockQuantity);
      } else {
        setUpdatedQuantity(value);
      }
    },
    [stockQuantity],
  );

  const handleViewProduct = useCallback(() => {
    navigate(`${APP_ROUTER.CATALOG}/${productId}`);
  }, [productId, navigate]);

  return (
    <div className="flex flex-col lg:flex-row lg:items-center justify-between p-4 border-2 border-zinc-900 rounded-md">
      <div className="flex items-center gap-4 lg:w-3/5">
        {isLoadingProduct ? (
          <Skeleton className="w-20 h-32" />
        ) : (
          <img
            src={product?.imageUrl}
            alt={product?.name}
            className="w-20 h-32 object-cover rounded-md cursor-pointer"
            onClick={handleViewProduct}
          />
        )}
        <div className="flex flex-col flex-1 gap-4">
          <div className="flex justify-between gap-8">
            <div className="flex flex-col gap-2">
              {isLoadingProduct ? (
                <Skeleton className="w-20 h-10" />
              ) : (
                <p className="font-semibold cursor-pointer max-w-[200px]" onClick={handleViewProduct}>
                  {product?.name}
                </p>
              )}
              {size && (
                <div className="w-fit">
                  <SizeOption size={size} isSelected disabled />
                </div>
              )}
              <p className="font-semibold truncate lg:hidden">${total.toFixed(2)}</p>
            </div>
            <p
              className={cn('text-end lg:hidden', {
                'text-green-500': stockQuantity > 0,
                'text-red-500': stockQuantity <= 0,
              })}
            >
              {stockQuantity > 0 ? `In stock: ${stockQuantity}` : 'Out of stock'}
            </p>
          </div>
          <Button
            type="button"
            variant="ghost"
            onClick={() => onDelete(id)}
            className="w-fit py-1 px-2 hidden lg:block"
          >
            <DeleteIcon />
          </Button>
        </div>
      </div>
      <div className="flex justify-between items-end mt-6 lg:mt-0">
        <div className="flex items-center gap-2 min-w-[140px]">
          <Button
            type="button"
            variant="outline"
            onClick={() => setUpdatedQuantity(updatedQuantity - 1)}
            disabled={updatedQuantity <= 1}
            className="min-w-9 p-3"
          >
            -
          </Button>
          <Input
            value={updatedQuantity}
            onChange={e => handleQuantityInput(Number(e.target.value))}
            className="w-12 text-center border-none rounded-md hover:ring-2 hover:ring-zinc-900 max-w-12"
          />
          <Button
            type="button"
            variant="outline"
            onClick={() => setUpdatedQuantity(updatedQuantity + 1)}
            disabled={updatedQuantity >= stockQuantity}
            className="min-w-9 p-3"
          >
            +
          </Button>
        </div>
        <Button type="button" variant="ghost" onClick={() => onDelete(id)} className="w-fit py-1 px-2 lg:hidden">
          <DeleteIcon />
        </Button>
      </div>
      <div className="min-w-[100px] w-28 h-full hidden lg:flex lg:flex-col lg:gap-4 items-end">
        <p className={cn('text-end', { 'text-green-500': stockQuantity > 0, 'text-red-500': stockQuantity <= 0 })}>
          {stockQuantity > 0 ? `In stock: ${stockQuantity}` : 'Out of stock'}
        </p>
        <p className="font-semibold truncate">${total.toFixed(2)}</p>
      </div>
    </div>
  );
};
