import type { GetCartDTO, AddProductToCartDTO } from './dto';

export const getCart = async (): Promise<GetCartDTO> => {
  const response = await fetch(`${import.meta.env.VITE_API_DOMAIN}/carts/me`, { credentials: 'include' });

  if (!response.ok) {
    const message = await response.text();
    throw {
      message,
      status: response.status,
    };
  }

  return await response.json();
};

export const addProductToCart = async (productData: AddProductToCartDTO) => {
  const response = await fetch(`${import.meta.env.VITE_API_DOMAIN}/carts/me/items`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(productData),
    credentials: 'include',
  });

  if (!response.ok) {
    const message = await response.text();
    throw {
      message,
      status: response.status,
    };
  }
};

export const updateCartItemQuantity = async ({ orderItemId, quantity }: { orderItemId: string; quantity: number }) => {
  const response = await fetch(`${import.meta.env.VITE_API_DOMAIN}/carts/me/items/${orderItemId}`, {
    method: 'PATCH',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ quantity }),
    credentials: 'include',
  });

  if (!response.ok) {
    const message = await response.text();
    throw {
      message,
      status: response.status,
    };
  }
};

export const deleteCartItem = async (orderItemId: string) => {
  const response = await fetch(`${import.meta.env.VITE_API_DOMAIN}/carts/me/items/${orderItemId}`, {
    method: 'DELETE',
    credentials: 'include',
  });

  if (!response.ok) {
    const message = await response.text();
    throw {
      message,
      status: response.status,
    };
  }
};
