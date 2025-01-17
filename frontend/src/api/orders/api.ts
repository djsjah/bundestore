import type { GetOrderDTO } from './dto';

export const getOrders = async (): Promise<GetOrderDTO[]> => {
  const response = await fetch(`${import.meta.env.VITE_API_DOMAIN}/orders/me`, { credentials: 'include' });

  if (!response.ok) {
    const message = await response.text();
    throw {
      message,
      status: response.status,
    };
  }

  return await response.json();
};

export const createOrder = async () => {
  const response = await fetch(`${import.meta.env.VITE_API_DOMAIN}/orders/me`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
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
