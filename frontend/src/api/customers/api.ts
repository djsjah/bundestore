import type { UpdateCustomerDTO } from './dto';

export const updateCustomerInfo = async (userData: UpdateCustomerDTO) => {
  const response = await fetch(`${import.meta.env.VITE_API_DOMAIN}/customers/me`, {
    method: 'PATCH',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(userData),
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
