import type { UpdateUserDTO } from './dto';

export const updateUserInfo = async (userData: UpdateUserDTO) => {
  const response = await fetch(`${import.meta.env.VITE_API_DOMAIN}/users/me`, {
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
