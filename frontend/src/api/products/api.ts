import type { GetProductDTO } from './dto';
import type { GetProductsQueryParams } from './params';

export const getProduct = async (id: string): Promise<GetProductDTO> => {
  const response = await fetch(`${import.meta.env.VITE_API_DOMAIN}/products/${id}`);

  if (!response.ok) {
    const message = await response.text();
    throw {
      message,
      status: response.status,
    };
  }

  return await response.json();
};

export const getProducts = async (filters: GetProductsQueryParams): Promise<GetProductDTO[]> => {
  const queryParams = new URLSearchParams();

  if (filters.category) {
    queryParams.set('category', filters.category);
  }

  if (filters.age) {
    queryParams.set('age', filters.age);
  }

  if (filters.gender) {
    queryParams.set('gender', filters.gender);
  }

  if (filters.club) {
    queryParams.set('club', filters.club);
  }

  if (filters.maxPrice !== undefined) {
    queryParams.set('price[lte]', filters.maxPrice.toString());
  }

  const response = await fetch(`${import.meta.env.VITE_API_DOMAIN}/products?${queryParams}`);

  if (!response.ok) {
    const message = await response.text();

    throw {
      message,
      status: response.status,
    };
  }

  return await response.json();
};
