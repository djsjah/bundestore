import type { GetProductsQueryParams } from '@/api';

export type ProductsFilters = Omit<Required<GetProductsQueryParams>, 'maxPrice'>;
