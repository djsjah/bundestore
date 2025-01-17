import type { GetAgeDTO, GetGenderDTO, GetCategoryDTO, GetFootballClubDTO } from '@/api';

export type GetProductsQueryParams = {
  category?: GetCategoryDTO;
  club?: GetFootballClubDTO;
  age?: GetAgeDTO;
  maxPrice?: number;
  gender?: GetGenderDTO;
};
