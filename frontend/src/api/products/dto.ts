export type GetFootballClubDTO =
  | 'BAYERN_MUNICH'
  | 'BORUSSIA_DORTMUND'
  | 'RB_LEIPZIG'
  | 'BAYER_04_LEVERKUSEN'
  | 'HOFFENHEIM';

export type GetCategoryDTO = 'UPPER_CLOTHING' | 'LOWER_CLOTHING' | 'FOOTWEAR' | 'ACCESSORIES';

export type GetAgeDTO = 'CHILD' | 'ADULT';

export type GetGenderDTO = 'MEN' | 'WOMEN' | 'UNISEX';

export type GetClothingSizeDTO = 'SIZE_S' | 'SIZE_M' | 'SIZE_L' | 'SIZE_XL';

export type GetFootwearSizeDTO =
  | 'SIZE_33'
  | 'SIZE_34'
  | 'SIZE_35'
  | 'SIZE_36'
  | 'SIZE_37'
  | 'SIZE_38'
  | 'SIZE_39'
  | 'SIZE_40'
  | 'SIZE_41'
  | 'SIZE_42';

export type GetProductVariantDTO = {
  size?: GetClothingSizeDTO | GetFootwearSizeDTO;
  stockQuantity: number;
};

type ProductDTO = {
  id: string;
  imageUrl: string;
  name: string;
  description: string;
  price: number;
  club: GetFootballClubDTO;
  category: GetCategoryDTO;
  age: GetAgeDTO;
  gender: GetGenderDTO;
  stockQuantity: number;
  variants: GetProductVariantDTO[];
};

export type GetProductDTO = ProductDTO;
