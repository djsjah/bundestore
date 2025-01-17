import type {
  GetAgeDTO,
  GetClothingSizeDTO,
  GetFootballClubDTO,
  GetFootwearSizeDTO,
  GetGenderDTO,
  GetCategoryDTO,
} from '@/api';

export const FOOTBALL_CLUBS: GetFootballClubDTO[] = [
  'BAYERN_MUNICH',
  'BORUSSIA_DORTMUND',
  'RB_LEIPZIG',
  'BAYER_04_LEVERKUSEN',
  'HOFFENHEIM',
];

export const FOOTBALL_CLUBS_LOGOS: Record<GetFootballClubDTO, string> = {
  BAYERN_MUNICH: '/src/assets/images/clubs-logos/bayer-munich.png',
  BORUSSIA_DORTMUND: '/src/assets/images/clubs-logos/borussia-dortmund.png',
  RB_LEIPZIG: '/src/assets/images/clubs-logos/rb-leipzig.png',
  BAYER_04_LEVERKUSEN: '/src/assets/images/clubs-logos/bayer-04-leverkusen.png',
  HOFFENHEIM: '/src/assets/images/clubs-logos/hoffenheim.png',
};

export const FOOTBALL_CLUBS_LABELS: Record<GetFootballClubDTO, string> = {
  BAYERN_MUNICH: 'Bayern Munich',
  BORUSSIA_DORTMUND: 'Borussia Dortmund',
  RB_LEIPZIG: 'RB Leipzig',
  BAYER_04_LEVERKUSEN: 'Bayer 04 Leverkusen',
  HOFFENHEIM: 'Hoffenheim',
};

export const CATEGORY_LABELS: Record<GetCategoryDTO, string> = {
  UPPER_CLOTHING: 'Upper Clothing',
  LOWER_CLOTHING: 'Lower Clothing',
  FOOTWEAR: 'Footwear',
  ACCESSORIES: 'Accessories',
};

export const AGE_LABELS: Record<GetAgeDTO, string> = {
  CHILD: 'Children',
  ADULT: 'Adult',
};

export const GENDER_LABELS: Record<GetGenderDTO, string> = {
  WOMEN: 'Women',
  MEN: 'Men',
  UNISEX: 'Unisex',
};

export const SIZE_LABELS: Record<GetClothingSizeDTO | GetFootwearSizeDTO, string> = {
  SIZE_S: 'S',
  SIZE_M: 'M',
  SIZE_L: 'L',
  SIZE_XL: 'XL',
  SIZE_33: '33',
  SIZE_34: '34',
  SIZE_35: '35',
  SIZE_36: '36',
  SIZE_37: '37',
  SIZE_38: '38',
  SIZE_39: '39',
  SIZE_40: '40',
  SIZE_41: '41',
  SIZE_42: '42',
};

export const CATEGORY_OPTIONS: { value: GetCategoryDTO; label: string }[] = [
  {
    value: 'UPPER_CLOTHING',
    label: CATEGORY_LABELS['UPPER_CLOTHING'],
  },
  {
    value: 'LOWER_CLOTHING',
    label: CATEGORY_LABELS['LOWER_CLOTHING'],
  },
  {
    value: 'FOOTWEAR',
    label: CATEGORY_LABELS['FOOTWEAR'],
  },
  {
    value: 'ACCESSORIES',
    label: CATEGORY_LABELS['ACCESSORIES'],
  },
];

export const AGE_OPTIONS: { value: GetAgeDTO; label: string }[] = [
  {
    value: 'CHILD',
    label: AGE_LABELS['CHILD'],
  },
  {
    value: 'ADULT',
    label: AGE_LABELS['ADULT'],
  },
];

export const GENDER_OPTIONS: { value: GetGenderDTO; label: string }[] = [
  {
    value: 'WOMEN',
    label: GENDER_LABELS['WOMEN'],
  },
  {
    value: 'MEN',
    label: GENDER_LABELS['MEN'],
  },
  {
    value: 'UNISEX',
    label: GENDER_LABELS['UNISEX'],
  },
];
