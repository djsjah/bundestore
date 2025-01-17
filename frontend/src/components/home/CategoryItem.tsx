/* eslint-disable max-len */
import { useCallback } from 'react';
import { useNavigate } from 'react-router-dom';

import { APP_ROUTER } from '@/constants';
import type { GetAgeDTO, GetGenderDTO } from '@/api';

import { Button } from '../shadcn';

type CategoryBlockProps = {
  title: string;
  image: string;
  filter: {
    gender?: GetGenderDTO;
    age?: GetAgeDTO;
  };
};

export const CategoryItem: React.FC<CategoryBlockProps> = ({ title, image, filter }) => {
  const navigate = useNavigate();

  const handleOpenCatalog = useCallback(() => {
    const queryParams = new URLSearchParams();

    if (filter.gender) {
      queryParams.set('gender', filter.gender);
    }

    if (filter.age) {
      queryParams.set('age', filter.age);
    }

    navigate(`${APP_ROUTER.CATALOG}?${queryParams.toString()}`);
  }, [filter.age, filter.gender, navigate]);

  return (
    <div className="relative group rounded-lg overflow-hidden shadow-md">
      <img src={image} alt={title} className="w-full h-[320px] object-cover" />
      <div className="absolute inset-0 bg-black bg-opacity-50 flex items-center justify-center opacity-0 group-hover:opacity-100 transition duration-300">
        <Button type="button" variant="secondary" onClick={handleOpenCatalog}>
          Catalog
        </Button>
      </div>
      <div className="absolute bottom-0 left-0 p-4 font-semibold bg-black bg-opacity-50 w-full">{title}</div>
    </div>
  );
};
