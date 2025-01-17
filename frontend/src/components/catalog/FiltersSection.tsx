/* eslint-disable max-len */
import { useEffect, useState } from 'react';

import { AGE_OPTIONS, CATEGORY_OPTIONS, GENDER_OPTIONS } from '@/constants';
import type { ProductsFilters } from '@/types';
import type { GetAgeDTO, GetGenderDTO, GetCategoryDTO } from '@/api';
import { useDebounce } from '@/hooks';
import { cn } from '@/utils';

import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  Label,
  Button,
  RadioGroup,
  RadioGroupItem,
  LabeledSlider,
} from '../shadcn';

type FiltersSectionProps = {
  category: GetCategoryDTO;
  age: GetAgeDTO;
  gender: GetGenderDTO;
  maxProductPrice: number | null;
  maxPriceFilter: number | null;
  setMaxPriceFilter: (maxPrice: number) => void;
  onFilterChange: (data: Partial<ProductsFilters>) => void;
  onResetFilters: () => void;
};

export const FiltersSection: React.FC<FiltersSectionProps> = ({
  category,
  age,
  gender,
  maxProductPrice,
  maxPriceFilter,
  setMaxPriceFilter,
  onFilterChange,
  onResetFilters,
}) => {
  const [maxPrice, setMaxPrice] = useState(maxPriceFilter);
  const debouncedMaxPrice = useDebounce(maxPrice);

  useEffect(() => {
    setMaxPrice(maxPriceFilter);
  }, [maxPriceFilter]);

  useEffect(() => {
    if (debouncedMaxPrice !== null) {
      setMaxPriceFilter(debouncedMaxPrice);
    }
  }, [debouncedMaxPrice, setMaxPriceFilter]);

  return (
    <div className="h-fit p-6 bg-zinc-950 bg-opacity-90 backdrop-blur-sm border-2 border-zinc-900 rounded-lg shadow-md">
      <h2 className="text-lg font-bold mb-4 text-center zinc-900">Filters</h2>
      <div className="flex flex-col gap-6 mb-8">
        <div>
          <h3 className="font-semibold mb-2">Category</h3>
          <RadioGroup value={category} onValueChange={value => onFilterChange({ category: value as GetCategoryDTO })}>
            <div className="flex flex-col flex-wrap gap-2 sm:flex-row sm:gap-4 lg:flex-col lg:gap-2">
              {CATEGORY_OPTIONS.map(category => (
                <div key={category.value} className="flex items-center gap-2">
                  <RadioGroupItem value={category.value} id={category.value} />
                  <Label htmlFor={category.value}>{category.label}</Label>
                </div>
              ))}
            </div>
          </RadioGroup>
        </div>
        <div className="flex flex-col gap-6 sm:flex-row lg:flex-col">
          <div>
            <h3 className="font-semibold mb-2">Age Category</h3>
            <Select value={age} onValueChange={value => onFilterChange({ age: value as GetAgeDTO })}>
              <SelectTrigger className="w-[180px]">
                <SelectValue placeholder="Age" />
              </SelectTrigger>
              <SelectContent>
                {AGE_OPTIONS.map(age => (
                  <SelectItem key={age.value} value={age.value}>
                    {age.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div>
            <h3 className="font-semibold mb-2">Gender</h3>
            <Select value={gender} onValueChange={value => onFilterChange({ gender: value as GetGenderDTO })}>
              <SelectTrigger className="w-[180px]">
                <SelectValue placeholder="Gender" />
              </SelectTrigger>
              <SelectContent>
                {GENDER_OPTIONS.map(gender => (
                  <SelectItem key={gender.value} value={gender.value}>
                    {gender.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>
        <div>
          <h3 className="font-semibold mb-2">Max Price</h3>
          <div className={cn({ 'pointer-events-none opacity-80': maxProductPrice === null })}>
            <LabeledSlider
              value={[maxPrice || 0]}
              max={maxProductPrice || 0}
              onValueChange={value => setMaxPrice(value[0])}
              formatLabel={value => `$${value}`}
            />
          </div>
        </div>
      </div>
      <Button type="button" variant="secondary" onClick={onResetFilters}>
        Reset Filters
      </Button>
    </div>
  );
};
