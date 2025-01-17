import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { useLocation } from 'react-router-dom';

import { FOOTBALL_CLUBS, FOOTBALL_CLUBS_LABELS, FOOTBALL_CLUBS_LOGOS } from '@/constants';
import type { ProductsFilters } from '@/types';
import type { GetAgeDTO, GetCategoryDTO, GetFootballClubDTO, GetGenderDTO } from '@/api';
import { useAlert, useGetCartQuery, useGetProductsQuery } from '@/hooks';
import {
  ErrorMessage,
  FiltersSection,
  ProductCard,
  ProductSizeChoiceModal,
  Skeleton,
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from '@/components';

export const CatalogPage = () => {
  const location = useLocation();
  const queryParams = useMemo(() => new URLSearchParams(location.search), [location.search]);

  const { openAlert } = useAlert();

  const initialFilters = useMemo(
    () => ({
      category: (queryParams.get('category') as GetCategoryDTO) || DEFAULT_FILTERS.category,
      club: (queryParams.get('club') as GetFootballClubDTO) || DEFAULT_FILTERS.club,
      age: (queryParams.get('age') as GetAgeDTO) || DEFAULT_FILTERS.age,
      gender: (queryParams.get('gender') as GetGenderDTO) || DEFAULT_FILTERS.gender,
    }),
    [queryParams],
  );

  const [filters, setFilters] = useState<ProductsFilters>(initialFilters);

  const [maxProductPrice, setMaxProductPrice] = useState<number | null>(null);
  const [maxPrice, setMaxPrice] = useState<number | null>(null);

  const {
    data: products,
    isLoading: isLoadingProducts,
    error: errorProducts,
  } = useGetProductsQuery(maxPrice !== null ? { ...filters, maxPrice } : filters);

  const { data: cart, isLoading: isLoadingCart, error: errorCart } = useGetCartQuery();

  useEffect(() => {
    if (products) {
      const maxProductPrice = Math.max(...products.map(product => product.price));
      setMaxProductPrice(maxProductPrice);
      setMaxPrice(maxProductPrice);
    }
  }, [products]);

  useEffect(() => {
    if (errorProducts && errorProducts.status !== 404) {
      openAlert('Something went wrong!', 'destructive');
    }
  }, [errorProducts, openAlert]);

  const handleFilterChange = useCallback((data: Partial<ProductsFilters>) => {
    setFilters(prevState => ({
      ...prevState,
      ...data,
    }));

    setMaxProductPrice(null);
    setMaxPrice(null);
  }, []);

  return (
    <React.Fragment>
      <div className="flex gap-6 p-4 flex-col lg:flex-row">
        <div className="flex flex-col gap-4 lg:w-1/3 xl:w-1/4">
          <div className="border-2 border-zinc-900 rounded-lg shadow-md py-4">
            <img src={FOOTBALL_CLUBS_LOGOS[filters.club]} alt={filters.club} className="mx-auto w-fit h-32" />
          </div>
          <FiltersSection
            category={filters.category}
            age={filters.age}
            gender={filters.gender}
            maxProductPrice={maxProductPrice}
            maxPriceFilter={maxPrice}
            setMaxPriceFilter={setMaxPrice}
            onFilterChange={handleFilterChange}
            onResetFilters={() => {
              setFilters(DEFAULT_FILTERS);
              setMaxPrice(maxProductPrice);
            }}
          />
        </div>
        <div className="flex-1">
          <Tabs value={filters.club} onValueChange={club => handleFilterChange({ club: club as GetFootballClubDTO })}>
            <TabsList className="mb-5 w-full overflow-auto">
              {FOOTBALL_CLUBS.map(club => (
                <TabsTrigger key={club} value={club}>
                  <span className="uppercase">{FOOTBALL_CLUBS_LABELS[club]}</span>
                </TabsTrigger>
              ))}
            </TabsList>
            {FOOTBALL_CLUBS.map(club => (
              <TabsContent key={club} value={club}>
                {isLoadingProducts || isLoadingCart ? (
                  <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-6">
                    {Array.from({ length: 7 }).map((_, index) => (
                      <Skeleton key={index} className="h-[300px] rounded-lg" />
                    ))}
                  </div>
                ) : errorProducts || (errorCart && errorCart.status !== 401) || !products ? (
                  errorProducts?.status === 404 ? (
                    <div className="flex justify-center items-center mt-2 lg:mt-10">
                      <p className="text-zinc-400 text-lg">No Products found matching these Criteria</p>
                    </div>
                  ) : (
                    <div className="flex justify-center items-center mt-2 lg:mt-10">
                      <ErrorMessage size="lg">Server Error</ErrorMessage>
                    </div>
                  )
                ) : (
                  <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-6">
                    {products
                      .filter(product => product.club === club)
                      .map(product => (
                        <ProductCard
                          key={product.id}
                          id={product.id}
                          category={product.category}
                          image={product.imageUrl}
                          name={product.name}
                          description={product.description}
                          price={product.price}
                          variants={product.variants}
                          isInCart={!!cart?.orderItems.find(orderItem => orderItem.productId === product.id)}
                        />
                      ))}
                  </div>
                )}
              </TabsContent>
            ))}
          </Tabs>
        </div>
      </div>
      <ProductSizeChoiceModal />
    </React.Fragment>
  );
};

const DEFAULT_FILTERS: ProductsFilters = {
  category: 'UPPER_CLOTHING',
  club: 'BAYERN_MUNICH',
  age: 'ADULT',
  gender: 'MEN',
};
