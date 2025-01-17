import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';

import { APP_ROUTER } from '@/constants';

import { Button, Carousel, CarouselContent, CarouselItem } from '../shadcn';

export const HeroBlock: React.FC = () => {
  const [currentIndex, setCurrentIndex] = useState(0);

  useEffect(() => {
    const interval = setInterval(() => {
      setCurrentIndex(index => (index + 1) % IMAGES.length);
    }, 3000);

    return () => clearInterval(interval);
  }, []);

  return (
    <section className="relative w-full h-[700px]">
      <Carousel className="absolute inset-0 h-full">
        <CarouselContent
          style={{ transform: `translateX(-${currentIndex * 100}%)` }}
          className="flex transition-transform duration-500 ease-in-out"
        >
          {IMAGES.map((image, index) => (
            <CarouselItem key={index}>
              <img src={image.src} alt="" className="w-full h-[700px] object-cover" />
            </CarouselItem>
          ))}
        </CarouselContent>
      </Carousel>
      <div className="absolute inset-0 bg-black bg-opacity-50 flex items-center justify-center text-center">
        <div className="p-10">
          <h1 className="text-4xl font-bold text-white">Welcome to Bundestore!</h1>
          <p className="text-xl text-zinc-500">The best football gear of your favorite teams.</p>
          <Link to={APP_ROUTER.CATALOG} className="block mt-4">
            <Button type="button" variant="secondary" size="lg">
              Browse Collections
            </Button>
          </Link>
        </div>
      </div>
    </section>
  );
};

const IMAGES = [
  { src: '/src/assets/images/hero-1.jpg' },
  { src: '/src/assets/images/hero-2.jpg' },
  { src: '/src/assets/images/hero-3.jpg' },
];
