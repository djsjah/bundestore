import type { GetAgeDTO, GetGenderDTO } from '@/api';
import { HeroBlock, CategoryItem } from '@/components';

export const HomePage: React.FC = () => {
  return (
    <div>
      <HeroBlock />
      <section className="mt-12 p-8 rounded-lg shadow-md">
        <h2 className="text-2xl font-bold mb-4">About Us</h2>
        <p className="text-lg mt-4">
          Whether you’re cheering from the stands or playing on the field, we’ve got the perfect gear for you. Our
          collection includes official jerseys, scarves, footwear, and other fan merchandise from top football clubs.
          <br /> Whether you’re a dedicated supporter or a new fan, you’ll find everything you need to represent your
          team with pride!
        </p>
      </section>
      <section className="mt-10">
        <div className="flex flex-col lg:flex-row gap-6 mb-10">
          {CATEGORIES.map(category => (
            <div key={category.title} className="flex-1">
              <CategoryItem
                image={category.image}
                title={category.title}
                filter={{
                  gender: category.gender,
                  age: category.age,
                }}
              />
            </div>
          ))}
        </div>
      </section>
    </div>
  );
};

const CATEGORIES: {
  title: string;
  image: string;
  gender?: GetGenderDTO;
  age?: GetAgeDTO;
}[] = [
  {
    title: 'Men Clothing',
    image: '/src/assets/images/men-category.jpg',
    gender: 'MEN',
  },
  {
    title: 'Women Clothing',
    image: '/src/assets/images/women-category.jpg',
    gender: 'WOMEN',
  },
  {
    title: 'Child Clothing',
    image: '/src/assets/images/child-category.jpg',
    age: 'CHILD',
  },
];
