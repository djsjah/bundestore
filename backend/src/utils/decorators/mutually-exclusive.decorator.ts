import { registerDecorator, ValidationArguments } from 'class-validator';

export function MutuallyExclusive(properties: string[]) {
  return function (object: object, propertyName: string) {
    registerDecorator({
      name: 'MutuallyExclusive',
      target: object.constructor,
      propertyName,
      constraints: properties,
      validator: {
        validate(value: any, args: ValidationArguments) {
          const relatedValues = properties.reduce(
            (acc, prop) => {
              acc[prop] = (args.object as any)[prop];
              return acc;
            },
            {} as Record<string, any>,
          );

          const hasNonNullableValue = Object.values(relatedValues).some(val => val !== undefined && val !== null);
          return !hasNonNullableValue || !(value !== undefined && value !== null);
        },
        defaultMessage(args: ValidationArguments) {
          return `Mutually-exclusive properties: ${args.constraints} and ${propertyName}`;
        },
      },
    });
  };
}
