import {
  registerDecorator,
  ValidationArguments,
  ValidationOptions,
  ValidatorConstraint,
  ValidatorConstraintInterface,
} from 'class-validator';

export function IsEqual(property: string, validationOptions?: ValidationOptions) {
  return (object: any, propertyName: string) => {
    registerDecorator({
      target: object.constructor,
      propertyName,
      options: validationOptions,
      constraints: [property],
      validator: IsEqualConstraint,
    });
  };
}

@ValidatorConstraint({ name: 'IsEqual' })
export class IsEqualConstraint implements ValidatorConstraintInterface {
  public validate(value: any, args: ValidationArguments): boolean {
    const [relatedPropertyName] = args.constraints;
    const relatedValue = (args.object as any)[relatedPropertyName];
    return value === relatedValue;
  }

  public defaultMessage(args: ValidationArguments): string {
    return args.property + ' must be equal to ' + args.constraints[0];
  }
}
