import { IUserCreateConfig } from './types';

export const userCreateConfig: IUserCreateConfig = {
  phoneNummber: {
    rule: /^\+1\s\([0-9]{3}\)\s[0-9]{3}-[0-9]{4}$/,
    message: 'The value must be a valid phone number',
  },
};
