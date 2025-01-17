import { IUserPayload } from '@/domain/user';
import { JWT } from '@/utils';

export type AuthData = Record<JWT, string> & {
  newUserPayload: IUserPayload;
};
