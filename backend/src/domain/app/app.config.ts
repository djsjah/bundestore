/* eslint-disable @typescript-eslint/no-namespace */
import { NodeENV } from '@/utils';

import { IUserPayload } from '../user';

declare global {
  namespace Express {
    interface Request {
      user?: IUserPayload;
    }
  }
}

export default () => ({
  nodeENV: (process.env.NODE_ENV as NodeENV) || NodeENV.dev,
  protocol: process.env.PROTOCOL || 'http',
  host: process.env.HOST || 'localhost',
  port: parseInt(process.env.PORT as string, 10) || 3000,
  database: {
    main: {
      host: process.env.DATABASE_HOST || 'localhost',
      port: parseInt(process.env.DATABASE_PORT as string, 10) || 5432,
    },
  },
});
