import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { CookieOptions } from 'express';
import jwt, { Secret } from 'jsonwebtoken';

import { IUserPayload } from '@/domain/user/types/user.payload.interface';

import { JWTConfig } from './jwt.config';
import { IJWTExpiration, JWT } from './types';

@Injectable()
export class JWTProvider {
  private readonly jwtSecret: Secret;
  private readonly jwtExpiration: IJWTExpiration = {
    access: 900000,
    refresh: 259200000,
  };

  constructor(
    private readonly configService: ConfigService,
    private readonly jwtConfig: JWTConfig,
  ) {
    this.jwtSecret = this.configService.get('JWT_SECRET') as Secret;
  }

  public generateJWT(userPayload: IUserPayload, jwtType: JWT): string {
    return jwt.sign(userPayload, this.jwtSecret, {
      expiresIn: `${this.jwtExpiration[jwtType]}ms`,
    });
  }

  public async validateJWT(token: string): Promise<IUserPayload> {
    return new Promise((resolve, reject) => {
      jwt.verify(token, this.jwtSecret, (err, decoded) => {
        if (err) {
          reject(new UnauthorizedException('You are not authorized'));
        }

        resolve(decoded as IUserPayload);
      });
    });
  }

  public createJWTCookie(jwtType: JWT): CookieOptions {
    return {
      ...this.jwtConfig.getCookieSettings(),
      maxAge: this.jwtExpiration[jwtType],
    };
  }
}
