import { Injectable } from '@nestjs/common';
import { CookieOptions } from 'express';

import { NodeConfig, NodeENV } from '@/utils/node';

@Injectable()
export class JWTConfig {
  private readonly jwtCookieSettings: Record<NodeENV, CookieOptions> = {
    dev: {
      secure: false,
    },
    prod: {
      secure: true,
    },
  };

  constructor(private readonly nodeConfig: NodeConfig) {}

  public getCookieSettings(): CookieOptions {
    return {
      httpOnly: true,
      ...this.jwtCookieSettings[this.nodeConfig.getNodeENV()],
    };
  }
}
