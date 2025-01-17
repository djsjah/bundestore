import {
  Req,
  Res,
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
  NotFoundException,
} from '@nestjs/common';
import { Request, Response } from 'express';

import { JWT, JWTProvider } from '@/utils';
import { UserService } from '@/domain/user/service/user.service';
import { IUserPayload } from '@/domain/user';

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(
    private readonly jwtProvider: JWTProvider,
    private readonly userService: UserService,
  ) { }

  private readonly unExceptionMessage: string = 'You are not authorized';

  public async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<Request>();
    const response = context.switchToHttp().getResponse<Response>();

    let accessToken = request.cookies[JWT.access];

    if (!accessToken && request.cookies[JWT.refresh]) {
      accessToken = await this.refreshAccessToken(request, response);
    } else if (!accessToken && !request.cookies[JWT.refresh]) {
      throw new UnauthorizedException(this.unExceptionMessage);
    }

    const userPayload: IUserPayload = await this.jwtProvider.validateJWT(accessToken);
    request.user = this.filterUserPayload(userPayload);

    return true;
  }

  private async refreshAccessToken(@Req() req: Request, @Res() res: Response): Promise<string> {
    try {
      await this.userService.getByUniqueParams({
        where: {
          refreshToken: req.cookies[JWT.refresh],
        },
      });
    } catch (err) {
      if (err instanceof NotFoundException) {
        throw new UnauthorizedException(this.unExceptionMessage);
      }

      throw err;
    }

    const userPayload: IUserPayload = await this.jwtProvider.validateJWT(req.cookies[JWT.refresh]);
    const accessToken = this.jwtProvider.generateJWT(this.filterUserPayload(userPayload), JWT.access);
    res.cookie(JWT.access, accessToken, this.jwtProvider.createJWTCookie(JWT.access));

    return accessToken;
  }

  private filterUserPayload(userPayload: IUserPayload): IUserPayload {
    const refreshUserPayload: IUserPayload = {
      id: userPayload.id,
      email: userPayload.email,
      role: userPayload.role,
      ...(userPayload.firstName && { firstName: userPayload.firstName }),
      ...(userPayload.lastName && { lastName: userPayload.lastName }),
      ...(userPayload.birthDate && { birthDate: userPayload.birthDate }),
      ...(userPayload.phoneNumber && { phoneNumber: userPayload.phoneNumber })
    };

    return refreshUserPayload;
  }
}
