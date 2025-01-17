import { Controller, Post, Get, Patch, Param, Body, Req, Res, UseGuards } from '@nestjs/common';
import { Request, Response } from 'express';
import { User, Role } from '@prisma/client';
import { ApiTags, ApiOperation, ApiParam, ApiBody, ApiResponse } from '@nestjs/swagger';

import { CryptoProvider, MailerProvider, UseRole } from '@/utils';
import { RedisService } from '@/cache/redis';

import { AuthGuard, RoleGuard } from '../auth/guards';
import { AuthService } from '../auth/service/auth.service';
import { TokenVerifDTO } from '../auth';

import { UserService } from './service/user.service';
import { UserEmailTemplate } from './service/user.email.template';
import { UserCreateDTO, UserUpdateDTO, UserDTO } from './dto';
import { IUserPayload, UserEmailSubject } from './types';

@ApiTags('Users')
@Controller('api/users')
@UseGuards(AuthGuard, RoleGuard)
export class UserController {
  constructor(
    private readonly redisService: RedisService,
    private readonly authService: AuthService,
    private readonly userEmailTemplate: UserEmailTemplate,
    private readonly userService: UserService,
    private readonly crypto: CryptoProvider,
    private readonly mailer: MailerProvider,
  ) { }

  @ApiOperation({ summary: 'Get all Users' })
  @ApiResponse({ status: 200, description: 'Successful Response', type: [UserDTO] })
  @ApiResponse({ status: 401, description: 'Not Authorized' })
  @ApiResponse({ status: 403, description: 'Not Authorized as Administrator' })
  @ApiResponse({ status: 500, description: 'Internal Server Error' })
  @UseRole(Role.ADMINISTRATOR)
  @Get()
  public async getAll(): Promise<UserDTO[]> {
    const users = await this.userService.getMany({});
    return users;
  }

  @ApiOperation({ summary: 'Get User by Id' })
  @ApiParam({
    name: 'userId',
    required: true,
    description: 'User id',
  })
  @ApiResponse({ status: 200, description: 'User Details', type: UserDTO })
  @ApiResponse({ status: 401, description: 'Not Authorized' })
  @ApiResponse({ status: 403, description: 'Not Authorized as Administrator' })
  @ApiResponse({ status: 404, description: 'Not Found' })
  @ApiResponse({ status: 500, description: 'Internal Server Error' })
  @UseRole(Role.ADMINISTRATOR)
  @Get(':userId')
  public async getUniqueById(@Param('userId') userId: string): Promise<UserDTO> {
    const user = await this.userService.getByUniqueParams({
      where: {
        id: userId,
      },
    });

    return user;
  }

  @ApiOperation({ summary: 'Register User' })
  @ApiResponse({ status: 200, description: 'Successful Response' })
  @ApiResponse({ status: 400, description: 'Bad Request' })
  @ApiResponse({ status: 401, description: 'Not Authorized' })
  @ApiResponse({ status: 403, description: 'Not Authorized as Administrator' })
  @ApiResponse({ status: 500, description: 'Internal Server Error' })
  @ApiBody({
    type: UserCreateDTO,
    examples: {
      'User - Moderator': {
        value: {
          email: 'st1035@mail.ru',
          password: 'lejklgHKJS9018!?',
          role: 'MODERATOR',
        },
      },
    },
  })
  @UseRole(Role.ADMINISTRATOR)
  @Post()
  public async create(@Body() userCreateData: UserCreateDTO, @Res() res: Response): Promise<Response | void> {
    if (userCreateData.role !== Role.MODERATOR) {
      return res.status(400).send('You can only register a moderator');
    }

    userCreateData.isVerified = true;
    const newUser = await this.userService.create(userCreateData);

    res.status(200).json({
      message: 'User registered successfully',
      data: newUser,
    });
  }

  @ApiOperation({ summary: 'Update User Data' })
  @ApiResponse({ status: 200, description: 'User Updated Successfully' })
  @ApiResponse({ status: 400, description: 'Bad Request' })
  @ApiResponse({ status: 401, description: 'Not Authorized' })
  @ApiResponse({ status: 403, description: 'Not Authorized as Customer' })
  @ApiResponse({ status: 500, description: 'Internal Server Error' })
  @ApiBody({
    type: UserUpdateDTO,
    examples: {
      User: {
        value: {
          email: 'st1035@mail.ru',
          password: 'lejklgHKJS9018!?',
        },
      },
    },
  })
  @UseRole(Role.CUSTOMER)
  @Patch('me')
  public async update(@Req() req: Request, @Body() userUpdateData: UserUpdateDTO, @Res() res: Response) {
    const user = req.user as IUserPayload;
    const updateFields = Object.fromEntries(
      Object.entries(userUpdateData).filter(([key]) => this.userService.getUpdateFilter().includes(key as keyof User)),
    );

    const updatedUser = await this.userService.update(user.id, updateFields);
    const { refresh } = await this.authService.setJWTCookie(updatedUser, res);

    await this.userService.update(user.id, {
      refreshToken: refresh,
    });

    if (userUpdateData.email && user.email !== userUpdateData.email) {
      const verifToken = this.crypto.generateSecureVerifToken();

      await this.redisService.set(verifToken, userUpdateData.email);
      await this.mailer.getTransporter().sendMail({
        to: userUpdateData.email,
        subject: this.userEmailTemplate.getEmailSubject(UserEmailSubject.updateEmail),
        html: this.userEmailTemplate.createModificationEmail({
          token: verifToken,
        }),
      });
    }

    res.status(200).send('User updated successfully');
  }

  @ApiOperation({ summary: 'Update User Email' })
  @ApiBody({
    type: TokenVerifDTO,
    examples: {
      User: {
        value: {
          token: '4747918d87de',
        },
      },
    },
  })
  @ApiOperation({ summary: 'Update User Data' })
  @ApiResponse({ status: 200, description: 'User Email Updated Successfully' })
  @ApiResponse({ status: 400, description: 'Bad Request' })
  @ApiResponse({ status: 401, description: 'Not Authorized' })
  @ApiResponse({ status: 403, description: 'Not Authorized as Customer' })
  @ApiResponse({ status: 404, description: 'Verification token expired' })
  @ApiResponse({ status: 500, description: 'Internal Server Error' })
  @UseRole(Role.CUSTOMER)
  @Post('me/verifyUserEmail')
  public async verifyUserEmail(
    @Req() req: Request,
    @Body() verifData: TokenVerifDTO,
    @Res() res: Response,
  ): Promise<Response | void> {
    const user = req.user as IUserPayload;
    const newEmail = await this.redisService.get(verifData.token);

    if (!newEmail) {
      return res.status(404).send('Verification token expired or invalid');
    }

    const updatedUser = await this.userService.update(user.id, {
      email: newEmail,
    });

    const { refresh } = await this.authService.setJWTCookie(updatedUser, res);

    await this.userService.update(user.id, {
      refreshToken: refresh,
    });

    await this.redisService.delete(verifData.token);

    res.status(200).send('Email verified successfully');
  }
}
