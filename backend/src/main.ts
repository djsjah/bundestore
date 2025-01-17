import { NestFactory } from '@nestjs/core';
import { BadRequestException, ValidationPipe } from '@nestjs/common';
import { CorsOptions } from '@nestjs/common/interfaces/external/cors-options.interface';
import { NestExpressApplication } from '@nestjs/platform-express';
import { ConfigService } from '@nestjs/config';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import CookieSerializer from 'cookie-parser';

import { AppModule } from './domain/app';

const bootstrap = async () => {
  const app = await NestFactory.create<NestExpressApplication>(AppModule);
  const configService = app.get(ConfigService);
  const port = configService.get('port');

  const corsOptions: CorsOptions = {
    origin: true,
    methods: 'GET, POST, PUT, DELETE, PATCH',
    allowedHeaders: 'Content-Type, Authorization, X-Requested-With',
    credentials: true,
  };

  app.enableCors(corsOptions);
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
      exceptionFactory: errors => {
        return new BadRequestException({
          statusCode: 400,
          message: 'Validation failed',
          errors: errors.map(error => ({
            field: error.property,
            constraints: error.constraints,
          })),
        });
      },
    }),
  );

  configService.set('uri', `${configService.get('protocol')}://${configService.get('host')}:${port}`);

  const config = new DocumentBuilder()
    .setTitle('Football Store API')
    .setDescription('ITMO Modern Informatics Football Store API description')
    .setVersion('1.0')
    .addServer(configService.get('uri') as string, `${configService.get('nodeENV')} environment`)
    .build();

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api', app, document);

  app.use(CookieSerializer());

  await app.listen(port);
};

bootstrap();
