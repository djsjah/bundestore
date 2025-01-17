import { Module, ValidationPipe } from '@nestjs/common';
import { APP_FILTER, APP_PIPE } from '@nestjs/core';
import { ConfigModule } from '@nestjs/config';

import { NodeModule } from '@/utils';

import { AuthModule } from '../auth';
import { AdminModule, ModeratorModule } from '../user';
import { CartModule } from '../cart';
import { OrderItemModule } from '../order-item';
import { OrderModule } from '../order';
import { ProductModule } from '../product';
import { ClothingModule } from '../product/entity/clothing/clothing.module';
import { FootwearModule } from '../product/entity/footwear/footwear.module';
import { AccessoryModule } from '../product/entity/accessory/accessory.module';

import appConfig from './app.config';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AppAllExceptionsFilter } from './filters';

@Module({
  imports: [
    ConfigModule.forRoot({
      load: [appConfig],
      envFilePath: ['.env', `.env.${process.env.NODE_ENV}`],
    }),
    NodeModule,
    AuthModule,
    AdminModule,
    ModeratorModule,
    CartModule,
    OrderItemModule,
    OrderModule,
    ClothingModule,
    FootwearModule,
    AccessoryModule,
    ProductModule,
  ],
  controllers: [AppController],
  providers: [
    AppService,
    {
      provide: APP_PIPE,
      useClass: ValidationPipe,
    },
    {
      provide: APP_FILTER,
      useClass: AppAllExceptionsFilter,
    },
  ],
})
export class AppModule {}
