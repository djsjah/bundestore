import { Module } from '@nestjs/common';

import { CryptoProvider } from './crypto.provider';

@Module({
  providers: [CryptoProvider],
  exports: [CryptoProvider],
})
export class CryptoModule {}
