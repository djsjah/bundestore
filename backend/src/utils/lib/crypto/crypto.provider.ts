import { createHash, randomBytes } from 'crypto';

export class CryptoProvider {
  public async hashStringBySHA256(str: string): Promise<string> {
    return new Promise((resolve, reject) => {
      try {
        const hash = createHash('sha256');
        hash.update(str);
        resolve(hash.digest('hex'));
      } catch (err) {
        reject(err);
      }
    });
  }

  public generateSecureVerifToken(length: number = 10): string {
    return randomBytes(length).toString('hex');
  }
}
