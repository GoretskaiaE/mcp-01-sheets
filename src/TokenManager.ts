import crypto from 'crypto';
import { SecretManagerServiceClient } from '@google-cloud/secret-manager';

interface TokenData {
  access_token: string;
  refresh_token?: string;
  expiry_date: number;
  scope: string[];
}

export class TokenManager {
  private secretClient: SecretManagerServiceClient;
  
  constructor() {
    this.secretClient = new SecretManagerServiceClient();
  }
  
  async storeTokens(userId: string, tokens: TokenData): Promise<void> {
    const projectId = process.env.GOOGLE_CLOUD_PROJECT;
    const secretId = `user-tokens-${userId}`;
    const parent = `projects/${projectId}`;
    const secretName = `${parent}/secrets/${secretId}`;
    
    const encryptedTokens = await this.encrypt(JSON.stringify(tokens));
    
    try {
      // Try to create secret if it doesn't exist
      await this.secretClient.createSecret({
        parent,
        secretId,
        secret: {
          replication: {
            automatic: {}
          }
        }
      });
    } catch (error: any) {
      // Secret might already exist, that's ok
      if (!error.message?.includes('already exists')) {
        throw error;
      }
    }
    
    // Add the secret version
    await this.secretClient.addSecretVersion({
      parent: secretName,
      payload: {
        data: Buffer.from(encryptedTokens, 'utf8')
      }
    });
  }
  
  async getTokens(userId: string): Promise<TokenData | null> {
    try {
      const projectId = process.env.GOOGLE_CLOUD_PROJECT;
      const name = `projects/${projectId}/secrets/user-tokens-${userId}/versions/latest`;
      
      const [version] = await this.secretClient.accessSecretVersion({ name });
      
      if (!version.payload?.data) {
        return null;
      }
      
      const encryptedData = version.payload.data.toString();
      const decryptedData = await this.decrypt(encryptedData);
      return JSON.parse(decryptedData);
    } catch (error) {
      console.error('Error getting tokens:', error);
      return null;
    }
  }
  
  private async encrypt(data: string): Promise<string> {
    const algorithm = 'aes-256-gcm';
    const key = Buffer.from(process.env.ENCRYPTION_KEY || '', 'hex');
    const iv = crypto.randomBytes(16);
    
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const authTag = cipher.getAuthTag();
    
    return JSON.stringify({
      encrypted,
      iv: iv.toString('hex'),
      authTag: authTag.toString('hex')
    });
  }
  
  private async decrypt(encryptedData: string): Promise<string> {
    const data = JSON.parse(encryptedData);
    const algorithm = 'aes-256-gcm';
    const key = Buffer.from(process.env.ENCRYPTION_KEY || '', 'hex');
    const iv = Buffer.from(data.iv, 'hex');
    
    const decipher = crypto.createDecipheriv(algorithm, key, iv);
    decipher.setAuthTag(Buffer.from(data.authTag, 'hex'));
    
    let decrypted = decipher.update(data.encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  }
}