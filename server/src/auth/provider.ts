export type UserId = string;

export interface AuthContext {
  userId: UserId;
  providerId: string;
  credentialId: string;
  serverNonce: string;
  expiresAt: number;
}

export interface AuthProvider {
  readonly id: string;
  beginRegister(userHandle?: UserId): Promise<{ serverNonce: string; options: unknown }>;
  finishRegister(serverNonce: string, response: unknown): Promise<{ userId: UserId; credentialId: string }>;
  beginAssert(userHandle?: UserId): Promise<{ serverNonce: string; options: unknown }>;
  verifyAssert(serverNonce: string, response: unknown): Promise<{ userId: UserId; credentialId: string }>;
}

export interface UserRecord {
  user_id: string;
  created_at: number;
  credentials: StoredCredential[];
}

export interface StoredCredential {
  id: string;
  public_key: string;
  counter: number;
  transports?: string[];
  created_at: number;
  provider_id: string;
}
