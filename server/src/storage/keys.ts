export const kvKey = (userId: string, keyId: string): string => `kv/${userId}/${keyId}`;
export const kvUserPrefix = (userId: string): string => `kv/${userId}/`;
export const userKey = (userId: string): string => `users/${userId}`;
export const credIndexKey = (credentialId: string): string => `users_by_credential/${credentialId}`;
