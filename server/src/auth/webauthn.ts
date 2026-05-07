import { randomBytes, createHash } from "node:crypto";
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";
import type {
  RegistrationResponseJSON,
  AuthenticationResponseJSON,
} from "@simplewebauthn/server";
import type { AuthProvider, UserId, UserRecord } from "./provider.js";
import type { StorageClient } from "../storage/client.js";
import { credIndexKey, userKey } from "../storage/keys.js";
import { SessionStore, bindChallenge } from "./sessions.js";
import { log } from "../log.js";

const PRF_SALT = createHash("sha256").update("enclave-kv-v1").digest();

export interface WebAuthnRp {
  id: string;
  name: string;
  origin: string;
}

export interface PendingChallenge {
  serverNonce: string;
  challengeB64Url: string;
  userHandleB64Url?: string;
}

export class WebAuthnProvider implements AuthProvider {
  readonly id = "webauthn";

  // Maps challenge -> pending data (keyed by serverNonce since challenge is derived from it).
  private readonly pendingRegistration = new Map<string, PendingChallenge>();
  private readonly pendingAssertion = new Map<string, PendingChallenge>();

  constructor(
    private readonly rp: WebAuthnRp,
    private readonly storage: StorageClient,
    private readonly sessions: SessionStore,
  ) {}

  async beginRegister(userHandle?: UserId): Promise<{ serverNonce: string; options: unknown }> {
    const session = this.sessions.begin();
    const userId = userHandle ?? randomBytes(16).toString("base64");
    const userIdBytes = Buffer.from(userId, "base64");
    const challenge = bindChallenge("register", session.nonceB64);
    const challengeBuf = Buffer.from(challenge, "base64url");

    const existing = userHandle ? await this.loadUser(userHandle) : null;
    const excludeCredentials = (existing?.credentials ?? []).map((c) => ({
      id: c.id,
      transports: (c.transports ?? []) as ("usb" | "ble" | "nfc" | "internal" | "hybrid")[],
    }));

    const options = await generateRegistrationOptions({
      rpName: this.rp.name,
      rpID: this.rp.id,
      userID: userIdBytes,
      userName: shortName(userId),
      userDisplayName: shortName(userId),
      timeout: 60_000,
      attestationType: "none",
      excludeCredentials,
      authenticatorSelection: {
        residentKey: "required",
        userVerification: "required",
      },
      supportedAlgorithmIDs: [-7, -257],
      extensions: {
        // PRF extension — registration only registers it; eval happens on assertion.
        // @ts-expect-error simplewebauthn types don't formally include prf yet
        prf: {},
      },
      challenge: new Uint8Array(challengeBuf),
    });

    this.pendingRegistration.set(session.nonceB64, {
      serverNonce: session.nonceB64,
      challengeB64Url: options.challenge,
      userHandleB64Url: Buffer.from(userIdBytes).toString("base64url"),
    });
    return { serverNonce: session.nonceB64, options };
  }

  async finishRegister(
    serverNonceB64: string,
    response: unknown,
  ): Promise<{ userId: UserId; credentialId: string }> {
    if (!this.sessions.consume(serverNonceB64)) throw new WebAuthnError("nonce_invalid_or_used");
    const pending = this.pendingRegistration.get(serverNonceB64);
    this.pendingRegistration.delete(serverNonceB64);
    if (!pending) throw new WebAuthnError("no_pending_registration");

    let verification;
    try {
      verification = await verifyRegistrationResponse({
        response: response as RegistrationResponseJSON,
        expectedChallenge: pending.challengeB64Url,
        expectedOrigin: this.rp.origin,
        expectedRPID: this.rp.id,
        requireUserVerification: true,
      });
    } catch (err) {
      log.warn("webauthn register verify failed", { err: String(err) });
      throw new WebAuthnError("register_verify_failed");
    }
    if (!verification.verified || !verification.registrationInfo) {
      throw new WebAuthnError("register_not_verified");
    }

    const cred = verification.registrationInfo.credential;
    const userIdB64 = Buffer.from(pending.userHandleB64Url ?? "", "base64url").toString("base64");

    const existing = await this.loadUser(userIdB64);
    if (existing && existing.credentials.some((c) => c.id === cred.id)) {
      throw new WebAuthnError("credential_already_registered");
    }

    const transports = (response as RegistrationResponseJSON).response.transports ?? [];

    const record: UserRecord = existing ?? {
      user_id: userIdB64,
      created_at: Date.now(),
      credentials: [],
    };
    record.credentials.push({
      id: cred.id,
      public_key: Buffer.from(cred.publicKey).toString("base64"),
      counter: cred.counter,
      transports,
      created_at: Date.now(),
      provider_id: this.id,
    });

    await this.storage.put(userKey(userIdB64), Buffer.from(JSON.stringify(record), "utf8"));
    await this.storage.put(
      credIndexKey(cred.id),
      Buffer.from(JSON.stringify({ user_id: userIdB64 }), "utf8"),
    );

    return { userId: userIdB64, credentialId: cred.id };
  }

  async beginAssert(userHandle?: UserId): Promise<{ serverNonce: string; options: unknown }> {
    const session = this.sessions.begin();
    const challenge = bindChallenge("assert", session.nonceB64);
    const challengeBuf = Buffer.from(challenge, "base64url");

    let allowCredentials: { id: string; transports?: string[] }[] | undefined;
    if (userHandle) {
      const user = await this.loadUser(userHandle);
      allowCredentials = (user?.credentials ?? []).map((c) => {
        const item: { id: string; transports?: string[] } = { id: c.id };
        if (c.transports) item.transports = c.transports;
        return item;
      });
    }

    const options = await generateAuthenticationOptions({
      rpID: this.rp.id,
      timeout: 60_000,
      userVerification: "required",
      allowCredentials: allowCredentials as never,
      extensions: {
        // Just signal that PRF should be enabled on the assertion. The PRF
        // salt is a fixed app constant (SHA256("enclave-kv-v1")) known to
        // both sides, so the client injects `eval.first` itself before
        // calling navigator.credentials.get(). Sending it on the wire would
        // double-encode (Uint8Array doesn't JSON-serialise as a buffer; v13's
        // server SDK leaves extensions untouched at JSON.stringify time).
        // @ts-expect-error prf extension not in types
        prf: {},
      },
      challenge: new Uint8Array(challengeBuf),
    });

    this.pendingAssertion.set(session.nonceB64, {
      serverNonce: session.nonceB64,
      challengeB64Url: options.challenge,
    });
    return { serverNonce: session.nonceB64, options };
  }

  async verifyAssert(
    serverNonceB64: string,
    response: unknown,
  ): Promise<{ userId: UserId; credentialId: string }> {
    if (!this.sessions.consume(serverNonceB64)) throw new WebAuthnError("nonce_invalid_or_used");
    const pending = this.pendingAssertion.get(serverNonceB64);
    this.pendingAssertion.delete(serverNonceB64);
    if (!pending) throw new WebAuthnError("no_pending_assertion");

    const credId = (response as AuthenticationResponseJSON).id;
    const userId = await this.lookupUserByCredential(credId);
    if (!userId) throw new WebAuthnError("unknown_credential");
    const user = await this.loadUser(userId);
    if (!user) throw new WebAuthnError("user_missing");
    const stored = user.credentials.find((c) => c.id === credId);
    if (!stored) throw new WebAuthnError("credential_missing");

    let verification;
    try {
      verification = await verifyAuthenticationResponse({
        response: response as AuthenticationResponseJSON,
        expectedChallenge: pending.challengeB64Url,
        expectedOrigin: this.rp.origin,
        expectedRPID: this.rp.id,
        credential: {
          id: stored.id,
          publicKey: new Uint8Array(Buffer.from(stored.public_key, "base64")),
          counter: stored.counter,
          transports: stored.transports as never,
        },
        requireUserVerification: true,
      });
    } catch (err) {
      log.warn("webauthn assert verify failed", { err: String(err) });
      throw new WebAuthnError("assert_verify_failed");
    }
    if (!verification.verified) throw new WebAuthnError("assert_not_verified");

    stored.counter = verification.authenticationInfo.newCounter;
    await this.storage.put(userKey(userId), Buffer.from(JSON.stringify(user), "utf8"));

    return { userId, credentialId: credId };
  }

  async loadUser(userId: UserId): Promise<UserRecord | null> {
    const raw = await this.storage.get(userKey(userId));
    if (!raw) return null;
    return JSON.parse(Buffer.from(raw).toString("utf8")) as UserRecord;
  }

  async lookupUserByCredential(credentialId: string): Promise<UserId | null> {
    const raw = await this.storage.get(credIndexKey(credentialId));
    if (!raw) return null;
    const obj = JSON.parse(Buffer.from(raw).toString("utf8")) as { user_id: string };
    return obj.user_id;
  }
}

export class WebAuthnError extends Error {
  constructor(public readonly reason: string) {
    super(`webauthn: ${reason}`);
    this.name = "WebAuthnError";
  }
}

function shortName(b64: string): string {
  // Stable, non-identifying display string derived from user_id.
  return `kv-${createHash("sha256").update(b64).digest("hex").slice(0, 8)}`;
}
