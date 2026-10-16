import {
  createCipheriv,
  createDecipheriv,
  createECDH,
  createHash,
  createHmac,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  hkdfSync,
  randomBytes,
  sign,
  verify,
} from "node:crypto";

const AES_ALGORITHM = "aes-256-gcm" as const;
const AES_KEY_BYTES = 32;
const AES_IV_BYTES = 12;
const AES_TAG_BYTES = 16;
const P384_CURVE = "prime384v1" as const;
const HKDF_HASH = "sha384" as const;
const MAX_SIGNATURE_CLOCK_SKEW_SECONDS = 300;

export const CRYPTO_SUITE_VERSION = "crypto-suite-v1";

export type EncryptedEnvelope = {
  version: typeof CRYPTO_SUITE_VERSION;
  algorithm: typeof AES_ALGORITHM;
  keyId: string;
  iv: string;
  ciphertext: string;
  authTag: string;
  aad?: string;
};

const b64 = (value: Uint8Array) => Buffer.from(value).toString("base64url");
const fromB64 = (value: string) => Buffer.from(value, "base64url");

export function generateAes256Key(): Buffer { return randomBytes(AES_KEY_BYTES); }

function assertAes256Key(key: Uint8Array): Buffer {
  const normalized = Buffer.from(key);
  if (normalized.length !== AES_KEY_BYTES) throw new Error("AES_256_KEY_MUST_BE_32_BYTES");
  return normalized;
}

export function encryptBytes(input: Uint8Array, key: Uint8Array, keyId = "primary", aad?: string): EncryptedEnvelope {
  const iv = randomBytes(AES_IV_BYTES);
  const cipher = createCipheriv(AES_ALGORITHM, assertAes256Key(key), iv, { authTagLength: AES_TAG_BYTES });
  if (aad !== undefined) cipher.setAAD(Buffer.from(aad, "utf8"), { plaintextLength: input.byteLength });
  const ciphertext = Buffer.concat([cipher.update(Buffer.from(input)), cipher.final()]);
  return {
    version: CRYPTO_SUITE_VERSION,
    algorithm: AES_ALGORITHM,
    keyId,
    iv: b64(iv),
    ciphertext: b64(ciphertext),
    authTag: b64(cipher.getAuthTag()),
    ...(aad !== undefined ? { aad: b64(Buffer.from(aad, "utf8")) } : {}),
  };
}

export function decryptBytes(envelope: EncryptedEnvelope, key: Uint8Array, aadOverride?: string): Buffer {
  if (envelope.version !== CRYPTO_SUITE_VERSION || envelope.algorithm !== AES_ALGORITHM) throw new Error("UNSUPPORTED_CRYPTO_ENVELOPE");
  const iv = fromB64(envelope.iv);
  if (iv.length !== AES_IV_BYTES) throw new Error("INVALID_AES_IV");
  const decipher = createDecipheriv(AES_ALGORITHM, assertAes256Key(key), iv, { authTagLength: AES_TAG_BYTES });
  const aad = aadOverride ?? (envelope.aad ? fromB64(envelope.aad).toString("utf8") : undefined);
  if (aad !== undefined) decipher.setAAD(Buffer.from(aad, "utf8"));
  decipher.setAuthTag(fromB64(envelope.authTag));
  return Buffer.concat([decipher.update(fromB64(envelope.ciphertext)), decipher.final()]);
}

export function encryptString(value: string, key: Uint8Array, keyId = "primary", aad?: string): EncryptedEnvelope {
  return encryptBytes(Buffer.from(value, "utf8"), key, keyId, aad);
}

export function decryptString(envelope: EncryptedEnvelope, key: Uint8Array, aadOverride?: string): string {
  return decryptBytes(envelope, key, aadOverride).toString("utf8");
}

export type P384KeyPair = { privateKey: Buffer; publicKey: Buffer };

/** Raw SEC1 P-384 keys. Private keys must remain server-side; public keys may be shared. */
export function generateP384KeyPair(): P384KeyPair {
  const ecdh = createECDH(P384_CURVE);
  ecdh.generateKeys();
  return { privateKey: ecdh.getPrivateKey(), publicKey: ecdh.getPublicKey() };
}

export function deriveP384SharedKey(privateKey: Uint8Array, peerPublicKey: Uint8Array, salt?: Uint8Array, info = "gainiren-security-p384-v1"): Buffer {
  const ecdh = createECDH(P384_CURVE);
  ecdh.setPrivateKey(Buffer.from(privateKey));
  const shared = ecdh.computeSecret(Buffer.from(peerPublicKey));
  return Buffer.from(hkdfSync(HKDF_HASH, shared, salt ?? Buffer.alloc(0), Buffer.from(info, "utf8"), AES_KEY_BYTES));
}

export type Ecdsa384KeyPair = { privateKeyPem: string; publicKeyPem: string };

export function generateEcdsa384KeyPair(): Ecdsa384KeyPair {
  const { privateKey, publicKey } = generateKeyPairSync("ec", {
    namedCurve: P384_CURVE,
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" },
  });
  return { privateKeyPem: privateKey, publicKeyPem: publicKey };
}

export function signEcdsa384(payload: Uint8Array | string, privateKeyPem: string): string {
  const data = typeof payload === "string" ? Buffer.from(payload, "utf8") : Buffer.from(payload);
  return b64(sign("sha384", data, createPrivateKey(privateKeyPem)));
}

export function verifyEcdsa384(payload: Uint8Array | string, signature: string, publicKeyPem: string): boolean {
  const data = typeof payload === "string" ? Buffer.from(payload, "utf8") : Buffer.from(payload);
  return verify("sha384", data, createPublicKey(publicKeyPem), fromB64(signature));
}

export type SignedEnvelope = {
  version: typeof CRYPTO_SUITE_VERSION;
  algorithm: "ECDSA-P384-SHA384";
  timestamp: number;
  nonce: string;
  payloadHash: string;
  signature: string;
};

/** Signs a fresh timestamp + nonce + SHA-384 payload digest. Persist the nonce server-side to prevent replay. */
export function createSignedEnvelope(payload: Uint8Array | string, privateKeyPem: string, now = Date.now()): SignedEnvelope {
  const nonce = b64(randomBytes(24));
  const payloadHash = sha384(payload);
  const canonical = `${CRYPTO_SUITE_VERSION}|ECDSA-P384-SHA384|${now}|${nonce}|${payloadHash}`;
  return {
    version: CRYPTO_SUITE_VERSION,
    algorithm: "ECDSA-P384-SHA384",
    timestamp: now,
    nonce,
    payloadHash,
    signature: signEcdsa384(canonical, privateKeyPem),
  };
}

export function verifySignedEnvelope(payload: Uint8Array | string, envelope: SignedEnvelope, publicKeyPem: string, now = Date.now(), maxClockSkewSeconds = MAX_SIGNATURE_CLOCK_SKEW_SECONDS): boolean {
  if (envelope.version !== CRYPTO_SUITE_VERSION || envelope.algorithm !== "ECDSA-P384-SHA384") return false;
  if (!Number.isSafeInteger(envelope.timestamp) || Math.abs(now - envelope.timestamp) > maxClockSkewSeconds * 1000) return false;
  if (!/^[A-Za-z0-9_-]{32}$/.test(envelope.nonce)) return false;
  if (envelope.payloadHash !== sha384(payload)) return false;
  const canonical = `${envelope.version}|${envelope.algorithm}|${envelope.timestamp}|${envelope.nonce}|${envelope.payloadHash}`;
  return verifyEcdsa384(canonical, envelope.signature, publicKeyPem);
}

export function sha384(value: Uint8Array | string): string {
  return createHash("sha384").update(typeof value === "string" ? Buffer.from(value, "utf8") : value).digest("hex");
}

export function sha512(value: Uint8Array | string): string {
  return createHash("sha512").update(typeof value === "string" ? Buffer.from(value, "utf8") : value).digest("hex");
}

export function hmacSha384(value: Uint8Array | string, secret: Uint8Array | string): string {
  return createHmac("sha384", secret).update(typeof value === "string" ? Buffer.from(value, "utf8") : value).digest("hex");
}
