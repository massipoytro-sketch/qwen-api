import {
  createCipheriv,
  createDecipheriv,
  createECDH,
  createHash,
  createHmac,
  createSign,
  randomBytes,
  timingSafeEqual,
  verify as verifySignature,
  createVerify,
} from "node:crypto";

const AES_ALGORITHM = "aes-256-gcm" as const;
const CURVE = "secp384r1" as const;
const MAX_AAD_BYTES = 4096;
const MAX_PLAINTEXT_BYTES = 1024 * 1024;

function boundedBuffer(value: Buffer | Uint8Array | string, max: number, name: string): Buffer {
  const buffer = Buffer.isBuffer(value) ? value : Buffer.from(value);
  if (buffer.length > max) throw new Error(`${name}_TOO_LARGE`);
  return buffer;
}

export function sha384Hex(value: Buffer | Uint8Array | string): string {
  return createHash("sha384").update(boundedBuffer(value, MAX_PLAINTEXT_BYTES, "HASH_INPUT")).digest("hex");
}

export function sha512Hex(value: Buffer | Uint8Array | string): string {
  return createHash("sha512").update(boundedBuffer(value, MAX_PLAINTEXT_BYTES, "HASH_INPUT")).digest("hex");
}

export function hmacSha256Hex(secret: Buffer | string, canonicalMessage: string): string {
  return createHmac("sha256", secret).update(boundedBuffer(canonicalMessage, 16 * 1024, "SIGNING_MESSAGE")).digest("hex");
}

export function constantTimeHexEqual(leftHex: string, rightHex: string): boolean {
  if (!/^[a-f0-9]{64}$/i.test(leftHex) || !/^[a-f0-9]{64}$/i.test(rightHex)) return false;
  const left = Buffer.from(leftHex, "hex");
  const right = Buffer.from(rightHex, "hex");
  return timingSafeEqual(left, right);
}

export type SignedRequest = {
  keyId: string;
  timestamp: number;
  nonce: string;
  bodyHash: string;
  signature: string;
};

export function canonicalSignedRequest(input: {
  method: string;
  path: string;
  timestamp: number;
  nonce: string;
  bodyHash: string;
  keyId: string;
}): string {
  return [input.method.toUpperCase(), input.path, String(input.timestamp), input.nonce, input.bodyHash, input.keyId].join("\n");
}

export function verifySignedRequest(input: {
  request: SignedRequest;
  method: string;
  path: string;
  body: Buffer | string;
  secret: Buffer | string;
  nowMs?: number;
  maxSkewMs?: number;
}): boolean {
  const now = input.nowMs ?? Date.now();
  const maxSkew = input.maxSkewMs ?? 5 * 60_000;
  if (!Number.isSafeInteger(input.request.timestamp) || Math.abs(now - input.request.timestamp) > maxSkew) return false;
  if (!/^[a-zA-Z0-9._:-]{8,128}$/.test(input.request.nonce)) return false;
  const bodyHash = sha384Hex(input.body);
  if (!/^[a-f0-9]{96}$/i.test(input.request.bodyHash) || bodyHash !== input.request.bodyHash.toLowerCase()) return false;
  const canonical = canonicalSignedRequest({ ...input.request, method: input.method, path: input.path });
  const expected = hmacSha256Hex(input.secret, canonical);
  return constantTimeHexEqual(expected, input.request.signature);
}

export function encryptAes256Gcm(plaintext: Buffer | string, key: Buffer, aad?: Buffer | string) {
  if (key.length !== 32) throw new Error("AES256_KEY_REQUIRED");
  const data = boundedBuffer(plaintext, MAX_PLAINTEXT_BYTES, "PLAINTEXT");
  const iv = randomBytes(12);
  const cipher = createCipheriv(AES_ALGORITHM, key, iv);
  if (aad !== undefined) cipher.setAAD(boundedBuffer(aad, MAX_AAD_BYTES, "AAD"));
  const ciphertext = Buffer.concat([cipher.update(data), cipher.final()]);
  return {
    algorithm: "AES-256-GCM" as const,
    iv: iv.toString("base64url"),
    ciphertext: ciphertext.toString("base64url"),
    tag: cipher.getAuthTag().toString("base64url"),
  };
}

export function decryptAes256Gcm(input: {
  key: Buffer;
  iv: string;
  ciphertext: string;
  tag: string;
  aad?: Buffer | string;
}): Buffer {
  if (input.key.length !== 32) throw new Error("AES256_KEY_REQUIRED");
  const decipher = createDecipheriv(AES_ALGORITHM, input.key, Buffer.from(input.iv, "base64url"));
  if (input.aad !== undefined) decipher.setAAD(boundedBuffer(input.aad, MAX_AAD_BYTES, "AAD"));
  decipher.setAuthTag(Buffer.from(input.tag, "base64url"));
  return Buffer.concat([decipher.update(Buffer.from(input.ciphertext, "base64url")), decipher.final()]);
}

export function generateP384KeyPair() {
  const ecdh = createECDH(CURVE);
  ecdh.generateKeys();
  return {
    curve: "P-384" as const,
    publicKey: ecdh.getPublicKey("base64url"),
    privateKey: ecdh.getPrivateKey("base64url"),
  };
}

export function deriveP384SharedSecret(privateKeyBase64Url: string, peerPublicKeyBase64Url: string): Buffer {
  const ecdh = createECDH(CURVE);
  ecdh.setPrivateKey(Buffer.from(privateKeyBase64Url, "base64url"));
  return ecdh.computeSecret(Buffer.from(peerPublicKeyBase64Url, "base64url"));
}

export function signP384Sha384(privateKeyPem: string, message: Buffer | string): string {
  const signer = createSign("SHA384");
  signer.update(boundedBuffer(message, 16 * 1024, "SIGNING_MESSAGE"));
  signer.end();
  return signer.sign(privateKeyPem, "base64url");
}

export function verifyP384Sha384(publicKeyPem: string, message: Buffer | string, signatureBase64Url: string): boolean {
  const verifier = createVerify("SHA384");
  verifier.update(boundedBuffer(message, 16 * 1024, "VERIFY_MESSAGE"));
  verifier.end();
  return verifier.verify(publicKeyPem, Buffer.from(signatureBase64Url, "base64url"));
}

export function createRotatingRequestNonce(): string {
  return randomBytes(24).toString("base64url");
}
