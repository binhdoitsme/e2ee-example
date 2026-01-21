/**
 * Accepts: Public Key (RSA/ECC) on init (prob. class init)
 * For every submission:
 * 1. Generate transient Symmetric Key (e.g. AES-256)
 * 2. Encrypt payload with this SK
 * 3. Encrypt SK using server's Public Key
 * 4. Return the packaged payload: {"encrypted_data": "...", "encrypted_key": "..."}
 */
export class E2EEHandler {
  constructor(
    private readonly publicKey: CryptoKey,
    private readonly encoder: TextEncoder = new TextEncoder(),
  ) {}

  private generateSymmetricKey() {
    return crypto.subtle.generateKey(
      {
        name: "AES-GCM",
        length: 256,
      },
      true,
      ["encrypt", "decrypt"],
    );
  }

  async encrypt(payload: { [key: string]: unknown }) {
    // generate a transient AES-GCM key and IV to encrypt the payload
    const symmetricKey = await this.generateSymmetricKey();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encoded = this.encoder.encode(JSON.stringify(payload));
    const encryptedPayload = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      symmetricKey,
      encoded,
    );

    // export the symmetric key as raw bytes and encrypt those bytes with the server's RSA public key
    const exportedKey = await crypto.subtle.exportKey("raw", symmetricKey);
    // encrypt the exported symmetric key using the server's RSA public key
    const encryptedKey = await crypto.subtle.encrypt(
      { name: "RSA-OAEP" },
      this.publicKey,
      exportedKey,
    );

    // prepend IV to the encrypted payload so a single field contains both
    const payloadBytes = new Uint8Array(encryptedPayload);
    const combined = new Uint8Array(iv.byteLength + payloadBytes.byteLength);
    combined.set(iv, 0);
    combined.set(payloadBytes, iv.byteLength);

    return {
      encryptedKey: arrayBufferToBase64(encryptedKey),
      // combined contains: [iv (12 bytes) | ciphertext]
      encryptedPayload: arrayBufferToBase64(combined.buffer),
    };
  }
}
export function arrayBufferToBase64(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  const chunkSize = 0x8000;
  let binary = "";
  for (let i = 0; i < bytes.length; i += chunkSize) {
    const slice = bytes.subarray(i, i + chunkSize);
    binary += String.fromCharCode.apply(null, Array.from(slice));
  }
  return btoa(binary);
}
