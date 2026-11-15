/**
 * Certificate authority for TLS interception.
 *
 * The scanner observes traffic at the wire level through a MITM proxy. To do
 * that it must present a valid certificate for any host the browser visits.
 * A throwaway CA is generated per scan (or cached on disk for real-browser
 * installs) and leaf certificates are signed on demand for each SNI host.
 *
 * Nothing here is a security boundary: the key material is local to the scan
 * and must never be trusted beyond it.
 */
import forge from 'node-forge';
import fs from 'node:fs';
import path from 'node:path';

const KEY_BITS = 2048;

export interface CaMaterial {
  caCertPem: string;
  caKeyPem: string;
}

export interface LeafCertificate {
  keyPem: string;
  certPem: string;
}

const cache = new Map<string, LeafCertificate>();

function rsaKeyPair(): forge.pki.rsa.KeyPair {
  return forge.pki.rsa.generateKeyPair(KEY_BITS);
}

export function generateCa(): CaMaterial {
  const keys = rsaKeyPair();
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = '01';
  cert.validity.notBefore = new Date(Date.now() - 60_000);
  cert.validity.notAfter = new Date(Date.now() + 10 * 365 * 24 * 3600 * 1000);
  const attrs = [
    { name: 'commonName', value: 'Pre-Consent Privacy Scanner CA' },
    { name: 'organizationName', value: 'Pre-Consent Privacy Scanner' },
  ];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.setExtensions([
    { name: 'basicConstraints', cA: true, critical: true },
    { name: 'keyUsage', keyCertSign: true, digitalSignature: true, critical: true },
    { name: 'subjectKeyIdentifier' },
  ]);
  cert.sign(keys.privateKey, forge.md.sha256.create());
  return {
    caCertPem: forge.pki.certificateToPem(cert),
    caKeyPem: forge.pki.privateKeyToPem(keys.privateKey),
  };
}

export function writeCa(material: CaMaterial, dir: string): { certPath: string; keyPath: string } {
  fs.mkdirSync(dir, { recursive: true });
  const certPath = path.join(dir, 'scanner-ca.pem');
  const keyPath = path.join(dir, 'scanner-ca-key.pem');
  fs.writeFileSync(certPath, material.caCertPem, { mode: 0o644 });
  fs.writeFileSync(keyPath, material.caKeyPem, { mode: 0o600 });
  return { certPath, keyPath };
}

function isIp(host: string): boolean {
  return /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host) || host.includes(':');
}

/**
 * A single leaf key is reused for every host: signing a certificate is fast,
 * generating an RSA key per host is not, and each certificate still carries its
 * own SAN for the host the browser asked for.
 */
let sharedLeafKey: forge.pki.rsa.KeyPair | null = null;

export function leafFor(ca: CaMaterial, host: string): LeafCertificate {
  const cached = cache.get(host);
  if (cached) return cached;

  const caCert = forge.pki.certificateFromPem(ca.caCertPem);
  const caKey = forge.pki.privateKeyFromPem(ca.caKeyPem);
  sharedLeafKey ??= rsaKeyPair();

  const cert = forge.pki.createCertificate();
  cert.publicKey = sharedLeafKey.publicKey;
  cert.serialNumber = forge.util.bytesToHex(forge.random.getBytesSync(8));
  cert.validity.notBefore = new Date(Date.now() - 60_000);
  cert.validity.notAfter = new Date(Date.now() + 365 * 24 * 3600 * 1000);
  cert.setSubject([{ name: 'commonName', value: host }]);
  cert.setIssuer(caCert.subject.attributes);

  if (isIp(host)) {
    cert.setExtensions([
      { name: 'basicConstraints', cA: false },
      { name: 'keyUsage', digitalSignature: true, keyEncipherment: true },
      { name: 'extKeyUsage', serverAuth: true },
      { name: 'subjectAltName', altNames: [{ type: 7, ip: host }] },
    ]);
  } else {
    cert.setExtensions([
      { name: 'basicConstraints', cA: false },
      { name: 'keyUsage', digitalSignature: true, keyEncipherment: true },
      { name: 'extKeyUsage', serverAuth: true },
      { name: 'subjectAltName', altNames: [{ type: 2, value: host }] },
    ]);
  }
  cert.sign(caKey, forge.md.sha256.create());

  const leaf: LeafCertificate = {
    keyPem: forge.pki.privateKeyToPem(sharedLeafKey.privateKey),
    certPem: forge.pki.certificateToPem(cert),
  };
  cache.set(host, leaf);
  return leaf;
}

/** Exposed for tests: pre-warm leaf certificates so the first request is not delayed. */
export function resetLeafCache(): void {
  cache.clear();
  sharedLeafKey = null;
}
