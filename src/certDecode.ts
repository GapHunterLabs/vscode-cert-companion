import { X509Certificate } from 'node:crypto';

/**
 * Pure certificate-decoding logic -- zero dependency on the `vscode`
 * module, and zero third-party npm dependency: Node's built-in
 * `node:crypto` X509Certificate class (available since Node 15.6) reads
 * PEM directly. Same "no bundled crypto library" philosophy as the
 * IntelliJ-family Cert Companion (JDK-only there, Node-only here).
 *
 * v0.1 scope, honestly noted: PEM/CRT/CER (text, PEM-encoded) and DER
 * (binary) X.509 certificates only. Keystores (.jks/.p12/.pfx) are a
 * real gap versus the IntelliJ version -- Node has no built-in
 * high-level PKCS12 reader, and JKS is a Java-proprietary format with
 * no Node support at all. Not attempted here, not silently skipped:
 * the command explicitly errors out with that explanation for those
 * extensions rather than pretending to support them.
 */

export interface CertSummary {
  subject: string;
  issuer: string;
  serialNumber: string;
  validFrom: Date;
  validTo: Date;
  fingerprint256: string;
  isExpired: boolean;
  expiresWithin30Days: boolean;
}

export class CertDecodeError extends Error {}

const PEM_CERT_BLOCK = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g;

/** Splits a PEM bundle (possibly containing multiple certificates,
 * concatenated -- the "ugly bundle rendering" case the IntelliJ version
 * fixes by giving each certificate its own card) into individual PEM
 * blocks. Non-certificate PEM content (private keys, etc.) is ignored. */
export function splitPemBundle(text: string): string[] {
  const matches = text.match(PEM_CERT_BLOCK);
  return matches ?? [];
}

function summarize(cert: X509Certificate): CertSummary {
  const validTo = new Date(cert.validTo);
  const now = Date.now();
  const thirtyDaysMs = 30 * 24 * 60 * 60 * 1000;
  return {
    subject: cert.subject.replace(/\n/g, ', '),
    issuer: cert.issuer.replace(/\n/g, ', '),
    serialNumber: cert.serialNumber,
    validFrom: new Date(cert.validFrom),
    validTo,
    fingerprint256: cert.fingerprint256,
    isExpired: validTo.getTime() < now,
    expiresWithin30Days: validTo.getTime() >= now && validTo.getTime() - now <= thirtyDaysMs,
  };
}

/** Parses a PEM string containing one or more certificates. Throws
 * CertDecodeError if the text contains no recognizable certificate. */
export function decodePemBundle(text: string): CertSummary[] {
  const blocks = splitPemBundle(text);
  if (blocks.length === 0) {
    throw new CertDecodeError(
      'No PEM certificate block found (expected -----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----).',
    );
  }
  return blocks.map((block, index) => {
    try {
      return summarize(new X509Certificate(block));
    } catch (error) {
      throw new CertDecodeError(`Certificate #${index + 1} in the bundle failed to parse: ${(error as Error).message}`);
    }
  });
}

/** Parses a single DER-encoded certificate from a binary buffer. */
export function decodeDer(buffer: Buffer): CertSummary {
  try {
    return summarize(new X509Certificate(buffer));
  } catch (error) {
    throw new CertDecodeError(`Not a valid DER certificate: ${(error as Error).message}`);
  }
}

export function formatSummary(cert: CertSummary, index?: number): string {
  const lines: string[] = [];
  const header = index !== undefined ? `Certificate #${index + 1}` : 'Certificate';
  lines.push(`=== ${header} ===`);
  lines.push(`Subject:      ${cert.subject}`);
  lines.push(`Issuer:       ${cert.issuer}`);
  lines.push(`Serial:       ${cert.serialNumber}`);
  lines.push(`Valid from:   ${cert.validFrom.toISOString()}`);
  lines.push(`Valid to:     ${cert.validTo.toISOString()}`);
  lines.push(`SHA-256 fpr:  ${cert.fingerprint256}`);
  if (cert.isExpired) {
    lines.push('Status:       EXPIRED');
  } else if (cert.expiresWithin30Days) {
    lines.push('Status:       expires within 30 days');
  } else {
    lines.push('Status:       valid');
  }
  return lines.join('\n');
}
