export function createVerifiableCredential(
  issuer: string,
  subject: string,
  credentialSubject: any,
  issuanceDate?: string,
  expirationDate?: string,
) {
  const now = issuanceDate ?? new Date().toISOString();
  const vc: any = {
    '@context': ['https://www.w3.org/2018/credentials/v1'],
    id: `urn:uuid:${Math.random().toString(36).slice(2, 10)}`,
    type: ['VerifiableCredential', 'KYC-Credential'],
    issuer,
    issuanceDate: now,
    credentialSubject: {
      id: subject,
      ...credentialSubject,
    },
  };

  if (expirationDate) vc.expirationDate = expirationDate;

  return vc;
}
