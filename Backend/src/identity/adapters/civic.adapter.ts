export class CivicAdapter {
  async importCredential(civicPayload: any) {
    // TODO: map Civic credential to VC
    return civicPayload;
  }

  async exportCredential(vc: any) {
    // TODO: map VC to Civic's API format
    return vc;
  }
}
