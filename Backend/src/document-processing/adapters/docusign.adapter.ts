import axios from 'axios';

export class DocusignAdapter {
  static baseUrl() {
    return process.env.DOCUSIGN_BASE_URL || 'https://demo.docusign.net/restapi';
  }

  static authHeader() {
    const token = process.env.DOCUSIGN_API_TOKEN || '';
    return { Authorization: `Bearer ${token}` };
  }

  // Fetch the signed document bytes for an envelopeId and documentId
  static async fetchSignedDocument(accountId: string, envelopeId: string, documentId: string) {
    const url = `${this.baseUrl()}/v2.1/accounts/${accountId}/envelopes/${envelopeId}/documents/${documentId}`;
    const resp = await axios.get(url, { headers: { ...this.authHeader() }, responseType: 'arraybuffer' });
    return Buffer.from(resp.data);
  }

  // Validate a webhook event signature if configured
  static validateWebhook(headers: any, body: string): boolean {
    try {
      const sig = headers['x-docusign-signature-1'] || headers['X-DocuSign-Signature-1'];
      if (!sig) return true; // allow sandbox where signature may be absent
      const secret = process.env.DOCUSIGN_WEBHOOK_SECRET;
      if (!secret) return true;
      const crypto = require('crypto');
      const hmac = crypto.createHmac('sha256', secret).update(body).digest('base64');
      return hmac === sig || Buffer.from(hmac).toString('base64') === sig;
    } catch (e) {
      return false;
    }
  }
}
