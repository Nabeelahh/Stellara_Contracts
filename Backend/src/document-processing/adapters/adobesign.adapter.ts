import axios from 'axios';

export class AdobeSignAdapter {
  static baseUrl() {
    return process.env.ADOBE_BASE_URL || 'https://api.echosign.com/api/rest/v6';
  }

  static authHeader() {
    const token = process.env.ADOBE_API_TOKEN || '';
    return { Authorization: `Bearer ${token}` };
  }

  static async fetchSignedAgreement(agreementId: string) {
    const url = `${this.baseUrl()}/agreements/${agreementId}/combinedDocument`;
    const resp = await axios.get(url, { headers: { ...this.authHeader() }, responseType: 'arraybuffer' });
    return Buffer.from(resp.data);
  }

  static validateWebhook(headers: any, body: string): boolean {
    try {
      const sig = headers['x-adobesignature'] || headers['X-Adobesignature'] || headers['x-adobe-signature'];
      if (!sig) return true;
      const secret = process.env.ADOBE_WEBHOOK_SECRET;
      if (!secret) return true;
      const crypto = require('crypto');
      const hmac = crypto.createHmac('sha256', secret).update(body).digest('base64');
      return hmac === sig || Buffer.from(hmac).toString('base64') === sig;
    } catch (e) {
      return false;
    }
  }
}
