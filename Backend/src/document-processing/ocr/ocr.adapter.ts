import { exec } from 'child_process';
import { promisify } from 'util';
const execp = promisify(exec);

export class OcrAdapter {
  // Use Tesseract if available; returns extracted text
  static async performOcr(filePath: string): Promise<string> {
    // try tesseract first
    try {
      const { stdout } = await execp(`tesseract ${JSON.stringify(filePath)} stdout` , { timeout: 60_000 });
      return stdout.toString();
    } catch (e) {
      // fallback: try strings (binary) or cat for text files
      try {
        const { stdout } = await execp(`strings ${JSON.stringify(filePath)}` , { timeout: 30_000 });
        return stdout.toString();
      } catch (e2) {
        // final fallback: read file as utf-8 (may be binary gibberish)
        const fs = require('fs');
        try {
          const t = fs.readFileSync(filePath, 'utf8');
          return t;
        } catch (e3) {
          return '';
        }
      }
    }
  }
}
