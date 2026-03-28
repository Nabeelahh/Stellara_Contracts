import http from 'k6/http';
import { check } from 'k6';

const BASELINE = JSON.parse(open('./baseline.json'));
const TARGET_URL = __ENV.TARGET_URL || 'http://localhost:3000';

if (!TARGET_URL) {
  throw new Error('TARGET_URL environment variable is required to run the performance test');
}

export const options = {
  vus: 50,
  duration: '1m',
  thresholds: {
    http_req_duration: [`p(95)<${Math.round(BASELINE.p95 * 1.1)}`],
    http_reqs: [`rate>${Math.round(BASELINE.rps * 0.9)}`],
  },
};

export default function () {
  const response = http.get(`${TARGET_URL}/health`);
  check(response, {
    'health endpoint returns 200': (r) => r.status === 200,
  });
}
