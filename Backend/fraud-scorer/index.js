const http = require('http');

const PORT = process.env.PORT || 3001;

const disposableDomains = new Set([
  'mailinator.com',
  'dispostable.com',
  '10minutemail.com',
  'tempmail.com',
]);

function score(input) {
  const reasons = [];
  let score = 0;

  try {
    const parts = (input.email || '').split('@');
    const domain = parts.length > 1 ? parts[1].toLowerCase() : '';
    if (disposableDomains.has(domain)) {
      score += 0.6;
      reasons.push('disposable_email_domain');
    }
  } catch (e) {}

  if (input.isNewTenant) {
    score += 0.08;
    reasons.push('new_tenant');
  }

  if (!input.paymentMethodId) {
    score += 0.05;
    reasons.push('no_payment_method');
  }

  score = Math.max(0, Math.min(1, score));

  let action = 'allow';
  if (score >= 0.7) action = 'block';
  else if (score >= 0.35) action = 'challenge';

  return { score, action, reasons };
}

const server = http.createServer(async (req, res) => {
  if (req.method === 'POST' && req.url === '/score') {
    let body = '';
    req.on('data', (chunk) => (body += chunk));
    req.on('end', () => {
      try {
        const input = JSON.parse(body || '{}');
        const out = score(input);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(out));
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'invalid_json' }));
      }
    });
    return;
  }

  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: 'not_found' }));
});

server.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`fraud-scorer listening on http://0.0.0.0:${PORT}`);
});

// Graceful shutdown
process.on('SIGTERM', () => server.close(() => process.exit(0)));
process.on('SIGINT', () => server.close(() => process.exit(0)));
