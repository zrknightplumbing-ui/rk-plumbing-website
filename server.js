const express = require('express');

const app = express();
const PORT = process.env.PORT || 8080;

const BUSINESS_PHONE = process.env.REQUEST_TO_PHONE || '+16037109777';
const BUSINESS_EMAIL = process.env.REQUEST_TO_EMAIL || 'rkplumbingpro@gmail.com';

app.use(express.json({ limit: '20kb' }));
app.use(express.urlencoded({ extended: true, limit: '20kb' }));

// Very small in-memory rate limit to discourage form spam.
const recentRequests = new Map();
const WINDOW_MS = 60 * 1000;
const MAX_REQUESTS_PER_IP = 5;

function clean(value, max = 2000) {
  return String(value ?? '').trim().slice(0, max);
}

function getClientIp(req) {
  return (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').toString().split(',')[0].trim();
}

function isValidEmail(value) {
  return !value || /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

async function sendSms(body) {
  const { TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_FROM_NUMBER } = process.env;
  if (!TWILIO_ACCOUNT_SID || !TWILIO_AUTH_TOKEN || !TWILIO_FROM_NUMBER) {
    throw new Error('SMS service is not configured.');
  }

  const form = new URLSearchParams({
    To: BUSINESS_PHONE,
    From: TWILIO_FROM_NUMBER,
    Body: body
  });

  const auth = Buffer.from(TWILIO_ACCOUNT_SID + ':' + TWILIO_AUTH_TOKEN).toString('base64');
  const response = await fetch(
    'https://api.twilio.com/2010-04-01/Accounts/' + encodeURIComponent(TWILIO_ACCOUNT_SID) + '/Messages.json',
    {
      method: 'POST',
      headers: {
        Authorization: 'Basic ' + auth,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: form
    }
  );

  if (!response.ok) {
    const detail = await response.text();
    throw new Error('Twilio error: ' + detail.slice(0, 500));
  }
}

async function sendEmail(subject, textBody, htmlBody) {
  const { RESEND_API_KEY, RESEND_FROM_EMAIL } = process.env;
  if (!RESEND_API_KEY || !RESEND_FROM_EMAIL) {
    throw new Error('Email service is not configured.');
  }

  const response = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      Authorization: 'Bearer ' + RESEND_API_KEY,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      from: RESEND_FROM_EMAIL,
      to: [BUSINESS_EMAIL],
      subject,
      text: textBody,
      html: htmlBody
    })
  });

  if (!response.ok) {
    const detail = await response.text();
    throw new Error('Resend error: ' + detail.slice(0, 500));
  }
}

app.post('/api/request-service', async (req, res) => {
  try {
    const ip = getClientIp(req);
    const now = Date.now();
    const entry = recentRequests.get(ip) || [];
    const active = entry.filter(ts => now - ts < WINDOW_MS);
    if (active.length >= MAX_REQUESTS_PER_IP) {
      return res.status(429).json({ ok: false, message: 'Too many requests. Please call RK Plumbing directly at 603-710-9777.' });
    }
    active.push(now);
    recentRequests.set(ip, active);

    // Honeypot field: real visitors never fill this.
    if (clean(req.body.website, 100)) {
      return res.json({ ok: true });
    }

    const name = clean(req.body.name, 100);
    const phone = clean(req.body.phone, 40);
    const email = clean(req.body.email, 160);
    const message = clean(req.body.message, 3000);

    if (!name || !phone || !message) {
      return res.status(400).json({ ok: false, message: 'Please enter your name, phone number, and what plumbing work you need.' });
    }
    if (!isValidEmail(email)) {
      return res.status(400).json({ ok: false, message: 'Please enter a valid email address.' });
    }

    const timestamp = new Date().toLocaleString('en-US', {
      timeZone: 'America/New_York',
      dateStyle: 'medium',
      timeStyle: 'short'
    });

    const sms = [
      'RK Plumbing WEBSITE REQUEST',
      'Name: ' + name,
      'Phone: ' + phone,
      email ? 'Email: ' + email : '',
      'Request: ' + message,
      'Received: ' + timestamp
    ].filter(Boolean).join('\n');

    const subject = 'New RK Plumbing Service Request — ' + name;
    const textBody = [
      'New service request from the RK Plumbing website.',
      '',
      'Name: ' + name,
      'Phone: ' + phone,
      email ? 'Email: ' + email : 'Email: Not provided',
      '',
      'Service needed:',
      message,
      '',
      'Received: ' + timestamp
    ].join('\n');

    const htmlBody = `
      <h2>New RK Plumbing Service Request</h2>
      <p><strong>Name:</strong> ${escapeHtml(name)}</p>
      <p><strong>Phone:</strong> ${escapeHtml(phone)}</p>
      <p><strong>Email:</strong> ${escapeHtml(email || 'Not provided')}</p>
      <p><strong>Service needed:</strong></p>
      <p>${escapeHtml(message).replace(/\n/g, '<br>')}</p>
      <p><strong>Received:</strong> ${escapeHtml(timestamp)}</p>
    `;

    const results = await Promise.allSettled([
      sendSms(sms),
      sendEmail(subject, textBody, htmlBody)
    ]);

    const smsOk = results[0].status === 'fulfilled';
    const emailOk = results[1].status === 'fulfilled';

    if (!smsOk && !emailOk) {
      console.error('Both notification services failed:', results.map(r => r.reason?.message));
      return res.status(502).json({ ok: false, message: 'The request could not be sent. Please call 603-710-9777.' });
    }

    if (!smsOk || !emailOk) {
      console.error('Partial notification failure:', results.map(r => r.status === 'rejected' ? r.reason?.message : 'ok'));
    }

    res.json({
      ok: true,
      message: 'Thanks! Your service request was sent. RK Plumbing will be in touch shortly.',
      smsSent: smsOk,
      emailSent: emailOk
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ ok: false, message: 'Something went wrong sending the request. Please call 603-710-9777.' });
  }
});

function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

app.use(express.static(__dirname));

app.use((req, res, next) => {
  if (req.path.startsWith('/api/')) return next();
  res.sendFile(require('path').join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
  console.log('RK Plumbing website listening on port ' + PORT);
});