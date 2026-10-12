const express = require('express');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs/promises');

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

// Private owner access. Credentials and signing secret are stored as Railway variables.
const OWNER_COOKIE = 'rk_owner_session';
const OWNER_SESSION_TTL_MS = 8 * 60 * 60 * 1000;
const OWNER_EMAIL = (process.env.OWNER_EMAIL || '').trim().toLowerCase();
const OWNER_PASSWORD_BOOTSTRAP = process.env.OWNER_PASSWORD || '';
let ownerPasswordHash = null;
const OWNER_SESSION_SECRET = process.env.OWNER_SESSION_SECRET || '';
const ownerSessions = new Map();
const ownerLoginAttempts = new Map();
const OWNER_LOGIN_WINDOW_MS = 15 * 60 * 1000;
const OWNER_LOGIN_MAX_ATTEMPTS = 8;

function safeEqual(a, b) {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

function makePasswordRecord(password) {
  const salt = crypto.randomBytes(16).toString('base64url');
  const hash = crypto.scryptSync(String(password), salt, 64).toString('hex');
  return { salt, hash, updatedAt: new Date().toISOString() };
}

function verifyOwnerPassword(password) {
  if (!ownerPasswordHash || !ownerPasswordHash.salt || !ownerPasswordHash.hash) return false;
  const derived = crypto.scryptSync(String(password), ownerPasswordHash.salt, 64).toString('hex');
  return safeEqual(derived, ownerPasswordHash.hash);
}

function ownerAuthConfigured() {
  return Boolean(OWNER_EMAIL && ownerPasswordHash && OWNER_SESSION_SECRET);
}

function signOwnerSession(sessionId) {
  return crypto.createHmac('sha256', OWNER_SESSION_SECRET).update(sessionId).digest('base64url');
}

function readCookie(req, name) {
  const cookieHeader = String(req.headers.cookie || '');
  for (const part of cookieHeader.split(';')) {
    const index = part.indexOf('=');
    if (index < 0) continue;
    if (part.slice(0, index).trim() === name) return part.slice(index + 1).trim();
  }
  return '';
}

function getOwnerSessionId(req) {
  if (!ownerAuthConfigured()) return '';
  const token = readCookie(req, OWNER_COOKIE);
  const separator = token.indexOf('.');
  if (separator <= 0) return '';
  const sessionId = token.slice(0, separator);
  const signature = token.slice(separator + 1);
  if (!safeEqual(signature, signOwnerSession(sessionId))) return '';
  const expiresAt = ownerSessions.get(sessionId);
  if (!expiresAt || expiresAt <= Date.now()) {
    ownerSessions.delete(sessionId);
    return '';
  }
  return sessionId;
}

function setOwnerCookie(res, sessionId) {
  const token = sessionId + '.' + signOwnerSession(sessionId);
  res.setHeader('Set-Cookie', OWNER_COOKIE + '=' + token + '; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=' + Math.floor(OWNER_SESSION_TTL_MS / 1000));
}

function clearOwnerCookie(res) {
  res.setHeader('Set-Cookie', OWNER_COOKIE + '=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0');
}

// Job data is stored on Railway's persistent volume (DATA_DIR=/data).
const DATA_DIR = process.env.DATA_DIR || '/tmp/rk-plumbing-schedule-data';
const JOBS_FILE = path.join(DATA_DIR, 'jobs.json');
const REVIEWS_FILE = path.join(DATA_DIR, 'reviews.json');
const OWNER_PASSWORD_FILE = path.join(DATA_DIR, 'owner-password.json');
let jobWriteQueue = Promise.resolve();
let reviewWriteQueue = Promise.resolve();
const publicReviewAttempts = new Map();
const JOB_STATUSES = new Set(['scheduled', 'confirmed', 'in-progress', 'completed', 'cancelled']);

async function initializeJobStorage() {
  await fs.mkdir(DATA_DIR, { recursive: true });
  try {
    await fs.access(JOBS_FILE);
  } catch {
    await fs.writeFile(JOBS_FILE, '[]', { flag: 'wx', mode: 0o600 });
  }
  let raw = await fs.readFile(JOBS_FILE, 'utf8');
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    // Repair the empty file created by the earlier initializer only.
    if (!raw.endsWith('\\n')) throw error;
    raw = raw.slice(0, -2);
    parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) throw new Error('Schedule storage is not a valid job list.');
    await fs.writeFile(JOBS_FILE, JSON.stringify(parsed, null, 2), { mode: 0o600 });
  }
  if (!Array.isArray(parsed)) throw new Error('Schedule storage is not a valid job list.');
}

async function readJobsFile() {
  const parsed = JSON.parse(await fs.readFile(JOBS_FILE, 'utf8'));
  if (!Array.isArray(parsed)) throw new Error('Schedule storage is not a valid job list.');
  return parsed;
}

async function readReviewsFile() {
  const parsed = JSON.parse(await fs.readFile(REVIEWS_FILE, 'utf8'));
  if (!Array.isArray(parsed)) throw new Error('Review storage is not a valid review list.');
  return parsed;
}

async function atomicWriteFile(filePath, value) {
  const tempPath = filePath + '.' + crypto.randomUUID() + '.tmp';
  await fs.writeFile(tempPath, JSON.stringify(value, null, 2), { mode: 0o600 });
  await fs.rename(tempPath, filePath);
}

async function saveOwnerPasswordRecord(record) {
  await atomicWriteFile(OWNER_PASSWORD_FILE, record);
}

function mutateReviews(mutator) {
  const operation = reviewWriteQueue.then(async () => {
    const reviews = await readReviewsFile();
    const result = await mutator(reviews);
    await atomicWriteFile(REVIEWS_FILE, reviews);
    return result;
  });
  reviewWriteQueue = operation.catch(() => {});
  return operation;
}

async function initializeReviewAndPasswordStorage() {
  try {
    await fs.access(REVIEWS_FILE);
  } catch {
    await fs.writeFile(REVIEWS_FILE, '[]', { flag: 'wx', mode: 0o600 });
  }
  const reviews = await readReviewsFile();
  if (!Array.isArray(reviews)) throw new Error('Review storage is not a valid review list.');

  try {
    const record = JSON.parse(await fs.readFile(OWNER_PASSWORD_FILE, 'utf8'));
    if (!record || typeof record.salt !== 'string' || typeof record.hash !== 'string' || !/^[a-f0-9]{128}$/i.test(record.hash)) {
      throw new Error('Owner password storage is not valid.');
    }
    ownerPasswordHash = record;
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
    if (!OWNER_PASSWORD_BOOTSTRAP) throw new Error('OWNER_PASSWORD is not set; cannot initialize owner password.');
    ownerPasswordHash = makePasswordRecord(OWNER_PASSWORD_BOOTSTRAP);
    await saveOwnerPasswordRecord(ownerPasswordHash);
  }
}

async function atomicWriteJobs(jobs) {
  const tempPath = JOBS_FILE + '.' + crypto.randomUUID() + '.tmp';
  await fs.writeFile(tempPath, JSON.stringify(jobs, null, 2), { mode: 0o600 });
  await fs.rename(tempPath, JOBS_FILE);
}

function mutateJobs(mutator) {
  const operation = jobWriteQueue.then(async () => {
    const jobs = await readJobsFile();
    const result = await mutator(jobs);
    await atomicWriteJobs(jobs);
    return result;
  });
  jobWriteQueue = operation.catch(() => {});
  return operation;
}

function validateJobInput(input, existing = {}) {
  const title = clean(input.title, 120);
  const customerName = clean(input.customerName, 120);
  const date = clean(input.date, 10);
  const time = clean(input.time, 5);
  const phone = clean(input.phone, 40);
  const email = clean(input.email, 160);
  const address = clean(input.address, 240);
  const notes = clean(input.notes, 3000);
  const status = clean(input.status || existing.status || 'scheduled', 24);
  const durationValue = Number(input.durationMinutes ?? existing.durationMinutes ?? 60);

  if (!title || !customerName || !date || !time) {
    return { error: 'Enter the work description, customer name, date, and start time.' };
  }
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
    return { error: 'Choose a valid work date.' };
  }
  const [year, month, day] = date.split('-').map(Number);
  const dateCheck = new Date(Date.UTC(year, month - 1, day));
  if (dateCheck.getUTCFullYear() !== year || dateCheck.getUTCMonth() + 1 !== month || dateCheck.getUTCDate() !== day) {
    return { error: 'Choose a valid work date.' };
  }
  if (!/^([01]\d|2[0-3]):[0-5]\d$/.test(time)) {
    return { error: 'Choose a valid start time.' };
  }
  if (email && !isValidEmail(email)) return { error: 'Enter a valid customer email address.' };
  if (!JOB_STATUSES.has(status)) return { error: 'Choose a valid job status.' };
  if (!Number.isInteger(durationValue) || durationValue < 15 || durationValue > 720) {
    return { error: 'Estimated duration must be between 15 minutes and 12 hours.' };
  }

  return {
    job: {
      title, customerName, date, time, phone, email, address, notes,
      status,
      durationMinutes: durationValue,
      updatedAt: new Date().toISOString()
    }
  };
}

function requireOwnerApi(req, res) {
  if (getOwnerSessionId(req)) return true;
  res.status(401).json({ ok: false, message: 'Please sign in to the owner area again.' });
  return false;
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

app.get('/owner-login', (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  if (getOwnerSessionId(req)) return res.redirect('/owner');
  res.sendFile(path.join(__dirname, 'owner-login.html'));
});

app.get('/owner', (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  if (!getOwnerSessionId(req)) return res.redirect('/owner-login');
  res.sendFile(path.join(__dirname, 'private', 'owner-dashboard.html'));
});

app.post('/api/owner/login', (req, res) => {
  if (!ownerAuthConfigured()) {
    return res.status(503).json({ ok: false, message: 'Owner login is not configured yet. Please contact the site owner.' });
  }

  const ip = getClientIp(req);
  const now = Date.now();
  const attempts = (ownerLoginAttempts.get(ip) || []).filter(ts => now - ts < OWNER_LOGIN_WINDOW_MS);
  if (attempts.length >= OWNER_LOGIN_MAX_ATTEMPTS) {
    ownerLoginAttempts.set(ip, attempts);
    return res.status(429).json({ ok: false, message: 'Too many sign-in attempts. Please wait 15 minutes and try again.' });
  }

  const email = clean(req.body.email, 254).toLowerCase();
  const password = String(req.body.password ?? '').slice(0, 1024);
  const valid = safeEqual(email, OWNER_EMAIL) && verifyOwnerPassword(password);
  if (!valid) {
    attempts.push(now);
    ownerLoginAttempts.set(ip, attempts);
    return res.status(401).json({ ok: false, message: 'Sign-in failed. Check your email and password.' });
  }

  ownerLoginAttempts.delete(ip);
  for (const [id, expiry] of ownerSessions) {
    if (expiry <= now) ownerSessions.delete(id);
  }
  const sessionId = crypto.randomBytes(32).toString('base64url');
  ownerSessions.set(sessionId, now + OWNER_SESSION_TTL_MS);
  setOwnerCookie(res, sessionId);
  res.setHeader('Cache-Control', 'no-store');
  return res.json({ ok: true });
});

app.post('/api/owner/password', async (req, res) => {
  if (!requireOwnerApi(req, res)) return;
  const currentPassword = String(req.body.currentPassword ?? '').slice(0, 1024);
  const newPassword = String(req.body.newPassword ?? '').slice(0, 1024);
  if (!verifyOwnerPassword(currentPassword)) {
    return res.status(401).json({ ok: false, message: 'Your current password is incorrect.' });
  }
  if (newPassword.length < 12) {
    return res.status(400).json({ ok: false, message: 'Use a new password with at least 12 characters.' });
  }
  if (newPassword === currentPassword) {
    return res.status(400).json({ ok: false, message: 'Choose a password different from your current password.' });
  }
  try {
    const record = makePasswordRecord(newPassword);
    await saveOwnerPasswordRecord(record);
    ownerPasswordHash = record;
    ownerSessions.clear();
    const sessionId = crypto.randomBytes(32).toString('base64url');
    ownerSessions.set(sessionId, Date.now() + OWNER_SESSION_TTL_MS);
    setOwnerCookie(res, sessionId);
    res.setHeader('Cache-Control', 'no-store');
    return res.json({ ok: true, message: 'Password changed successfully.' });
  } catch (error) {
    console.error('Unable to update owner password:', error.message);
    return res.status(500).json({ ok: false, message: 'Password could not be changed. Please try again.' });
  }
});

app.post('/api/owner/logout', (req, res) => {
  const sessionId = getOwnerSessionId(req);
  if (sessionId) ownerSessions.delete(sessionId);
  clearOwnerCookie(res);
  res.setHeader('Cache-Control', 'no-store');
  return res.json({ ok: true });
});

app.get('/api/owner/jobs', async (req, res) => {
  if (!requireOwnerApi(req, res)) return;
  try {
    const jobs = await readJobsFile();
    jobs.sort((a, b) => (a.date + 'T' + a.time).localeCompare(b.date + 'T' + b.time));
    res.setHeader('Cache-Control', 'no-store');
    return res.json({ ok: true, jobs });
  } catch (error) {
    console.error('Unable to read schedule:', error.message);
    return res.status(500).json({ ok: false, message: 'Could not load the work schedule. Please try again.' });
  }
});

app.post('/api/owner/jobs', async (req, res) => {
  if (!requireOwnerApi(req, res)) return;
  const validated = validateJobInput(req.body || {});
  if (validated.error) return res.status(400).json({ ok: false, message: validated.error });
  try {
    const job = await mutateJobs(jobs => {
      const created = { id: crypto.randomUUID(), createdAt: new Date().toISOString(), ...validated.job };
      jobs.push(created);
      return created;
    });
    return res.status(201).json({ ok: true, job, message: 'Work has been added to your schedule.' });
  } catch (error) {
    console.error('Unable to save scheduled job:', error.message);
    return res.status(500).json({ ok: false, message: 'Could not save this job. Please try again.' });
  }
});

app.put('/api/owner/jobs/:id', async (req, res) => {
  if (!requireOwnerApi(req, res)) return;
  const validated = validateJobInput(req.body || {});
  if (validated.error) return res.status(400).json({ ok: false, message: validated.error });
  try {
    const result = await mutateJobs(jobs => {
      const index = jobs.findIndex(job => job.id === req.params.id);
      if (index < 0) return null;
      jobs[index] = { ...jobs[index], ...validated.job, id: jobs[index].id, createdAt: jobs[index].createdAt };
      return jobs[index];
    });
    if (!result) return res.status(404).json({ ok: false, message: 'That scheduled job could not be found.' });
    return res.json({ ok: true, job: result, message: 'Schedule updated.' });
  } catch (error) {
    console.error('Unable to update scheduled job:', error.message);
    return res.status(500).json({ ok: false, message: 'Could not update this job. Please try again.' });
  }
});

app.delete('/api/owner/jobs/:id', async (req, res) => {
  if (!requireOwnerApi(req, res)) return;
  try {
    const removed = await mutateJobs(jobs => {
      const index = jobs.findIndex(job => job.id === req.params.id);
      if (index < 0) return false;
      jobs.splice(index, 1);
      return true;
    });
    if (!removed) return res.status(404).json({ ok: false, message: 'That scheduled job could not be found.' });
    return res.json({ ok: true, message: 'Scheduled job deleted.' });
  } catch (error) {
    console.error('Unable to delete scheduled job:', error.message);
    return res.status(500).json({ ok: false, message: 'Could not delete this job. Please try again.' });
  }
});

app.get('/api/reviews/approved', async (req, res) => {
  try {
    const reviews = await readReviewsFile();
    const approved = reviews
      .filter(review => review.status === 'approved')
      .sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)))
      .map(({ id, name, rating, review, createdAt }) => ({ id, name, rating, review, createdAt }));
    res.setHeader('Cache-Control', 'no-store');
    return res.json({ ok: true, reviews: approved });
  } catch (error) {
    console.error('Unable to load public reviews:', error.message);
    return res.status(500).json({ ok: false, message: 'Reviews are temporarily unavailable.' });
  }
});

app.post('/api/reviews', async (req, res) => {
  try {
    const ip = getClientIp(req);
    const now = Date.now();
    const attempts = (publicReviewAttempts.get(ip) || []).filter(ts => now - ts < 60 * 60 * 1000);
    if (attempts.length >= 3) {
      publicReviewAttempts.set(ip, attempts);
      return res.status(429).json({ ok: false, message: 'Too many review submissions. Please try again later.' });
    }
    // Honeypot field; legitimate visitors leave it empty.
    if (clean(req.body.website, 100)) return res.json({ ok: true, message: 'Thank you for your feedback.' });

    const name = clean(req.body.name, 100);
    const reviewText = clean(req.body.review, 4000);
    const rating = Number(req.body.rating);
    if (!name || reviewText.length < 10 || !Number.isInteger(rating) || rating < 1 || rating > 5) {
      return res.status(400).json({ ok: false, message: 'Please enter your name, choose a star rating, and write a review of at least 10 characters.' });
    }

    const created = await mutateReviews(reviews => {
      const review = {
        id: crypto.randomUUID(),
        name,
        rating,
        review: reviewText,
        status: 'pending',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      };
      reviews.push(review);
      return review;
    });
    attempts.push(now);
    publicReviewAttempts.set(ip, attempts);
    return res.status(201).json({ ok: true, message: 'Thank you! Your review was submitted for owner approval.', reviewId: created.id });
  } catch (error) {
    console.error('Unable to save customer review:', error.message);
    return res.status(500).json({ ok: false, message: 'Your review could not be submitted. Please try again.' });
  }
});

app.get('/api/owner/reviews', async (req, res) => {
  if (!requireOwnerApi(req, res)) return;
  try {
    const reviews = await readReviewsFile();
    reviews.sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)));
    res.setHeader('Cache-Control', 'no-store');
    return res.json({ ok: true, reviews });
  } catch (error) {
    console.error('Unable to load review queue:', error.message);
    return res.status(500).json({ ok: false, message: 'Could not load the review queue.' });
  }
});

app.patch('/api/owner/reviews/:id', async (req, res) => {
  if (!requireOwnerApi(req, res)) return;
  const status = clean(req.body.status, 20);
  if (!['pending', 'approved', 'declined'].includes(status)) {
    return res.status(400).json({ ok: false, message: 'Choose pending, approved, or declined.' });
  }
  try {
    const result = await mutateReviews(reviews => {
      const review = reviews.find(item => item.id === req.params.id);
      if (!review) return null;
      review.status = status;
      review.updatedAt = new Date().toISOString();
      return review;
    });
    if (!result) return res.status(404).json({ ok: false, message: 'That review could not be found.' });
    return res.json({ ok: true, review: result, message: status === 'approved' ? 'Review approved and published.' : status === 'declined' ? 'Review declined and kept out of the public website.' : 'Review moved back to pending.' });
  } catch (error) {
    console.error('Unable to update review status:', error.message);
    return res.status(500).json({ ok: false, message: 'Could not update the review. Please try again.' });
  }
});

app.get('/api/health', (req, res) => {
  res.json({
    ok: true,
    smsConfigured: Boolean(process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN && process.env.TWILIO_FROM_NUMBER),
    emailConfigured: Boolean(process.env.RESEND_API_KEY && process.env.RESEND_FROM_EMAIL)
  });
});

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

// Do not serve dashboard files directly from the public static path.
app.use('/private', (req, res) => res.sendStatus(404));

app.use(express.static(__dirname));

app.use((req, res, next) => {
  if (req.path.startsWith('/api/')) return next();
  res.sendFile(require('path').join(__dirname, 'index.html'));
});

initializeJobStorage()
  .then(initializeReviewAndPasswordStorage)
  .then(() => {
    app.listen(PORT, () => {
      console.log('RK Plumbing website listening on port ' + PORT);
      console.log('Owner work schedule and review storage ready at ' + DATA_DIR);
    });
  })
  .catch(error => {
    console.error('Failed to initialize work schedule storage:', error);
    process.exit(1);
  });