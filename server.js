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
const CALENDAR_FEED_FILE = path.join(DATA_DIR, 'calendar-feed-token.json');
const GOOGLE_CALENDAR_CONNECTION_FILE = path.join(DATA_DIR, 'google-calendar-connection.json');
const GOOGLE_CALENDAR_SCOPES = [
  'openid',
  'email',
  'https://www.googleapis.com/auth/calendar.events',
  'https://www.googleapis.com/auth/calendar.calendarlist.readonly'
];
const GOOGLE_REDIRECT_URI = process.env.GOOGLE_REDIRECT_URI || 'https://rk-plumbing-website-production.up.railway.app/auth/google/callback';
let calendarFeedToken = null;
let googleCalendarConnection = {
  refreshToken: null,
  accessToken: null,
  expiresAt: 0,
  connectedEmail: '',
  calendarId: '',
  calendarSummary: '',
  lastSyncAt: null,
  lastSyncError: null,
  lastSyncStats: null
};
const googleOAuthStates = new Map();
let googleTokenRefreshPromise = null;
let googleCalendarSyncPromise = null;
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

async function initializeCalendarFeedStorage() {
  try {
    const record = JSON.parse(await fs.readFile(CALENDAR_FEED_FILE, 'utf8'));
    if (!record || typeof record.token !== 'string' || !/^[A-Za-z0-9_-]{40,80}$/.test(record.token)) {
      throw new Error('Calendar feed token storage is not valid.');
    }
    calendarFeedToken = record.token;
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
    calendarFeedToken = crypto.randomBytes(32).toString('base64url');
    await atomicWriteFile(CALENDAR_FEED_FILE, { token: calendarFeedToken, createdAt: new Date().toISOString() });
  }
}

async function initializeGoogleCalendarStorage() {
  try {
    const stored = JSON.parse(await fs.readFile(GOOGLE_CALENDAR_CONNECTION_FILE, 'utf8'));
    if (!stored || typeof stored !== 'object' || Array.isArray(stored)) throw new Error('Google Calendar connection storage is not valid.');
    googleCalendarConnection = { ...googleCalendarConnection, ...stored };
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
    await atomicWriteFile(GOOGLE_CALENDAR_CONNECTION_FILE, googleCalendarConnection);
  }
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


function googleOAuthConfigured() {
  return Boolean(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET && GOOGLE_REDIRECT_URI);
}

function ownerSessionIsActive(sessionId) {
  const expiry = ownerSessions.get(sessionId);
  if (!expiry || expiry <= Date.now()) {
    ownerSessions.delete(sessionId);
    return false;
  }
  return true;
}

async function saveGoogleCalendarConnection() {
  await atomicWriteFile(GOOGLE_CALENDAR_CONNECTION_FILE, googleCalendarConnection);
}

function googleCalendarStatus() {
  return {
    configured: googleOAuthConfigured(),
    connected: Boolean(googleCalendarConnection.refreshToken),
    connectedEmail: googleCalendarConnection.connectedEmail || '',
    calendarId: googleCalendarConnection.calendarId || '',
    calendarSummary: googleCalendarConnection.calendarSummary || '',
    lastSyncAt: googleCalendarConnection.lastSyncAt || null,
    lastSyncError: googleCalendarConnection.lastSyncError || null,
    lastSyncStats: googleCalendarConnection.lastSyncStats || null,
    redirectUri: GOOGLE_REDIRECT_URI
  };
}

app.get('/owner/google-calendar/connect', (req, res) => {
  const sessionId = getOwnerSessionId(req);
  if (!sessionId) return res.redirect('/owner-login');
  if (!googleOAuthConfigured()) return res.redirect('/owner?google=setup-required#google-calendar-sync');

  const now = Date.now();
  for (const [key, entry] of googleOAuthStates) {
    if (entry.expiresAt <= now) googleOAuthStates.delete(key);
  }
  const state = crypto.randomBytes(32).toString('base64url');
  googleOAuthStates.set(state, { sessionId, expiresAt: now + 10 * 60 * 1000 });

  const authUrl = new URL('https://accounts.google.com/o/oauth2/v2/auth');
  authUrl.searchParams.set('client_id', process.env.GOOGLE_CLIENT_ID);
  authUrl.searchParams.set('redirect_uri', GOOGLE_REDIRECT_URI);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('scope', GOOGLE_CALENDAR_SCOPES.join(' '));
  authUrl.searchParams.set('access_type', 'offline');
  authUrl.searchParams.set('prompt', 'consent');
  authUrl.searchParams.set('include_granted_scopes', 'true');
  authUrl.searchParams.set('state', state);
  res.setHeader('Cache-Control', 'no-store');
  return res.redirect(authUrl.toString());
});

app.get('/auth/google/callback', async (req, res) => {
  const state = clean(req.query.state, 200);
  const stateRecord = googleOAuthStates.get(state);
  googleOAuthStates.delete(state);
  if (!stateRecord || stateRecord.expiresAt <= Date.now() || !ownerSessionIsActive(stateRecord.sessionId)) {
    return res.redirect('/owner?google=state-error#google-calendar-sync');
  }
  if (req.query.error) return res.redirect('/owner?google=denied#google-calendar-sync');
  const code = clean(req.query.code, 4096);
  if (!code || !googleOAuthConfigured()) return res.redirect('/owner?google=setup-required#google-calendar-sync');

  try {
    const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code,
        client_id: process.env.GOOGLE_CLIENT_ID,
        client_secret: process.env.GOOGLE_CLIENT_SECRET,
        redirect_uri: GOOGLE_REDIRECT_URI,
        grant_type: 'authorization_code'
      })
    });
    const tokenData = await tokenResponse.json().catch(() => ({}));
    if (!tokenResponse.ok || !tokenData.access_token) {
      console.error('Google Calendar authorization exchange failed:', tokenData.error || tokenResponse.status);
      return res.redirect('/owner?google=auth-failed#google-calendar-sync');
    }

    let connectedEmail = googleCalendarConnection.connectedEmail || '';
    try {
      const userResponse = await fetch('https://openidconnect.googleapis.com/v1/userinfo', {
        headers: { Authorization: 'Bearer ' + tokenData.access_token }
      });
      if (userResponse.ok) {
        const user = await userResponse.json();
        connectedEmail = clean(user.email, 254).toLowerCase();
      }
    } catch {}

    googleCalendarConnection = {
      ...googleCalendarConnection,
      refreshToken: tokenData.refresh_token || googleCalendarConnection.refreshToken || null,
      accessToken: tokenData.access_token,
      expiresAt: Date.now() + (Number(tokenData.expires_in) || 3600) * 1000,
      connectedEmail,
      lastSyncError: null
    };
    await saveGoogleCalendarConnection();
    res.setHeader('Cache-Control', 'no-store');
    return res.redirect('/owner?google=connected#google-calendar-sync');
  } catch (error) {
    console.error('Google Calendar authorization failed:', error.message);
    return res.redirect('/owner?google=auth-failed#google-calendar-sync');
  }
});

async function googleAccessToken() {
  if (!googleOAuthConfigured()) throw new Error('Google Calendar is not configured yet. Add the Google OAuth credentials in Railway first.');
  if (!googleCalendarConnection.refreshToken) throw new Error('Connect your Google account first.');
  if (googleCalendarConnection.accessToken && googleCalendarConnection.expiresAt > Date.now() + 60000) {
    return googleCalendarConnection.accessToken;
  }
  if (googleTokenRefreshPromise) return googleTokenRefreshPromise;

  googleTokenRefreshPromise = (async () => {
    const response = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: process.env.GOOGLE_CLIENT_ID,
        client_secret: process.env.GOOGLE_CLIENT_SECRET,
        refresh_token: googleCalendarConnection.refreshToken,
        grant_type: 'refresh_token'
      })
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok || !data.access_token) {
      googleCalendarConnection.lastSyncError = 'Google authorization needs to be reconnected. Use Disconnect, then Connect Google Calendar again.';
      await saveGoogleCalendarConnection().catch(() => {});
      throw new Error(googleCalendarConnection.lastSyncError);
    }
    googleCalendarConnection = {
      ...googleCalendarConnection,
      accessToken: data.access_token,
      expiresAt: Date.now() + (Number(data.expires_in) || 3600) * 1000,
      refreshToken: data.refresh_token || googleCalendarConnection.refreshToken
    };
    await saveGoogleCalendarConnection();
    return googleCalendarConnection.accessToken;
  })();

  try {
    return await googleTokenRefreshPromise;
  } finally {
    googleTokenRefreshPromise = null;
  }
}

async function googleApiRequest(apiPath, options = {}, alreadyRetried = false) {
  const token = await googleAccessToken();
  const headers = { Authorization: 'Bearer ' + token, ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...(options.headers || {}) };
  const response = await fetch('https://www.googleapis.com/calendar/v3' + apiPath, {
    ...options,
    headers,
    body: options.body && typeof options.body !== 'string' ? JSON.stringify(options.body) : options.body
  });
  if (response.status === 401 && !alreadyRetried) {
    googleCalendarConnection.accessToken = '';
    googleCalendarConnection.expiresAt = 0;
    await saveGoogleCalendarConnection();
    return googleApiRequest(apiPath, options, true);
  }
  if (response.status === 204) return null;
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const message = data?.error?.message || ('Google Calendar returned HTTP ' + response.status + '.');
    throw new Error(String(message).slice(0, 240));
  }
  return data;
}

async function googleCalendarList() {
  const calendars = [];
  let pageToken = '';
  do {
    const params = new URLSearchParams({ maxResults: '250' });
    if (pageToken) params.set('pageToken', pageToken);
    const data = await googleApiRequest('/users/me/calendarList?' + params.toString());
    calendars.push(...(Array.isArray(data.items) ? data.items : []));
    pageToken = data.nextPageToken || '';
  } while (pageToken);
  return calendars;
}

app.get('/api/owner/google-calendar/status', (req, res) => {
  if (!requireOwnerApi(req, res)) return;
  res.setHeader('Cache-Control', 'no-store');
  return res.json({ ok: true, status: googleCalendarStatus() });
});

app.get('/api/owner/google-calendar/calendars', async (req, res) => {
  if (!requireOwnerApi(req, res)) return;
  try {
    const calendars = await googleCalendarList();
    const writable = calendars
      .filter(calendar => ['owner', 'writer'].includes(calendar.accessRole) && calendar.id)
      .map(calendar => ({
        id: calendar.id,
        summary: clean(calendar.summary || 'Untitled calendar', 200),
        primary: Boolean(calendar.primary),
        accessRole: calendar.accessRole,
        selected: calendar.id === googleCalendarConnection.calendarId
      }));
    res.setHeader('Cache-Control', 'no-store');
    return res.json({ ok: true, calendars: writable });
  } catch (error) {
    return res.status(502).json({ ok: false, message: 'Could not load writable Google calendars: ' + error.message });
  }
});

app.post('/api/owner/google-calendar/select', async (req, res) => {
  if (!requireOwnerApi(req, res)) return;
  const calendarId = clean(req.body.calendarId, 500);
  if (!calendarId) return res.status(400).json({ ok: false, message: 'Choose a Google Calendar first.' });
  try {
    const calendars = await googleCalendarList();
    const selected = calendars.find(calendar => calendar.id === calendarId);
    if (!selected || !['owner', 'writer'].includes(selected.accessRole)) {
      return res.status(403).json({ ok: false, message: 'Choose a calendar where your Google account has edit access.' });
    }
    googleCalendarConnection = {
      ...googleCalendarConnection,
      calendarId: selected.id,
      calendarSummary: clean(selected.summary || 'Google Calendar', 200),
      lastSyncError: null
    };
    await saveGoogleCalendarConnection();
    const stats = await syncGoogleCalendar();
    res.setHeader('Cache-Control', 'no-store');
    return res.json({ ok: true, status: googleCalendarStatus(), stats, message: 'Calendar connected. The initial two-way sync has finished.' });
  } catch (error) {
    googleCalendarConnection.lastSyncError = error.message;
    await saveGoogleCalendarConnection().catch(() => {});
    return res.status(502).json({ ok: false, message: 'The calendar was selected, but sync did not finish: ' + error.message, status: googleCalendarStatus() });
  }
});

app.post('/api/owner/google-calendar/sync', async (req, res) => {
  if (!requireOwnerApi(req, res)) return;
  if (!googleCalendarConnection.refreshToken) return res.status(400).json({ ok: false, message: 'Connect your Google account first.' });
  if (!googleCalendarConnection.calendarId) return res.status(400).json({ ok: false, message: 'Choose a writable Google Calendar first.' });
  try {
    const stats = await syncGoogleCalendar();
    res.setHeader('Cache-Control', 'no-store');
    return res.json({ ok: true, stats, status: googleCalendarStatus(), message: 'Google Calendar and RK Plumbing schedule are synced.' });
  } catch (error) {
    return res.status(502).json({ ok: false, message: error.message, status: googleCalendarStatus() });
  }
});

app.post('/api/owner/google-calendar/disconnect', async (req, res) => {
  if (!requireOwnerApi(req, res)) return;
  const tokenToRevoke = googleCalendarConnection.refreshToken || googleCalendarConnection.accessToken;
  if (googleCalendarSyncPromise) return res.status(409).json({ ok: false, message: 'Calendar sync is running. Try disconnecting again in a moment.' });
  if (tokenToRevoke) {
    try {
      await fetch('https://oauth2.googleapis.com/revoke', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ token: tokenToRevoke })
      });
    } catch {}
  }
  googleCalendarConnection = {
    refreshToken: null, accessToken: null, expiresAt: 0, connectedEmail: '',
    calendarId: '', calendarSummary: '', lastSyncAt: null, lastSyncError: null, lastSyncStats: null
  };
  try {
    await saveGoogleCalendarConnection();
    return res.json({ ok: true, status: googleCalendarStatus(), message: 'Google Calendar disconnected. Existing events have not been deleted.' });
  } catch (error) {
    return res.status(500).json({ ok: false, message: 'Could not save the disconnect. Please try again.' });
  }
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


function buildCalendarFeedUrl(req, token) {
  const host = String(req.get('host') || 'rk-plumbing-website-production.up.railway.app').replace(/[^a-zA-Z0-9.:-]/g, '');
  return 'https://' + host + '/calendar-feed/' + token + '.ics';
}

function escapeIcsText(value) {
  return String(value ?? '')
    .replace(/\\/g, '\\\\')
    .replace(/\r\n|\r|\n/g, '\\n')
    .replace(/;/g, '\\;')
    .replace(/,/g, '\\,');
}

function foldIcsLine(line) {
  const folded = [];
  let current = '';
  for (const character of String(line)) {
    if (current && Buffer.byteLength(current + character, 'utf8') > 73) {
      folded.push(current);
      current = ' ' + character;
    } else {
      current += character;
    }
  }
  folded.push(current);
  return folded;
}

function icsUtcStamp(value) {
  return new Date(value).toISOString().replace(/[-:]/g, '').replace(/\.\d{3}Z$/, 'Z');
}

function icsLocalDateTime(date, time) {
  return String(date).replace(/-/g, '') + 'T' + String(time).replace(':', '') + '00';
}

function calendarDuration(minutes) {
  const value = Math.max(15, Math.min(720, Number(minutes) || 60));
  const hours = Math.floor(value / 60);
  const mins = value % 60;
  return 'PT' + (hours ? hours + 'H' : '') + (mins ? mins + 'M' : '');
}

app.get('/api/owner/calendar-feed', (req, res) => {
  if (!requireOwnerApi(req, res)) return;
  res.setHeader('Cache-Control', 'no-store');
  return res.json({ ok: true, url: buildCalendarFeedUrl(req, calendarFeedToken) });
});

app.post('/api/owner/calendar-feed/rotate', async (req, res) => {
  if (!requireOwnerApi(req, res)) return;
  try {
    const nextToken = crypto.randomBytes(32).toString('base64url');
    await atomicWriteFile(CALENDAR_FEED_FILE, { token: nextToken, createdAt: new Date().toISOString() });
    calendarFeedToken = nextToken;
    res.setHeader('Cache-Control', 'no-store');
    return res.json({ ok: true, url: buildCalendarFeedUrl(req, calendarFeedToken), message: 'A new private calendar link was created. The previous link no longer works.' });
  } catch (error) {
    console.error('Unable to rotate calendar feed link:', error.message);
    return res.status(500).json({ ok: false, message: 'Could not create a new calendar link. Please try again.' });
  }
});

// This URL is a private, read-only subscription feed. Keep it secret: anyone with the link can view the published schedule details.
app.get('/calendar-feed/:token.ics', async (req, res) => {
  if (!calendarFeedToken || !safeEqual(req.params.token, calendarFeedToken)) {
    return res.status(404).type('text/plain').send('Calendar feed not found.');
  }

  try {
    const jobs = await readJobsFile();
    const now = new Date();
    const lines = [
      'BEGIN:VCALENDAR',
      'VERSION:2.0',
      'PRODID:-//RK Plumbing LLC//Owner Work Schedule//EN',
      'CALSCALE:GREGORIAN',
      'METHOD:PUBLISH',
      'X-WR-CALNAME:RK Plumbing Work Schedule',
      'X-WR-TIMEZONE:America/New_York',
      'BEGIN:VTIMEZONE',
      'TZID:America/New_York',
      'X-LIC-LOCATION:America/New_York',
      'BEGIN:DAYLIGHT',
      'TZOFFSETFROM:-0500',
      'TZOFFSETTO:-0400',
      'TZNAME:EDT',
      'DTSTART:20070311T020000',
      'RRULE:FREQ=YEARLY;BYMONTH=3;BYDAY=2SU',
      'END:DAYLIGHT',
      'BEGIN:STANDARD',
      'TZOFFSETFROM:-0400',
      'TZOFFSETTO:-0500',
      'TZNAME:EST',
      'DTSTART:20071104T020000',
      'RRULE:FREQ=YEARLY;BYMONTH=11;BYDAY=1SU',
      'END:STANDARD',
      'END:VTIMEZONE'
    ];

    for (const job of jobs) {
      if (!job || !job.id || !/^\d{4}-\d{2}-\d{2}$/.test(String(job.date)) || !/^([01]\d|2[0-3]):[0-5]\d$/.test(String(job.time))) continue;
      const status = JOB_STATUSES.has(job.status) ? job.status : 'scheduled';
      const title = clean(job.title, 120) || 'Scheduled work';
      const customerName = clean(job.customerName, 120);
      const summary = '[RK Plumbing] ' + title + (customerName ? ' — ' + customerName : '');
      const startStamp = icsLocalDateTime(job.date, job.time);
      const updatedAt = job.updatedAt || job.createdAt || now.toISOString();
      lines.push(
        'BEGIN:VEVENT',
        'UID:' + escapeIcsText(job.id) + '@rk-plumbing-website-production.up.railway.app',
        'DTSTAMP:' + icsUtcStamp(now),
        'LAST-MODIFIED:' + icsUtcStamp(updatedAt),
        'DTSTART;TZID=America/New_York:' + startStamp,
        'DURATION:' + calendarDuration(job.durationMinutes),
        'SUMMARY:' + escapeIcsText(summary),
        job.address ? 'LOCATION:' + escapeIcsText(clean(job.address, 240)) : '',
        'DESCRIPTION:' + escapeIcsText('Status: ' + (statusLabelsForCalendar(status)) + '\nEstimated length: ' + (Number(job.durationMinutes) || 60) + ' minutes'),
        status === 'cancelled' ? 'STATUS:CANCELLED' : 'STATUS:CONFIRMED',
        'END:VEVENT'
      );
    }

    lines.push('END:VCALENDAR');
    const body = lines.filter(Boolean).flatMap(foldIcsLine).join('\r\n') + '\r\n';
    res.setHeader('Content-Type', 'text/calendar; charset=utf-8');
    res.setHeader('Content-Disposition', 'inline; filename="rk-plumbing-work-schedule.ics"');
    res.setHeader('Cache-Control', 'no-store, max-age=0');
    res.setHeader('X-Robots-Tag', 'noindex, nofollow, noarchive');
    return res.status(200).send(body);
  } catch (error) {
    console.error('Unable to generate private calendar feed:', error.message);
    return res.status(500).type('text/plain').send('Calendar feed is temporarily unavailable.');
  }
});

function statusLabelsForCalendar(status) {
  const labels = { scheduled: 'Scheduled', confirmed: 'Confirmed', 'in-progress': 'In progress', completed: 'Completed', cancelled: 'Cancelled' };
  return labels[status] || 'Scheduled';
}


function googleEventTitleForJob(job) {
  const title = clean(job.title, 120) || 'Scheduled work';
  const customer = clean(job.customerName, 120);
  return customer && !['Google Calendar', 'Added from Google Calendar'].includes(customer)
    ? title + ' — ' + customer
    : title;
}

function splitGoogleEventTitle(summary, existingCustomerName = '') {
  let text = clean(summary, 240) || 'Google Calendar appointment';
  text = text.replace(/^\[RK Plumbing\]\s*/i, '');
  const separator = text.match(/\s+[—–]\s+/);
  if (separator && separator.index !== undefined) {
    const title = clean(text.slice(0, separator.index), 120) || 'Scheduled work';
    const customerName = clean(text.slice(separator.index + separator[0].length), 120) || existingCustomerName || 'Google Calendar';
    return { title, customerName };
  }
  return { title: clean(text, 120) || 'Scheduled work', customerName: existingCustomerName || 'Google Calendar' };
}

function localDateTimeFromGoogle(value) {
  const parts = new Intl.DateTimeFormat('en-CA', {
    timeZone: 'America/New_York',
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', hourCycle: 'h23'
  }).formatToParts(new Date(value));
  const item = Object.fromEntries(parts.map(part => [part.type, part.value]));
  return { date: item.year + '-' + item.month + '-' + item.day, time: item.hour + ':' + item.minute };
}

function googleEventToScheduleFields(event, existing = {}) {
  let date;
  let time;
  let durationMinutes;
  if (event.start?.dateTime) {
    const start = localDateTimeFromGoogle(event.start.dateTime);
    date = start.date;
    time = start.time;
    const endValue = event.end?.dateTime ? new Date(event.end.dateTime).getTime() : new Date(event.start.dateTime).getTime() + 60 * 60000;
    durationMinutes = Math.round((endValue - new Date(event.start.dateTime).getTime()) / 60000);
    durationMinutes = Math.max(15, Math.min(720, Number.isFinite(durationMinutes) ? durationMinutes : 60));
  } else if (event.start?.date) {
    date = event.start.date;
    time = '09:00';
    durationMinutes = 480;
  } else {
    return null;
  }

  const titleParts = splitGoogleEventTitle(event.summary, existing.customerName && existing.customerName !== 'Google Calendar' ? existing.customerName : '');
  return {
    title: titleParts.title,
    customerName: titleParts.customerName,
    date, time, durationMinutes,
    address: clean(event.location || existing.address || '', 240),
    status: existing.status && JOB_STATUSES.has(existing.status) ? existing.status : 'scheduled'
  };
}

function makeGoogleEventBody(job) {
  const durationMinutes = Math.max(15, Math.min(720, Number(job.durationMinutes) || 60));
  const startWallClock = new Date(String(job.date) + 'T' + String(job.time) + ':00Z');
  const endWallClock = new Date(startWallClock.getTime() + durationMinutes * 60000);
  const endDate = endWallClock.getUTCFullYear() + '-' + String(endWallClock.getUTCMonth() + 1).padStart(2, '0') + '-' + String(endWallClock.getUTCDate()).padStart(2, '0');
  const endTime = String(endWallClock.getUTCHours()).padStart(2, '0') + ':' + String(endWallClock.getUTCMinutes()).padStart(2, '0') + ':00';
  const startTime = String(job.time) + ':00';
  const eventId = clean(job.googleCalendarEventId, 200) || String(job.id).replace(/-/g, '').toLowerCase();
  const body = {
    id: /^[0-9a-v]{5,1024}$/.test(eventId) ? eventId : undefined,
    summary: googleEventTitleForJob(job),
    description: [
      'RK Plumbing work-schedule entry.',
      'Status: ' + statusLabelsForCalendar(job.status),
      'Estimated length: ' + durationMinutes + ' minutes.',
      'Managed by RK Plumbing Work Schedule.'
    ].join('\n'),
    start: { dateTime: String(job.date) + 'T' + startTime, timeZone: 'America/New_York' },
    end: { dateTime: endDate + 'T' + endTime, timeZone: 'America/New_York' },
    extendedProperties: {
      private: { rkPlumbingJobId: String(job.id), rkPlumbingManaged: 'true' }
    }
  };
  if (job.address) body.location = clean(job.address, 240);
  else body.location = '';
  if (job.status === 'cancelled') body.status = 'cancelled';
  return body;
}

async function listGoogleCalendarEvents(calendarId) {
  const events = [];
  let pageToken = '';
  do {
    const params = new URLSearchParams({ maxResults: '2500', showDeleted: 'true', timeZone: 'America/New_York' });
    if (pageToken) params.set('pageToken', pageToken);
    const url = '/calendars/' + encodeURIComponent(calendarId) + '/events?' + params.toString();
    const data = await googleApiRequest(url);
    events.push(...(Array.isArray(data.items) ? data.items : []));
    pageToken = data.nextPageToken || '';
  } while (pageToken);
  return events;
}

async function insertOrUpdateGoogleEvent(job, event = null) {
  const calendarId = googleCalendarConnection.calendarId;
  const body = makeGoogleEventBody(job);
  if (event && event.id) {
    const result = await googleApiRequest('/calendars/' + encodeURIComponent(calendarId) + '/events/' + encodeURIComponent(event.id), {
      method: 'PATCH', body
    });
    return result;
  }
  const result = await googleApiRequest('/calendars/' + encodeURIComponent(calendarId) + '/events', {
    method: 'POST', body
  });
  return result;
}

async function deleteGoogleEvent(eventId) {
  await googleApiRequest('/calendars/' + encodeURIComponent(googleCalendarConnection.calendarId) + '/events/' + encodeURIComponent(eventId), {
    method: 'DELETE'
  });
}

async function syncGoogleCalendarOnce() {
  if (!googleCalendarConnection.refreshToken) throw new Error('Connect your Google account first.');
  if (!googleCalendarConnection.calendarId) throw new Error('Choose a writable Google Calendar first.');

  const calendarId = googleCalendarConnection.calendarId;
  const events = await listGoogleCalendarEvents(calendarId);
  const eventById = new Map(events.filter(event => event && event.id).map(event => [event.id, event]));
  const nowIso = new Date().toISOString();
  const stats = { importedFromGoogle: 0, updatedFromGoogle: 0, createdInGoogle: 0, updatedInGoogle: 0, cancelled: 0, deletedFromGoogle: 0, unchanged: 0 };

  await mutateJobs(async jobs => {
    const processed = new Set();

    for (const event of events) {
      if (!event || !event.id) continue;
      if (event.recurringEventId || event.recurrence) continue;
      const privateProps = event.extendedProperties?.private || {};
      const linkedJobId = clean(privateProps.rkPlumbingJobId, 100);
      let job = (linkedJobId && jobs.find(item => item.id === linkedJobId)) ||
        jobs.find(item => item.googleCalendarId === calendarId && item.googleCalendarEventId === event.id);

      if (event.status === 'cancelled') {
        if (job) {
          if (job.status !== 'cancelled') {
            job.status = 'cancelled';
            job.updatedAt = nowIso;
            stats.cancelled++;
          } else {
            stats.unchanged++;
          }
          job.googleCalendarId = calendarId;
          job.googleCalendarEventId = event.id;
          job.googleEventUpdatedAt = event.updated || job.googleEventUpdatedAt || nowIso;
          job.googleLastSyncedJobUpdatedAt = job.updatedAt;
          processed.add(job.id);
        }
        continue;
      }

      if (job) {
        processed.add(job.id);
        job.googleCalendarId = calendarId;
        job.googleCalendarEventId = event.id;

        const markersMissing = !job.googleLastSyncedJobUpdatedAt || !job.googleEventUpdatedAt;
        const localChanged = !markersMissing && job.updatedAt !== job.googleLastSyncedJobUpdatedAt;
        const googleChanged = !markersMissing && Boolean(event.updated) && event.updated !== job.googleEventUpdatedAt;
        const googleIsNewer = googleChanged && (!localChanged || Date.parse(event.updated) > Date.parse(job.updatedAt));

        if (googleIsNewer) {
          const fields = googleEventToScheduleFields(event, job);
          if (fields) {
            Object.assign(job, fields);
            job.updatedAt = nowIso;
            job.googleEventUpdatedAt = event.updated || nowIso;
            job.googleLastSyncedJobUpdatedAt = job.updatedAt;
            stats.updatedFromGoogle++;
          }
        } else if (localChanged || googleChanged || markersMissing) {
          const updated = await insertOrUpdateGoogleEvent(job, event);
          job.googleEventUpdatedAt = updated?.updated || nowIso;
          job.googleLastSyncedJobUpdatedAt = job.updatedAt;
          stats.updatedInGoogle++;
        } else {
          job.googleEventUpdatedAt = event.updated || job.googleEventUpdatedAt || nowIso;
          job.googleLastSyncedJobUpdatedAt = job.updatedAt;
          stats.unchanged++;
        }
        continue;
      }

      if (linkedJobId) {
        // This event belongs to a job that no longer exists in the work schedule.
        await deleteGoogleEvent(event.id);
        stats.deletedFromGoogle++;
        continue;
      }

      const fields = googleEventToScheduleFields(event);
      if (!fields) continue;
      const importedJob = {
        id: crypto.randomUUID(),
        createdAt: nowIso,
        updatedAt: nowIso,
        phone: '',
        email: '',
        notes: '',
        ...fields,
        googleCalendarId: calendarId,
        googleCalendarEventId: event.id,
        googleEventUpdatedAt: event.updated || nowIso
      };
      importedJob.googleLastSyncedJobUpdatedAt = importedJob.updatedAt;
      jobs.push(importedJob);
      processed.add(importedJob.id);

      // Tag manually-created Google events to make later syncs idempotent.
      const patched = await insertOrUpdateGoogleEvent(importedJob, event);
      importedJob.googleCalendarEventId = patched?.id || event.id;
      importedJob.googleEventUpdatedAt = patched?.updated || event.updated || nowIso;
      importedJob.googleLastSyncedJobUpdatedAt = importedJob.updatedAt;
      stats.importedFromGoogle++;
    }

    for (const job of jobs) {
      if (processed.has(job.id) && job.googleCalendarId === calendarId && job.googleCalendarEventId) continue;
      if (job.status === 'cancelled' && job.googleCalendarId === calendarId && job.googleCalendarEventId && eventById.get(job.googleCalendarEventId)?.status === 'cancelled') {
        processed.add(job.id);
        continue;
      }
      if (job.googleCalendarId === calendarId && job.googleCalendarEventId) {
        const associated = eventById.get(job.googleCalendarEventId);
        if (!associated) {
          // If Google removed the event permanently, reset the linkage and recreate it only for open work.
          job.googleCalendarEventId = '';
          job.googleEventUpdatedAt = '';
          job.googleLastSyncedJobUpdatedAt = '';
        } else if (associated.status === 'cancelled') {
          processed.add(job.id);
          continue;
        }
      }
      if (job.status === 'cancelled') {
        processed.add(job.id);
        continue;
      }

      const previousCalendarId = job.googleCalendarId || '';
      const linkedEvent = previousCalendarId === calendarId && job.googleCalendarEventId ? eventById.get(job.googleCalendarEventId) : null;
      if (linkedEvent && linkedEvent.status !== 'cancelled') continue;

      const createdOrUpdated = await insertOrUpdateGoogleEvent(job, linkedEvent);
      job.googleCalendarId = calendarId;
      job.googleCalendarEventId = createdOrUpdated?.id || job.googleCalendarEventId || '';
      job.googleEventUpdatedAt = createdOrUpdated?.updated || nowIso;
      job.googleLastSyncedJobUpdatedAt = job.updatedAt;
      stats.createdInGoogle++;
    }
  });

  googleCalendarConnection.lastSyncAt = new Date().toISOString();
  googleCalendarConnection.lastSyncError = null;
  googleCalendarConnection.lastSyncStats = stats;
  await saveGoogleCalendarConnection();
  return stats;
}

async function syncGoogleCalendar() {
  if (googleCalendarSyncPromise) return googleCalendarSyncPromise;
  googleCalendarSyncPromise = (async () => {
    try {
      return await syncGoogleCalendarOnce();
    } catch (error) {
      googleCalendarConnection.lastSyncError = error.message;
      await saveGoogleCalendarConnection().catch(() => {});
      throw error;
    } finally {
      googleCalendarSyncPromise = null;
    }
  })();
  return googleCalendarSyncPromise;
}

function startGoogleCalendarSyncLoop() {
  const timer = setInterval(() => {
    if (!googleCalendarConnection.refreshToken || !googleCalendarConnection.calendarId || googleCalendarSyncPromise) return;
    syncGoogleCalendar().catch(error => console.error('Google Calendar background sync failed:', error.message));
  }, 60 * 1000);
  timer.unref();
}

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
  .then(initializeCalendarFeedStorage)
  .then(initializeGoogleCalendarStorage)
  .then(() => {
    app.listen(PORT, () => {
      console.log('RK Plumbing website listening on port ' + PORT);
      console.log('Owner work schedule and review storage ready at ' + DATA_DIR);
      startGoogleCalendarSyncLoop();
    });
  })
  .catch(error => {
    console.error('Failed to initialize work schedule storage:', error);
    process.exit(1);
  });