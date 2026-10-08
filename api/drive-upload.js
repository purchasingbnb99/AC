const { cert, getApp, getApps, initializeApp } = require('firebase-admin/app');
const { getAuth } = require('firebase-admin/auth');
const { getFirestore } = require('firebase-admin/firestore');

function getAdminApp() {
  if (getApps().length) return getApp();

  const privateKey = String(process.env.FIREBASE_PRIVATE_KEY || '').replace(/\\n/g, '\n');

  if (
    !process.env.FIREBASE_PROJECT_ID ||
    !process.env.FIREBASE_CLIENT_EMAIL ||
    !privateKey
  ) {
    throw new Error('Konfigurasi Firebase Admin di Vercel belum lengkap.');
  }

  return initializeApp({
    credential: cert({
      projectId: process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey
    })
  });
}

function json(res, status, body) {
  res.status(status);
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  return res.end(JSON.stringify(body));
}

function getBearerToken(req) {
  const header = String(req.headers?.authorization || '');
  const match = header.match(/^Bearer\s+(.+)$/i);
  return match ? match[1].trim() : '';
}

function getBody(req) {
  if (req.body == null) return null;
  if (typeof req.body === 'string') return JSON.parse(req.body);
  return req.body;
}

function validatePayload(payload) {
  if (!payload || typeof payload !== 'object') {
    throw new Error('Payload tidak valid.');
  }

  if (!payload.fileName || !payload.base64Data) {
    throw new Error('fileName dan base64Data wajib diisi.');
  }

  const allowed = new Set([
    'image/jpeg',
    'image/png',
    'application/pdf'
  ]);

  if (payload.mimeType && !allowed.has(payload.mimeType)) {
    throw new Error('Tipe file tidak diizinkan.');
  }

  const jsonBytes = Buffer.byteLength(JSON.stringify(payload), 'utf8');
  if (jsonBytes > 4 * 1024 * 1024) {
    throw new Error('Ukuran upload terlalu besar. Kompres foto terlebih dahulu.');
  }
}

function isAnonymous(decoded) {
  return decoded?.firebase?.sign_in_provider === 'anonymous';
}

function validateAnonymousUpload(payload) {
  const photoType = String(payload?.photoType || '').trim().toLowerCase();
  const allowedAnonymousTypes = new Set([
    'technician_access',
    'before',
    'after',
    'attachments'
  ]);

  if (!allowedAnonymousTypes.has(photoType)) {
    const err = new Error('Jenis upload tidak diizinkan untuk Quick Technician.');
    err.statusCode = 403;
    throw err;
  }

  if (photoType === 'technician_access') {
    const name = String(payload?.technicianName || '').trim();
    if (name.length < 2 || name.length > 120) {
      const err = new Error('Nama Teknisi tidak valid.');
      err.statusCode = 400;
      throw err;
    }
    return;
  }

  const maintenanceNumber = String(payload?.maintenanceNumber || '').trim();
  if (!/^MNT-[A-Z0-9_-]+$/i.test(maintenanceNumber)) {
    const err = new Error('Nomor maintenance tidak valid untuk upload Teknisi.');
    err.statusCode = 400;
    throw err;
  }
}

module.exports = async function handler(req, res) {
  if (req.method === 'OPTIONS') {
    res.setHeader('Allow', 'POST, OPTIONS');
    return json(res, 204, {});
  }

  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST, OPTIONS');
    return json(res, 405, {
      ok: false,
      error: 'Method tidak diizinkan.'
    });
  }

  try {
    if (!process.env.DRIVE_GATEWAY_URL || !process.env.DRIVE_GATEWAY_TOKEN) {
      return json(res, 500, {
        ok: false,
        error: 'Konfigurasi Drive Gateway di Vercel belum lengkap.'
      });
    }

    const idToken = getBearerToken(req);
    if (!idToken) {
      return json(res, 401, {
        ok: false,
        error: 'Login Firebase diperlukan.'
      });
    }

    const app = getAdminApp();
    const decoded = await getAuth(app).verifyIdToken(idToken);
    const anonymous = isAnonymous(decoded);
    let actorRole = '';

    if (anonymous) {
      actorRole = 'technician_quick';
    } else {
      const userSnap = await getFirestore(app)
        .collection('users')
        .doc(decoded.uid)
        .get();

      if (!userSnap.exists) {
        return json(res, 403, {
          ok: false,
          error: 'Akun tidak terdaftar di sistem.'
        });
      }

      const userData = userSnap.data() || {};
      const isActiveAllowedRole =
        (userData.role === 'admin' || userData.role === 'technician') &&
        userData.active === true;

      if (!isActiveAllowedRole) {
        return json(res, 403, {
          ok: false,
          error: 'Akun tidak memiliki akses aktif untuk upload.'
        });
      }

      actorRole = userData.role;
    }

    const payload = getBody(req);
    validatePayload(payload);

    if (anonymous) {
      validateAnonymousUpload(payload);
    }

    const upstreamPayload = {
      ...payload,
      token: process.env.DRIVE_GATEWAY_TOKEN,
      uploadedByUid: decoded.uid,
      uploadedByRole: actorRole
    };

    const upstream = await fetch(process.env.DRIVE_GATEWAY_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(upstreamPayload)
    });

    const responseText = await upstream.text();
    let responseBody;

    try {
      responseBody = JSON.parse(responseText);
    } catch {
      responseBody = {
        ok: false,
        error: 'Respons gateway tidak valid.'
      };
    }

    return json(
      res,
      upstream.ok ? 200 : upstream.status,
      responseBody
    );
  } catch (err) {
    console.error('Drive upload proxy error:', err);

    const status = Number(err?.statusCode);
    return json(res, Number.isInteger(status) && status >= 400 && status <= 599 ? status : 500, {
      ok: false,
      error: err instanceof Error
        ? err.message
        : 'Terjadi kesalahan pada proxy upload.'
    });
  }
};
