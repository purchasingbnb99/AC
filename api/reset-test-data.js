const { cert, getApp, getApps, initializeApp } = require('firebase-admin/app');
const { getAuth } = require('firebase-admin/auth');
const { getFirestore } = require('firebase-admin/firestore');

const RESET_ENABLED = String(process.env.AC_MAINTENANCE_RESET_ENABLED || '').toLowerCase() === 'true';

function getAdminApp() {
  if (getApps().length) return getApp();
  const privateKey = String(process.env.FIREBASE_PRIVATE_KEY || '').replace(/\\n/g, '\n');
  if (!process.env.FIREBASE_PROJECT_ID || !process.env.FIREBASE_CLIENT_EMAIL || !privateKey) {
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
  if (req.body == null) return {};
  if (typeof req.body === 'string') return JSON.parse(req.body);
  return req.body;
}

async function deleteCollection(db, name) {
  let deleted = 0;
  while (true) {
    const snap = await db.collection(name).limit(400).get();
    if (snap.empty) break;
    const batch = db.batch();
    snap.docs.forEach((doc) => batch.delete(doc.ref));
    await batch.commit();
    deleted += snap.size;
    if (snap.size < 400) break;
  }
  return deleted;
}

async function deleteTechnicianAuthUsers(auth, preserveUid) {
  let deleted = 0;
  let pageToken;
  do {
    const page = await auth.listUsers(1000, pageToken);
    const targets = page.users
      .filter((u) => u.uid !== preserveUid)
      .map((u) => u.uid);
    for (let i = 0; i < targets.length; i += 100) {
      const chunk = targets.slice(i, i + 100);
      if (!chunk.length) continue;
      await auth.deleteUsers(chunk);
      deleted += chunk.length;
    }
    pageToken = page.pageToken;
  } while (pageToken);
  return deleted;
}

async function purgeDriveFolder() {
  if (!process.env.DRIVE_GATEWAY_URL || !process.env.DRIVE_GATEWAY_TOKEN) {
    throw new Error('Drive Gateway belum dikonfigurasi di Vercel.');
  }
  const upstream = await fetch(process.env.DRIVE_GATEWAY_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      action: 'purge_ac_maintenance_folder',
      token: process.env.DRIVE_GATEWAY_TOKEN
    })
  });
  const text = await upstream.text();
  let body;
  try { body = JSON.parse(text); }
  catch { body = { ok: false, error: 'Respons Drive Gateway tidak valid.' }; }
  if (!upstream.ok || !body?.ok) {
    throw new Error(body?.error || `Drive cleanup gagal (${upstream.status}).`);
  }
  return {
    files: Number(body.deletedFiles || 0),
    folders: Number(body.deletedFolders || 0)
  };
}

module.exports = async function handler(req, res) {
  if (req.method === 'OPTIONS') {
    res.setHeader('Allow', 'POST, OPTIONS');
    return json(res, 204, {});
  }
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST, OPTIONS');
    return json(res, 405, { ok: false, error: 'Method tidak diizinkan.' });
  }
  if (!RESET_ENABLED) {
    return json(res, 403, {
      ok: false,
      error: 'Fitur Reset Data Test sedang dinonaktifkan di Vercel.'
    });
  }

  try {
    const payload = getBody(req);
    if (String(payload.confirmation || '').trim().toUpperCase() !== 'RESET DATA TEST') {
      return json(res, 400, { ok: false, error: 'Konfirmasi reset tidak valid.' });
    }

    const token = getBearerToken(req);
    if (!token) return json(res, 401, { ok: false, error: 'Login Admin diperlukan.' });

    const app = getAdminApp();
    const adminAuth = getAuth(app);
    const db = getFirestore(app);
    const decoded = await adminAuth.verifyIdToken(token);
    const adminUid = decoded.uid;
    const adminSnap = await db.collection('users').doc(adminUid).get();
    if (!adminSnap.exists || adminSnap.data()?.role !== 'admin' || adminSnap.data()?.active !== true) {
      return json(res, 403, { ok: false, error: 'Hanya Admin aktif yang dapat melakukan reset data test.' });
    }

    // Drive cleanup is performed first. Firestore/Auth deletion starts only after Drive cleanup succeeds.
    const drive = await purgeDriveFolder();

    const collections = [
      'ac_units',
      'ac_units_public',
      'locations',
      'vendors',
      'vendors_public',
      'mcbs',
      'maintenance',
      'maintenance_public',
      'notifications',
      'settings',
      'technician_sessions',
      'technician_access_logs'
    ];

    // Delete every user profile except the Admin account currently executing the reset.
    const userSnapshot = await db.collection('users').get();
    let firestoreDeleted = 0;
    for (const userDoc of userSnapshot.docs) {
      if (userDoc.id === adminUid) continue;
      await userDoc.ref.delete();
      firestoreDeleted += 1;
    }

    for (const name of collections) {
      firestoreDeleted += await deleteCollection(db, name);
    }

    const authDeleted = await deleteTechnicianAuthUsers(adminAuth, adminUid);

    return json(res, 200, {
      ok: true,
      firestoreDeleted,
      authDeleted,
      driveDeletedFiles: drive.files,
      driveDeletedFolders: drive.folders,
      preservedAdminUid: adminUid
    });
  } catch (err) {
    console.error('Reset test data error:', err);
    return json(res, 500, {
      ok: false,
      error: err instanceof Error ? err.message : 'Reset data test gagal.'
    });
  }
};
