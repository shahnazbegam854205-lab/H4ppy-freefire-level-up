const express = require('express');
const axios = require('axios');
const cors = require('cors');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json());

// ─── Configuration ──────────────────────────────
const CLIENT_ID = '100067';
const OAUTH_BASE = 'https://auth.garena.com/universal/oauth';
const API_BASE = 'https://api-discountstore.gid.recargajogo.com.br';
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');

// ─── Store session ──────────────────────────────
const sessionStore = new Map();

// ─── Helper: Get Base URL Dynamically ───────────
function getBaseUrl(req) {
    // Vercel par: https://your-project.vercel.app
    // Local: http://localhost:3000
    const protocol = req.headers['x-forwarded-proto'] || req.protocol || 'http';
    const host = req.headers['x-forwarded-host'] || req.headers.host || 'localhost:3000';
    return `${protocol}://${host}`;
}

// ─── Step 1: Generate OAuth Login URL ────────────
app.get('/api/auth/login', (req, res) => {
    const platform = req.query.platform || '8';
    const state = crypto.randomBytes(32).toString('hex');
    
    sessionStore.set(state, { platform, timestamp: Date.now() });
    
    // ─── Auto-detect redirect_uri ──────────────────
    const baseUrl = getBaseUrl(req);
    const redirectUri = `${baseUrl}/api/auth/callback`;
    
    const oauthUrl = `${OAUTH_BASE}?response_type=code&client_id=${CLIENT_ID}&platform=${platform}&redirect_uri=${encodeURIComponent(redirectUri)}&state=${state}`;
    
    res.json({ url: oauthUrl });
});

// ─── Step 2: OAuth Callback ──────────────────────
app.get('/api/auth/callback', async (req, res) => {
    const { code, state } = req.query;
    
    if (!sessionStore.has(state)) {
        return res.status(400).json({ error: 'Invalid state' });
    }
    sessionStore.delete(state);
    
    try {
        // ─── Code → Eat Token ──────────────────────
        const eatResponse = await axios.get(`${API_BASE}/oauth/callback_redirect/`, {
            params: { code, app_id: CLIENT_ID },
            headers: {
                'User-Agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Referer': 'https://auth.garena.com/'
            },
            maxRedirects: 0,
            validateStatus: (status) => status >= 200 && status < 400
        });

        const location = eatResponse.headers.location || eatResponse.headers.Location;
        if (!location) throw new Error('No redirect location');

        const urlParams = new URL(location);
        const eatToken = urlParams.searchParams.get('eat');
        const region = urlParams.searchParams.get('region') || 'IND';
        const accountId = urlParams.searchParams.get('account_id');
        const nickname = urlParams.searchParams.get('nickname');

        // ─── Eat Token → User Data ──────────────────
        const userResponse = await axios.get(`${API_BASE}/oauth/callback/`, {
            params: { eat: eatToken, lang: 'en', region },
            headers: {
                'Origin': 'https://discstore.recargajogo.com.br',
                'Referer': 'https://discstore.recargajogo.com.br/',
                'User-Agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36',
                'Accept': 'application/json, text/plain, */*'
            }
        });

        const userData = userResponse.data;

        // ─── Generate JWT ────────────────────────────
        const jwt_token = jwt.sign(
            {
                account_id: userData.account_id || userData.uid || accountId,
                nickname: Buffer.from(userData.nickname || nickname || 'User').toString('base64'),
                noti_region: userData.region || region,
                lock_region: userData.region || region,
                external_id: userData.external_id || crypto.randomBytes(16).toString('hex'),
                external_type: 8,
                plat_id: 1,
                client_version: "1.126.2",
                emulator_score: 100,
                is_emulator: true,
                country_code: "US",
                external_uid: userData.external_uid || 1021001667174,
                reg_avatar: 102000007,
                source: 0,
                lock_region_time: Math.floor(Date.now() / 1000),
                client_type: 2,
                signature_md5: "",
                using_version: 0,
                release_channel: "",
                release_version: "OB54",
                exp: Math.floor(Date.now() / 1000) + 7 * 24 * 60 * 60
            },
            JWT_SECRET,
            { algorithm: 'HS256', header: { svr: "3", typ: "JWT" } }
        );

        // ─── Return HTML Page with Auto-Display ─────
        res.send(`
            <!DOCTYPE html>
            <html>
            <head>
                <title>Login Successful</title>
                <style>
                    body { font-family: Arial; background: #0a0a0a; color: #fff; display: flex; justify-content: center; align-items: center; height: 100vh; }
                    .container { background: rgba(10,8,8,0.92); padding: 40px; border-radius: 20px; border: 1px solid rgba(60,120,255,0.12); max-width: 500px; width: 90%; }
                    h1 { color: #6b9fff; }
                    .data { margin: 10px 0; padding: 10px; background: rgba(0,0,0,0.3); border-radius: 10px; }
                    .token { font-family: monospace; word-break: break-all; font-size: 12px; color: #b0aaaa; }
                    .btn { display: inline-block; margin-top: 20px; padding: 12px 24px; background: linear-gradient(135deg, #1a4aff, #0a2aaa); color: #fff; border: none; border-radius: 10px; cursor: pointer; text-decoration: none; }
                    .btn:hover { opacity: 0.8; }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>✅ Login Successful!</h1>
                    <div class="data"><strong>Nickname:</strong> ${userData.nickname || nickname || 'User'}</div>
                    <div class="data"><strong>UID:</strong> ${userData.account_id || userData.uid || accountId}</div>
                    <div class="data"><strong>Region:</strong> ${userData.region || region}</div>
                    <div class="data"><strong>Level:</strong> ${userData.level || '—'}</div>
                    <div class="data"><strong>Access Token:</strong><br/><span class="token">${userData.access_token || userData.token || '—'}</span></div>
                    <div class="data"><strong>JWT Token:</strong><br/><span class="token">${jwt_token}</span></div>
                    <a href="/" class="btn">← Go Back to Home</a>
                    <button onclick="window.close()" class="btn" style="margin-left: 10px;">Close</button>
                </div>
                <script>
                    // Send data to parent window
                    if (window.opener) {
                        window.opener.postMessage({
                            type: 'LOGIN_SUCCESS',
                            data: {
                                nickname: '${userData.nickname || nickname || 'User'}',
                                uid: '${userData.account_id || userData.uid || accountId}',
                                region: '${userData.region || region}',
                                level: '${userData.level || '—'}',
                                access_token: '${userData.access_token || userData.token || '—'}',
                                jwt_token: '${jwt_token}'
                            }
                        }, '*');
                    }
                </script>
            </body>
            </html>
        `);

    } catch (error) {
        console.error('Callback error:', error.response?.data || error.message);
        res.send(`
            <html>
            <body style="background:#0a0a0a;color:#fff;display:flex;justify-content:center;align-items:center;height:100vh;font-family:Arial;">
                <div style="background:rgba(10,8,8,0.92);padding:40px;border-radius:20px;border:1px solid rgba(255,40,40,0.2);max-width:500px;">
                    <h1 style="color:#ff4a4a;">❌ Login Failed</h1>
                    <p>${error.response?.data?.message || 'Authentication failed'}</p>
                    <a href="/" class="btn" style="display:inline-block;margin-top:20px;padding:12px 24px;background:linear-gradient(135deg,#1a4aff,#0a2aaa);color:#fff;border:none;border-radius:10px;cursor:pointer;text-decoration:none;">Try Again</a>
                </div>
            </body>
            </html>
        `);
    }
});

// ─── Step 3: Generate Endpoint (Manual Eat Token) ──
app.post('/api/generate', async (req, res) => {
    const { eat } = req.body;
    
    if (!eat) {
        return res.json({ success: false, error: 'Eat token required' });
    }
    
    try {
        let eatToken = eat;
        let region = 'IND';
        
        if (eat.includes('eat=')) {
            const url = new URL(eat);
            eatToken = url.searchParams.get('eat');
            region = url.searchParams.get('region') || 'IND';
        }
        
        const response = await axios.get(`${API_BASE}/oauth/callback/`, {
            params: { eat: eatToken, lang: 'en', region },
            headers: {
                'Origin': 'https://discstore.recargajogo.com.br',
                'Referer': 'https://discstore.recargajogo.com.br/',
                'User-Agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36',
                'Accept': 'application/json, text/plain, */*'
            }
        });
        
        const data = response.data;
        
        const jwt_token = jwt.sign(
            {
                account_id: data.account_id || data.uid,
                nickname: Buffer.from(data.nickname || 'User').toString('base64'),
                noti_region: data.region || region,
                lock_region: data.region || region,
                external_id: data.external_id || crypto.randomBytes(16).toString('hex'),
                external_type: 8,
                plat_id: 1,
                client_version: "1.126.2",
                emulator_score: 100,
                is_emulator: true,
                country_code: "US",
                external_uid: data.external_uid || 1021001667174,
                reg_avatar: 102000007,
                source: 0,
                lock_region_time: Math.floor(Date.now() / 1000),
                client_type: 2,
                signature_md5: "",
                using_version: 0,
                release_channel: "",
                release_version: "OB54",
                exp: Math.floor(Date.now() / 1000) + 7 * 24 * 60 * 60
            },
            JWT_SECRET,
            { algorithm: 'HS256', header: { svr: "3", typ: "JWT" } }
        );
        
        res.json({
            success: true,
            nickname: data.nickname || 'User',
            region: data.region || region,
            uid: data.account_id || data.uid,
            level: data.level || '—',
            access_token: data.access_token || data.token,
            jwt_token: jwt_token,
            avatar: data.avatar || null
        });
        
    } catch (error) {
        console.error('Generate error:', error.response?.data || error.message);
        res.json({
            success: false,
            error: error.response?.data?.message || 'Invalid eat token or expired'
        });
    }
});

// ─── Serve Frontend ──────────────────────────────
const path = require('path');
app.use(express.static(path.join(__dirname, '../public')));

app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '../public/index.html'));
});

// ─── Export for Vercel ────────────────────────────
module.exports = app;
