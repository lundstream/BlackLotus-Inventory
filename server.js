const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');
const db = require('./db');

const settings = JSON.parse(fs.readFileSync(path.join(__dirname, 'settings.json'), 'utf8'));

// --- CIDR / IP matching for trusted-network checks ---
function parseIPv4(ip) {
  // Handle IPv4-mapped IPv6 (::ffff:x.x.x.x)
  const mapped = ip.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
  if (mapped) ip = mapped[1];
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  const nums = parts.map(Number);
  if (nums.some(n => isNaN(n) || n < 0 || n > 255)) return null;
  return (nums[0] << 24 | nums[1] << 16 | nums[2] << 8 | nums[3]) >>> 0;
}

function ipInCIDR(ip, cidr) {
  // IPv6 loopback
  if (cidr === '::1/128') return ip === '::1';
  const [net, bits] = cidr.split('/');
  const prefix = parseInt(bits, 10);
  const netInt = parseIPv4(net);
  const ipInt = parseIPv4(ip);
  if (netInt === null || ipInt === null) return false;
  const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
  return (ipInt & mask) === (netInt & mask);
}

function isInternalIP(ip) {
  const nets = settings.trustedNetworks || ['10.0.0.0/8','172.16.0.0/12','192.168.0.0/16','127.0.0.0/8','::1/128'];
  return nets.some(cidr => ipInCIDR(ip, cidr));
}

// Middleware: restrict to internal network only
function internalOnly(req, res, next) {
  const clientIP = req.ip || req.connection?.remoteAddress || '';
  if (isInternalIP(clientIP)) return next();
  return res.status(403).json({ error: 'Forbidden: dashboard is only accessible from the internal network' });
}

const app = express();
app.set('trust proxy', true);
app.disable('x-powered-by');
app.use(cors());
app.use(express.json({ limit: '100kb' }));

// Rate limiting — protect API from abuse
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 300,                   // 300 requests per window per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later' }
});
const reportLimiter = rateLimit({
  windowMs: 60 * 1000,        // 1 minute
  max: 30,                    // 30 reports/min per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many reports, please try again later' }
});
app.use('/api/', apiLimiter);
app.use('/api/report', reportLimiter);

// HTTPS redirect when behind IIS / reverse proxy
app.use((req, res, next) => {
  if (process.env.NODE_ENV === 'production' && req.headers['x-forwarded-proto'] === 'http') {
    return res.redirect(301, 'https://' + req.headers.host + req.url);
  }
  next();
});

// Security headers
app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://unpkg.com https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: blob:; connect-src 'self'; frame-ancestors 'self'");
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  next();
});

// --- Dashboard access: internal network only ---
// Block external IPs from accessing static files / dashboard pages
app.use((req, res, next) => {
  // Allow /api/report from anywhere (internet-facing endpoint)
  if (req.path.startsWith('/api/report')) return next();
  // All other requests must come from a trusted network
  const clientIP = req.ip || req.connection?.remoteAddress || '';
  if (isInternalIP(clientIP)) return next();
  // External IP hitting a non-report route
  if (req.path.startsWith('/api/')) {
    return res.status(403).json({ error: 'Forbidden: this endpoint is only accessible from the internal network' });
  }
  return res.status(403).send('Forbidden');
});

// Serve static files (dashboard — internal only)
app.use(express.static(path.join(__dirname, 'public'), {
  setHeaders(res, filePath) {
    if (/\.(html|js|css)$/i.test(filePath)) {
      res.setHeader('Cache-Control', 'no-cache, must-revalidate');
    }
  }
}));

// Block direct access to sensitive files
app.use((req, res, next) => {
  const lower = req.path.toLowerCase();
  if (lower.includes('settings.json') || lower.includes('secureboot.db')) {
    return res.status(403).send('Forbidden');
  }
  next();
});

// --- API key validation middleware ---
function requireApiKey(req, res, next) {
  const key = req.headers['x-api-key'];
  if (!key || key !== settings.apiKey) {
    return res.status(401).json({ error: 'Unauthorized: invalid or missing API key' });
  }
  next();
}

// --- Public settings (no secrets) ---
app.get('/api/settings', (req, res) => {
  res.json({
    siteName: settings.siteName || 'Secure Boot Inventory',
    footerText: settings.footerText || ''
  });
});

// --- Receive inventory report from clients (requires API key) ---
app.post('/api/report', requireApiKey, (req, res) => {
  try {
    const report = req.body;
    if (!report || !report.hostname) {
      return res.status(400).json({ error: 'Missing required field: hostname' });
    }
    db.upsertDevice(report);
    res.json({ status: 'ok', hostname: report.hostname });
  } catch (err) {
    console.error('Error saving report:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// --- Get summary dashboard data ---
app.get('/api/summary', (req, res) => {
  try {
    res.json(db.getSummary());
  } catch (err) {
    console.error('Error getting summary:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// --- Get devices list (paginated, filterable) ---
app.get('/api/devices', (req, res) => {
  try {
    const { search, domain, phase, sort, order, limit, offset } = req.query;
    res.json(db.getDevices({ search, domain, phase, sort, order, limit, offset }));
  } catch (err) {
    console.error('Error getting devices:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// --- Get single device detail ---
app.get('/api/devices/:hostname', (req, res) => {
  try {
    const domain = req.query.domain || '';
    const device = db.getDevice(req.params.hostname, domain);
    if (!device) return res.status(404).json({ error: 'Device not found' });
    const history = db.getDeviceHistory(req.params.hostname, domain);
    res.json({ device, history });
  } catch (err) {
    console.error('Error getting device:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// --- Get available filters ---
app.get('/api/filters', (req, res) => {
  try {
    res.json({
      domains: db.getDomains(),
      phases: db.getPhases()
    });
  } catch (err) {
    console.error('Error getting filters:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// --- Export all devices as CSV ---
app.get('/api/export', (req, res) => {
  try {
    const result = db.getDevices({ limit: 10000, offset: 0 });
    const devices = result.devices;

    const columns = [
      'hostname','domain','os_name','os_build','os_version','manufacturer','model',
      'bios_version','bios_date','is_virtual_machine','vmware_hw_version','bitlocker_status',
      'secure_boot_enabled','migration_phase',
      'db_install_status','db_default_install_status','msrom_install_status',
      'optrom_install_status','kek_install_status','third_party_install_status',
      'dbx_revocation_status','uefica2023_status','windows_uefica2023_capable',
      'collected_at'
    ];

    const escCsv = (val) => {
      if (val == null) return '';
      const s = String(val);
      if (s.includes(',') || s.includes('"') || s.includes('\n')) {
        return '"' + s.replace(/"/g, '""') + '"';
      }
      return s;
    };

    const header = columns.join(',');
    const rows = devices.map(d => columns.map(c => escCsv(d[c])).join(','));
    const csv = header + '\n' + rows.join('\n');

    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="secureboot-inventory.csv"');
    res.send(csv);
  } catch (err) {
    console.error('Error exporting:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// --- Start server ---
// iisnode sets process.env.PORT to a named pipe; fall back to config/3001 for standalone
const PORT = process.env.PORT || settings.server?.port || 3001;
app.listen(PORT, () => {
  console.log(`Secure Boot Inventory server running on port ${PORT}`);
  if (typeof PORT === 'number' || /^\d+$/.test(PORT)) {
    console.log(`Dashboard: http://localhost:${PORT}`);
  } else {
    console.log('Running behind IIS (named pipe)');
  }
  // Initialize database
  db.getDb();
});
