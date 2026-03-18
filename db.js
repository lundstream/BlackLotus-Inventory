const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

const dataDir = fs.existsSync(path.join(__dirname, 'data')) ? path.join(__dirname, 'data') : __dirname;
const DB_PATH = path.join(dataDir, 'secureboot.db');
let db;

function getDb() {
  if (!db) {
    db = new Database(DB_PATH);
    db.pragma('journal_mode = WAL');
    db.pragma('foreign_keys = ON');
    initTables();
  }
  return db;
}

function initTables() {
  const d = getDb();

  d.exec(`
    CREATE TABLE IF NOT EXISTS devices (
      hostname TEXT NOT NULL,
      domain TEXT,
      os_version TEXT,
      os_build TEXT,
      os_name TEXT,
      manufacturer TEXT,
      model TEXT,
      bios_version TEXT,
      is_virtual_machine INTEGER DEFAULT 0,
      secure_boot_enabled INTEGER DEFAULT 0,
      migration_phase TEXT,
      available_updates INTEGER,
      uefi_secure_boot_enabled INTEGER,
      uefica2023_status TEXT,
      uefica2023_error TEXT,
      windows_uefica2023_capable TEXT,
      oem_manufacturer_name TEXT,
      oem_model_number TEXT,
      db_install_status INTEGER,
      db_default_install_status INTEGER,
      msrom_install_status INTEGER,
      optrom_install_status INTEGER,
      kek_install_status INTEGER,
      third_party_install_status INTEGER,
      dbx_revocation_status INTEGER,
      collected_at TEXT NOT NULL,
      received_at TEXT NOT NULL DEFAULT (datetime('now')),
      PRIMARY KEY (hostname, domain)
    )
  `);

  // History table: keep every report for trend tracking
  d.exec(`
    CREATE TABLE IF NOT EXISTS device_history (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      hostname TEXT NOT NULL,
      domain TEXT,
      migration_phase TEXT,
      collected_at TEXT NOT NULL,
      received_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `);

  // Migrations: add new columns if missing
  try { d.exec(`ALTER TABLE devices ADD COLUMN bios_date TEXT`); } catch (e) {}
  try { d.exec(`ALTER TABLE devices ADD COLUMN vmware_hw_version TEXT`); } catch (e) {}
  try { d.exec(`ALTER TABLE devices ADD COLUMN bitlocker_status TEXT`); } catch (e) {}

  // Indexes
  try { d.exec(`CREATE INDEX IF NOT EXISTS idx_devices_phase ON devices(migration_phase)`); } catch (e) {}
  try { d.exec(`CREATE INDEX IF NOT EXISTS idx_devices_domain ON devices(domain)`); } catch (e) {}
  try { d.exec(`CREATE INDEX IF NOT EXISTS idx_history_hostname ON device_history(hostname, domain)`); } catch (e) {}
}

// --- Upsert a device report ---
function upsertDevice(report) {
  const d = getDb();

  const boolToInt = (v) => v === true ? 1 : v === false ? 0 : v == null ? null : (v ? 1 : 0);

  const stmt = d.prepare(`
    INSERT INTO devices (
      hostname, domain, os_version, os_build, os_name,
      manufacturer, model, bios_version, bios_date, is_virtual_machine,
      vmware_hw_version, bitlocker_status,
      secure_boot_enabled, migration_phase,
      available_updates, uefi_secure_boot_enabled, uefica2023_status, uefica2023_error,
      windows_uefica2023_capable, oem_manufacturer_name, oem_model_number,
      db_install_status, db_default_install_status, msrom_install_status,
      optrom_install_status, kek_install_status, third_party_install_status,
      dbx_revocation_status, collected_at
    ) VALUES (
      @hostname, @domain, @osVersion, @osBuild, @osName,
      @manufacturer, @model, @biosVersion, @biosDate, @isVirtualMachine,
      @vmwareHWVersion, @bitlockerStatus,
      @secureBootEnabled, @migrationPhase,
      @availableUpdates, @uefiSecureBootEnabled, @uefica2023Status, @uefica2023Error,
      @windowsUefica2023Capable, @oemManufacturerName, @oemModelNumber,
      @dbInstallStatus, @dbDefaultInstallStatus, @msromInstallStatus,
      @optromInstallStatus, @kekInstallStatus, @thirdPartyInstallStatus,
      @dbxRevocationStatus, @collectedAt
    )
    ON CONFLICT(hostname, domain) DO UPDATE SET
      os_version = excluded.os_version,
      os_build = excluded.os_build,
      os_name = excluded.os_name,
      manufacturer = excluded.manufacturer,
      model = excluded.model,
      bios_version = excluded.bios_version,
      bios_date = excluded.bios_date,
      is_virtual_machine = excluded.is_virtual_machine,
      vmware_hw_version = excluded.vmware_hw_version,
      bitlocker_status = excluded.bitlocker_status,
      secure_boot_enabled = excluded.secure_boot_enabled,
      migration_phase = excluded.migration_phase,
      available_updates = excluded.available_updates,
      uefi_secure_boot_enabled = excluded.uefi_secure_boot_enabled,
      uefica2023_status = excluded.uefica2023_status,
      uefica2023_error = excluded.uefica2023_error,
      windows_uefica2023_capable = excluded.windows_uefica2023_capable,
      oem_manufacturer_name = excluded.oem_manufacturer_name,
      oem_model_number = excluded.oem_model_number,
      db_install_status = excluded.db_install_status,
      db_default_install_status = excluded.db_default_install_status,
      msrom_install_status = excluded.msrom_install_status,
      optrom_install_status = excluded.optrom_install_status,
      kek_install_status = excluded.kek_install_status,
      third_party_install_status = excluded.third_party_install_status,
      dbx_revocation_status = excluded.dbx_revocation_status,
      collected_at = excluded.collected_at,
      received_at = datetime('now')
  `);

  const reg = report.registry || {};
  const certs = report.certificates || {};

  stmt.run({
    hostname: report.hostname || '',
    domain: report.domain || '',
    osVersion: report.osVersion || '',
    osBuild: report.osBuild || '',
    osName: report.osName || '',
    manufacturer: report.manufacturer || '',
    model: report.model || '',
    biosVersion: report.biosVersion || '',
    biosDate: report.biosDate || null,
    isVirtualMachine: boolToInt(report.isVirtualMachine),
    vmwareHWVersion: report.vmwareHWVersion || null,
    bitlockerStatus: report.bitlockerStatus || null,
    secureBootEnabled: boolToInt(report.secureBootEnabled),
    migrationPhase: report.migrationPhase || 'Unknown',
    availableUpdates: reg.AvailableUpdates != null ? Number(reg.AvailableUpdates) : null,
    uefiSecureBootEnabled: reg.UEFISecureBootEnabled != null ? Number(reg.UEFISecureBootEnabled) : null,
    uefica2023Status: reg.UEFICA2023Status || null,
    uefica2023Error: reg.UEFICA2023Error || null,
    windowsUefica2023Capable: reg.WindowsUEFICA2023Capable != null ? String(reg.WindowsUEFICA2023Capable) : null,
    oemManufacturerName: reg.OEMManufacturerName || null,
    oemModelNumber: reg.OEMModelNumber || null,
    dbInstallStatus: boolToInt(certs.DBInstallStatus),
    dbDefaultInstallStatus: boolToInt(certs.DBDefaultInstallStatus),
    msromInstallStatus: boolToInt(certs.MSROMInstallStatus),
    optromInstallStatus: boolToInt(certs.OptROMInstallStatus),
    kekInstallStatus: boolToInt(certs.KEKInstallStatus),
    thirdPartyInstallStatus: boolToInt(certs.ThirdPartyInstallStatus),
    dbxRevocationStatus: boolToInt(certs.DBXRevocationStatus),
    collectedAt: report.collectedAt || new Date().toISOString()
  });

  // Insert history record
  const histStmt = d.prepare(`
    INSERT INTO device_history (hostname, domain, migration_phase, collected_at)
    VALUES (@hostname, @domain, @migrationPhase, @collectedAt)
  `);
  histStmt.run({
    hostname: report.hostname || '',
    domain: report.domain || '',
    migrationPhase: report.migrationPhase || 'Unknown',
    collectedAt: report.collectedAt || new Date().toISOString()
  });
}

// --- Get all devices ---
function getDevices({ search, domain, phase, sort, order, limit, offset } = {}) {
  const d = getDb();
  let where = [];
  let params = {};

  if (search) {
    where.push(`(hostname LIKE @search OR os_name LIKE @search OR manufacturer LIKE @search OR model LIKE @search)`);
    params.search = `%${search}%`;
  }
  if (domain) {
    where.push(`domain = @domain`);
    params.domain = domain;
  }
  if (phase) {
    where.push(`migration_phase = @phase`);
    params.phase = phase;
  }

  const whereClause = where.length > 0 ? `WHERE ${where.join(' AND ')}` : '';

  const allowedSorts = ['hostname', 'domain', 'migration_phase', 'os_name', 'collected_at', 'manufacturer'];
  const sortCol = allowedSorts.includes(sort) ? sort : 'hostname';
  const sortOrder = order === 'desc' ? 'DESC' : 'ASC';

  const countRow = d.prepare(`SELECT COUNT(*) as total FROM devices ${whereClause}`).get(params);

  const lim = Math.min(Math.max(parseInt(limit) || 50, 1), 500);
  const off = Math.max(parseInt(offset) || 0, 0);

  const rows = d.prepare(`
    SELECT * FROM devices ${whereClause}
    ORDER BY ${sortCol} ${sortOrder}
    LIMIT @limit OFFSET @offset
  `).all({ ...params, limit: lim, offset: off });

  return { total: countRow.total, devices: rows, limit: lim, offset: off };
}

// --- Get a single device ---
function getDevice(hostname, domain) {
  const d = getDb();
  return d.prepare(`SELECT * FROM devices WHERE hostname = ? AND domain = ?`).get(hostname, domain || '');
}

// --- Get device history ---
function getDeviceHistory(hostname, domain, limit = 50) {
  const d = getDb();
  return d.prepare(`
    SELECT * FROM device_history
    WHERE hostname = ? AND domain = ?
    ORDER BY collected_at DESC
    LIMIT ?
  `).all(hostname, domain || '', limit);
}

// --- Get summary statistics ---
function getSummary() {
  const d = getDb();

  const total = d.prepare(`SELECT COUNT(*) as count FROM devices`).get().count;

  const byPhase = d.prepare(`
    SELECT migration_phase, COUNT(*) as count
    FROM devices GROUP BY migration_phase ORDER BY count DESC
  `).all();

  const byDomain = d.prepare(`
    SELECT domain, COUNT(*) as count
    FROM devices GROUP BY domain ORDER BY count DESC
  `).all();

  const secureBootEnabled = d.prepare(`SELECT COUNT(*) as count FROM devices WHERE secure_boot_enabled = 1`).get().count;
  const secureBootDisabled = d.prepare(`SELECT COUNT(*) as count FROM devices WHERE secure_boot_enabled = 0`).get().count;

  const virtualMachines = d.prepare(`SELECT COUNT(*) as count FROM devices WHERE is_virtual_machine = 1`).get().count;
  const physicalMachines = d.prepare(`SELECT COUNT(*) as count FROM devices WHERE is_virtual_machine = 0`).get().count;

  const complete = d.prepare(`SELECT COUNT(*) as count FROM devices WHERE migration_phase = 'Complete'`).get().count;

  const lastReport = d.prepare(`SELECT MAX(collected_at) as last FROM devices`).get().last;

  // Certificate breakdown
  const certStats = {
    dbInstalled: d.prepare(`SELECT COUNT(*) as count FROM devices WHERE db_install_status = 1`).get().count,
    dbDefaultInstalled: d.prepare(`SELECT COUNT(*) as count FROM devices WHERE db_default_install_status = 1`).get().count,
    kekInstalled: d.prepare(`SELECT COUNT(*) as count FROM devices WHERE kek_install_status = 1`).get().count,
    dbxRevoked: d.prepare(`SELECT COUNT(*) as count FROM devices WHERE dbx_revocation_status = 1`).get().count,
    msromInstalled: d.prepare(`SELECT COUNT(*) as count FROM devices WHERE msrom_install_status = 1`).get().count,
    optromInstalled: d.prepare(`SELECT COUNT(*) as count FROM devices WHERE optrom_install_status = 1`).get().count,
  };

  return {
    total,
    byPhase,
    byDomain,
    secureBootEnabled,
    secureBootDisabled,
    virtualMachines,
    physicalMachines,
    complete,
    completionPercent: total > 0 ? Math.round((complete / total) * 100) : 0,
    lastReport,
    certStats
  };
}

// --- Get list of unique domains ---
function getDomains() {
  const d = getDb();
  return d.prepare(`SELECT DISTINCT domain FROM devices WHERE domain != '' ORDER BY domain`).all().map(r => r.domain);
}

// --- Get list of unique migration phases ---
function getPhases() {
  const d = getDb();
  return d.prepare(`SELECT DISTINCT migration_phase FROM devices ORDER BY migration_phase`).all().map(r => r.migration_phase);
}

// --- Delete a device ---
function deleteDevice(hostname, domain) {
  const d = getDb();
  d.prepare(`DELETE FROM devices WHERE hostname = ? AND domain = ?`).run(hostname, domain || '');
  d.prepare(`DELETE FROM device_history WHERE hostname = ? AND domain = ?`).run(hostname, domain || '');
}

// --- Purge stale devices (no report in X days) ---
function purgeStaleDevices(days = 90) {
  const d = getDb();
  const cutoff = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();
  const result = d.prepare(`DELETE FROM devices WHERE collected_at < ?`).run(cutoff);
  d.prepare(`DELETE FROM device_history WHERE collected_at < ?`).run(cutoff);
  return result.changes;
}

module.exports = {
  getDb,
  upsertDevice,
  getDevices,
  getDevice,
  getDeviceHistory,
  getSummary,
  getDomains,
  getPhases,
  deleteDevice,
  purgeStaleDevices,
};
