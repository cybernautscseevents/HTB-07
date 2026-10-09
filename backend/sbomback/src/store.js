const db = require('./database');

const insertScan = db.prepare(`
  INSERT INTO scans (id, owner_id, scan_json)
  VALUES (?, ?, ?)
  ON CONFLICT(id) DO UPDATE SET
    owner_id = excluded.owner_id,
    scan_json = excluded.scan_json
`);

const selectById = db.prepare(`
  SELECT scan_json FROM scans
  WHERE id = ? AND owner_id = ?
`);

const selectLatest = db.prepare(`
  SELECT scan_json FROM scans
  WHERE owner_id = ?
  ORDER BY created_at DESC, rowid DESC
  LIMIT 1
`);

const selectAll = db.prepare(`
  SELECT scan_json FROM scans
  WHERE owner_id = ?
  ORDER BY created_at DESC, rowid DESC
`);

const deleteScan = db.prepare(`
  DELETE FROM scans WHERE id = ? AND owner_id = ?
`);

module.exports = {
  save(scan) {
    if (!scan.id || !scan.ownerId) {
      throw new Error('A scan ID and owner ID are required');
    }

    insertScan.run(scan.id, scan.ownerId, JSON.stringify(scan));
    return scan;
  },

  get(id, ownerId) {
    if (id === 'latest') {
      const row = selectLatest.get(ownerId);
      return row ? JSON.parse(row.scan_json) : undefined;
    }

    const row = selectById.get(id, ownerId);
    return row ? JSON.parse(row.scan_json) : undefined;
  },

  list(ownerId) {
    return selectAll.all(ownerId).map(row => JSON.parse(row.scan_json));
  },

  remove(id, ownerId) {
    return deleteScan.run(id, ownerId).changes > 0;
  },
};