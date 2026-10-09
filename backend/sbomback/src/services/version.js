// Loose version comparison for ordering OSV fixed versions.

function parse(v) {
  const s = String(v).trim().replace(/^v/i, '');
  const [core, pre] = s.split(/-(.+)/);

  const nums = core
    .split(/[.+_]/)
    .map((x) => (/^\d+$/.test(x) ? Number(x) : x));

  return {
    nums,
    pre: pre || null
  };
}

function compareVersions(a, b) {
  const pa = parse(a);
  const pb = parse(b);

  const len = Math.max(pa.nums.length, pb.nums.length);

  for (let i = 0; i < len; i++) {
    const x = pa.nums[i] ?? 0;
    const y = pb.nums[i] ?? 0;

    if (x === y) continue;

    if (typeof x === 'number' && typeof y === 'number') {
      return x < y ? -1 : 1;
    }

    return String(x).localeCompare(String(y));
  }

  // Prerelease versions are lower than stable versions.
  if (pa.pre && !pb.pre) return -1;
  if (!pa.pre && pb.pre) return 1;

  if (pa.pre && pb.pre) {
    return pa.pre.localeCompare(pb.pre);
  }

  return 0;
}

module.exports = { compareVersions };