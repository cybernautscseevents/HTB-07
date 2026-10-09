const TYPE_TO_ECOSYSTEM = {
  npm: 'npm', pypi: 'PyPI', maven: 'Maven', golang: 'Go', cargo: 'crates.io',
  gem: 'RubyGems', nuget: 'NuGet', composer: 'Packagist', hex: 'Hex', pub: 'Pub',
};

function parsePurl(purl) {
  if (typeof purl !== 'string' || !purl.startsWith('pkg:')) return null;
  try {
    const noQuery = purl.slice(4).split(/[?#]/)[0];
    const at = noQuery.lastIndexOf('@');
    const hasVersion = at > noQuery.indexOf('/');
    const path = hasVersion ? noQuery.slice(0, at) : noQuery;
    const version = hasVersion ? decodeURIComponent(noQuery.slice(at + 1)) : null;
    const segs = path.split('/');
    const type = segs.shift().toLowerCase();
    const name = decodeURIComponent(segs.pop() || '');
    const namespace = segs.length ? decodeURIComponent(segs.join('/')) : null;
    if (!type || !name) return null;
    return { type, namespace, name, version, ecosystem: TYPE_TO_ECOSYSTEM[type] || null };
  } catch {
    return null;
  }
}

module.exports = { parsePurl, TYPE_TO_ECOSYSTEM };
