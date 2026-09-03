const WMTS_Z0_SCALE = 559082264.0287178;

function localName(name) {
  const value = String(name || '');
  const i = value.indexOf(':');
  return i >= 0 ? value.slice(i + 1) : value;
}

function parseAttrs(raw) {
  const attrs = {};
  const re = /([A-Za-z_][\w:.-]*)\s*=\s*("([^"]*)"|'([^']*)')/g;
  let m;
  while ((m = re.exec(String(raw || '')))) {
    const value = m[3] != null ? m[3] : m[4];
    attrs[m[1]] = value;
    const local = localName(m[1]);
    if (!(local in attrs)) attrs[local] = value;
  }
  return attrs;
}

export function parseXml(xml) {
  const source = String(xml || '')
    .replace(/^\uFEFF/, '')
    .replace(/<\?xml[\s\S]*?\?>/i, '')
    .replace(/<!--[\s\S]*?-->/g, '')
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1');
  const root = { name: 'root', attrs: {}, children: [], text: '' };
  const stack = [root];
  const re = /<(\/)?([A-Za-z_][\w:.-]*)([^>]*?)(\/?)>|([^<]+)/g;
  let m;
  while ((m = re.exec(source))) {
    if (m[5] != null) {
      const text = m[5].replace(/\s+/g, ' ');
      if (text.trim()) stack[stack.length - 1].text += text;
      continue;
    }
    if (m[1]) {
      if (stack.length > 1) stack.pop();
      continue;
    }
    const node = { name: m[2], attrs: parseAttrs(m[3]), children: [], text: '' };
    stack[stack.length - 1].children.push(node);
    if (!m[4]) stack.push(node);
  }
  return root;
}

function childrenOf(node, name) {
  return (node?.children || []).filter((child) => localName(child.name) === name);
}

function childOf(node, name) {
  return childrenOf(node, name)[0] || null;
}

function deepFind(node, name, acc = []) {
  if (!node) return acc;
  if (localName(node.name) === name) acc.push(node);
  for (const child of node.children || []) deepFind(child, name, acc);
  return acc;
}

function textOf(node) {
  if (!node) return '';
  const own = String(node.text || '').trim();
  if (own) return decodeXml(own);
  return decodeXml((node.children || []).map(textOf).join('').trim());
}

function decodeXml(value) {
  return String(value || '')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, '&');
}

function identifierOf(node) {
  return textOf(childOf(node, 'Identifier')) || textOf(childOf(node, 'identifier'));
}

function titleOf(node, fallback = '') {
  return textOf(childOf(node, 'Title')) || textOf(childOf(node, 'title')) || fallback;
}

export function leafletZoomFromScale(scaleDenominator) {
  const scale = Number(scaleDenominator);
  if (!Number.isFinite(scale) || scale <= 0) return null;
  return Math.round(Math.log2(WMTS_Z0_SCALE / scale));
}

function matrixNumericId(id) {
  const match = String(id || '').match(/(\d+)\s*$/);
  return match ? Number(match[1]) : NaN;
}

function tileMatrixPlaceholder(matrices) {
  if (!matrices.length) return '{z}';
  if (matrices.every((item) => /^\d+$/.test(String(item.id)))) return '{z}';
  const first = String(matrices[0].id);
  const match = first.match(/^(.*?)(\d+)$/);
  if (!match) return '{TileMatrix}';
  const prefix = match[1];
  const ok = matrices.every((item) => {
    const n = Number.isFinite(item.leafletZoom) ? item.leafletZoom : matrixNumericId(item.id);
    const trailing = matrixNumericId(item.id);
    return String(item.id) === `${prefix}${n}` || String(item.id) === `${prefix}${trailing}`;
  });
  return ok ? `${prefix}{z}` : '{TileMatrix}';
}

function classifyCrs(crs, matrixSetId) {
  const id = String(matrixSetId || '');
  const c = String(crs || '');
  if (/GoogleMapsCompatible/i.test(id) || /3857|900913/i.test(c)) return 'EPSG:3857';
  if (/GoogleCRS84Quad/i.test(id) || /4326|CRS:84|OGC:2:84/i.test(c) || /WGS.?84/i.test(c)) return 'EPSG:4326';
  if (/default028mm/i.test(id)) return /4326|CRS:84/i.test(c) ? 'EPSG:4326' : 'EPSG:3857';
  return (c.replace(/^urn:ogc:def:crs:/i, '') || 'unknown');
}

function leafletZoomFromMatrixWidth(crs, matrixWidth) {
  const w = Number(matrixWidth);
  if (!Number.isFinite(w) || w < 1) return null;
  if (crs === 'EPSG:4326') return Math.max(0, Math.round(Math.log2(w) - 1));
  return Math.max(0, Math.round(Math.log2(w)));
}

export function resolveWmtsCapabilitiesUrl(raw, serviceRoot = '') {
  let url = String(raw || '').trim() || String(serviceRoot || '').trim();
  if (!url) return '';
  url = url.replace(/^http:\/\//i, 'https://');
  if (/request=GetCapabilities/i.test(url) || /WMTSCapabilities\.xml/i.test(url)) return url;

  url = url.replace(/\/tile\/\{[^}]+\}.*$/i, '');
  url = url.replace(/\/WMTS\/tile\/.*$/i, '');
  url = url.replace(/\/+$/, '');

  if (/\/WMTS\/1\.0\.0$/i.test(url)) return `${url}/WMTSCapabilities.xml`;
  if (/\/WMTS$/i.test(url)) return `${url}/1.0.0/WMTSCapabilities.xml`;
  if (/\/(ImageServer|MapServer)$/i.test(url)) return `${url}/WMTS/1.0.0/WMTSCapabilities.xml`;

  try {
    const parsed = new URL(url);
    parsed.searchParams.set('SERVICE', 'WMTS');
    parsed.searchParams.set('REQUEST', 'GetCapabilities');
    parsed.searchParams.set('VERSION', '1.0.0');
    return parsed.toString();
  } catch {
    return url;
  }
}

function imageServerRootFromUrl(url) {
  const match = String(url || '').match(
    /^(https?:\/\/[^/]+\/arcgis\/rest\/services\/[^/]+\/[^/]+\/(?:ImageServer|MapServer))/i,
  );
  return match ? match[1].replace(/^http:\/\//i, 'https://') : '';
}

function synthesizeResourceTemplate(capabilitiesUrl, layerId) {
  const root = imageServerRootFromUrl(capabilitiesUrl);
  if (root) {
    return `${root}/WMTS/tile/1.0.0/{Style}/{TileMatrixSet}/{TileMatrix}/{TileRow}/{TileCol}`;
  }
  try {
    const parsed = new URL(capabilitiesUrl);
    parsed.search = '';
    parsed.pathname = parsed.pathname.replace(/\/WMTS\/.*$/i, '').replace(/\/WMTSCapabilities\.xml$/i, '');
    const base = parsed.toString().replace(/\/+$/, '');
    return `${base}?SERVICE=WMTS&REQUEST=GetTile&VERSION=1.0.0&LAYER=${encodeURIComponent(layerId || '')}&STYLE={Style}&TILEMATRIXSET={TileMatrixSet}&TILEMATRIX={TileMatrix}&TILEROW={TileRow}&TILECOL={TileCol}&FORMAT={Format}`;
  } catch {
    return '';
  }
}

function buildTileTemplate(resourceTemplate, layer, matrixSet, styleId, format) {
  let template = String(resourceTemplate || '');
  if (!template) return '';
  const style = styleId || layer.defaultStyle || 'default';
  const fmt = format || layer.formats[0] || 'image/png';
  template = template
    .replaceAll('{Style}', style)
    .replaceAll('{style}', style)
    .replaceAll('{TileMatrixSet}', matrixSet.id)
    .replaceAll('{tileMatrixSet}', matrixSet.id)
    .replaceAll('{Layer}', layer.id)
    .replaceAll('{layer}', layer.id)
    .replaceAll('{Format}', fmt)
    .replaceAll('{format}', fmt)
    .replaceAll('{TileRow}', '{y}')
    .replaceAll('{TileCol}', '{x}')
    .replaceAll('{tileRow}', '{y}')
    .replaceAll('{tileCol}', '{x}');
  if (matrixSet.tileMatrixPlaceholder && matrixSet.tileMatrixPlaceholder !== '{TileMatrix}') {
    template = template.replaceAll('{TileMatrix}', matrixSet.tileMatrixPlaceholder)
      .replaceAll('{tileMatrix}', matrixSet.tileMatrixPlaceholder);
  } else if (matrixSet.numericIds) {
    template = template.replaceAll('{TileMatrix}', '{z}').replaceAll('{tileMatrix}', '{z}');
  }
  return template;
}

export function parseWmtsCapabilities(xml, capabilitiesUrl = '') {
  const tree = parseXml(xml);
  const capabilities = deepFind(tree, 'Capabilities')[0] || tree;
  const contents = childOf(capabilities, 'Contents') || deepFind(capabilities, 'Contents')[0];
  if (!contents) {
    return { ok: false, error: 'NO_CONTENTS', message: 'В WMTSCapabilities.xml нет раздела Contents' };
  }

  const serviceId = childOf(capabilities, 'ServiceIdentification') || childOf(capabilities, 'ServiceProvider');
  const serviceTitle = titleOf(serviceId, '') || titleOf(capabilities, '');

  const tileMatrixSets = childrenOf(contents, 'TileMatrixSet').map((node) => {
    const id = identifierOf(node);
    const crs = textOf(childOf(node, 'SupportedCRS')) || textOf(childOf(node, 'supportedCRS'));
    const classified = classifyCrs(crs, id);
    const matrices = childrenOf(node, 'TileMatrix').map((matrixNode) => {
      const matrixId = identifierOf(matrixNode);
      const scaleDenominator = Number(textOf(childOf(matrixNode, 'ScaleDenominator')));
      const tileWidth = Number(textOf(childOf(matrixNode, 'TileWidth'))) || 256;
      const matrixWidth = Number(textOf(childOf(matrixNode, 'MatrixWidth')));
      const matrixHeight = Number(textOf(childOf(matrixNode, 'MatrixHeight')));
      const fromSize = leafletZoomFromMatrixWidth(classified, matrixWidth);
      return {
        id: matrixId,
        scaleDenominator: Number.isFinite(scaleDenominator) ? scaleDenominator : null,
        leafletZoom: fromSize != null ? fromSize : leafletZoomFromScale(scaleDenominator),
        tileWidth,
        matrixWidth: Number.isFinite(matrixWidth) ? matrixWidth : null,
        matrixHeight: Number.isFinite(matrixHeight) ? matrixHeight : null,
      };
    }).filter((item) => item.id);
    const numericIds = matrices.length > 0 && matrices.every((item) => /^\d+$/.test(String(item.id)));
    const placeholder = tileMatrixPlaceholder(matrices);
    const first = matrices[0];
    const firstServiceZ = first ? matrixNumericId(first.id) : 0;
    const firstLeafletZ = first?.leafletZoom;
    const zoomOffset = Number.isFinite(firstServiceZ) && firstLeafletZ != null
      ? firstServiceZ - firstLeafletZ
      : 0;
    const leafletZooms = matrices.map((item) => item.leafletZoom).filter((z) => z != null);
    const wellKnown = /GoogleMapsCompatible/i.test(id)
      ? 'GoogleMapsCompatible'
      : /GoogleCRS84Quad/i.test(id)
        ? 'GoogleCRS84Quad'
        : /default028mm/i.test(id)
          ? 'default028mm'
          : null;
    return {
      id,
      crs: classified,
      supportedCrs: crs,
      wellKnown,
      supported: classified === 'EPSG:3857' || classified === 'EPSG:4326',
      mapCrs: classified === 'EPSG:4326' ? 'EPSG:4326' : (classified === 'EPSG:3857' ? 'EPSG:3857' : null),
      numericIds,
      tileMatrixPlaceholder: placeholder,
      zoomOffset,
      minNativeZoom: leafletZooms.length ? Math.min(...leafletZooms) : 0,
      maxNativeZoom: leafletZooms.length ? Math.max(...leafletZooms) : 19,
      tileSize: first?.tileWidth || 256,
      matrixCount: matrices.length,
      matrices,
    };
  }).filter((item) => item.id);

  const layers = childrenOf(contents, 'Layer').map((node) => {
    const id = identifierOf(node);
    const styles = childrenOf(node, 'Style').map((styleNode) => ({
      id: identifierOf(styleNode),
      title: titleOf(styleNode, identifierOf(styleNode)),
      isDefault: String(styleNode.attrs.isDefault || styleNode.attrs.default || '').toLowerCase() === 'true',
    })).filter((item) => item.id);
    const formats = childrenOf(node, 'Format').map((item) => textOf(item)).filter(Boolean);
    const tileMatrixSetIds = childrenOf(node, 'TileMatrixSetLink')
      .map((link) => textOf(childOf(link, 'TileMatrixSet')))
      .filter(Boolean);
    const resourceUrls = childrenOf(node, 'ResourceURL')
      .concat(deepFind(node, 'ResourceURL'))
      .filter((item, index, all) => all.indexOf(item) === index)
      .map((item) => ({
        format: item.attrs.format || '',
        resourceType: item.attrs.resourceType || item.attrs.resourcetype || 'tile',
        template: item.attrs.template || '',
      }))
      .filter((item) => item.template);
    const defaultStyle = styles.find((item) => item.isDefault)?.id || styles[0]?.id || 'default';
    const fallbackTemplate = synthesizeResourceTemplate(capabilitiesUrl, id);
    return {
      id,
      title: titleOf(node, id),
      styles,
      defaultStyle,
      formats,
      tileMatrixSetIds,
      resourceUrls,
      fallbackTemplate,
    };
  }).filter((item) => item.id);

  return {
    ok: true,
    capabilitiesUrl,
    serviceTitle,
    layers,
    tileMatrixSets,
  };
}

export function buildWmtsRestUrl(layer, matrixSet, styleId, format) {
  if (!layer || !matrixSet) return '';
  const wantedFormat = format || layer.formats.find((item) => /png/i.test(item)) || layer.formats[0] || 'image/png';
  const resource = layer.resourceUrls.find((item) => item.resourceType === 'tile' && item.format === wantedFormat)
    || layer.resourceUrls.find((item) => item.resourceType === 'tile')
    || layer.resourceUrls[0];
  return buildTileTemplate(resource?.template || layer.fallbackTemplate, layer, matrixSet, styleId, wantedFormat);
}

export function pickSuggestedWmts(parsed, opts = {}) {
  const preferNotGmc = !!opts.preferNotGoogleMapsCompatible;
  const layers = parsed.layers || [];
  const sets = parsed.tileMatrixSets || [];
  const setById = new Map(sets.map((item) => [item.id, item]));
  const layer = layers[0];
  if (!layer) return null;
  const linked = layer.tileMatrixSetIds.map((id) => setById.get(id)).filter(Boolean);
  const mercator = linked.filter((item) => item.crs === 'EPSG:3857');
  const geographic = linked.filter((item) => item.crs === 'EPSG:4326');
  const usable = mercator.length ? mercator : geographic;
  const gmc = usable.find((item) => item.wellKnown === 'GoogleMapsCompatible');
  const notGmc = usable.find((item) => item.wellKnown !== 'GoogleMapsCompatible') || usable[0];
  const matrixSet = preferNotGmc ? (notGmc || gmc) : (gmc || notGmc);
  if (!matrixSet) {
    return {
      layerId: layer.id,
      matrixSetId: layer.tileMatrixSetIds[0] || '',
      styleId: layer.defaultStyle,
      tileUrl: '',
      zoomOffset: 0,
      minNativeZoom: 0,
      maxNativeZoom: 19,
      crs: '',
      warning: 'Нет матрицы EPSG:3857 или EPSG:4326',
    };
  }
  const tileUrl = buildWmtsRestUrl(layer, matrixSet, layer.defaultStyle);
  let warning = '';
  if (matrixSet.crs === 'EPSG:4326') {
    warning = 'Матрица в градусах (EPSG:4326): карта переключится из Web Mercator.';
  }
  if (preferNotGmc && gmc && matrixSet !== gmc) {
    warning = 'Матрица GoogleMapsCompatible есть в capabilities, но у dzz.by её нет (ответ 520). Выбран запасной набор.';
  } else if (matrixSet.wellKnown === 'GoogleMapsCompatible' && preferNotGmc) {
    warning = 'Матрица GoogleMapsCompatible у dzz.by отвечает 520 — слоя нет.';
  }
  return {
    layerId: layer.id,
    matrixSetId: matrixSet.id,
    styleId: layer.defaultStyle,
    tileUrl,
    zoomOffset: matrixSet.zoomOffset,
    minNativeZoom: matrixSet.minNativeZoom,
    maxNativeZoom: matrixSet.maxNativeZoom,
    numericIds: matrixSet.numericIds,
    wellKnown: matrixSet.wellKnown,
    crs: matrixSet.crs,
    warning,
  };
}

export function isBlockedWmtsHost(hostname) {
  const host = String(hostname || '').toLowerCase().replace(/\.+$/, '');
  if (!host) return true;
  if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local')) return true;
  if (host === '::1' || host === '[::1]') return true;
  if (/^(127|10|0)\./.test(host)) return true;
  if (/^192\.168\./.test(host)) return true;
  if (/^169\.254\./.test(host)) return true;
  if (/^172\.(1[6-9]|2\d|3[0-1])\./.test(host)) return true;
  return false;
}

export function fillWmtsSampleTileUrl(template, zoomOffset = 0) {
  const z = Math.max(0, 8 + Number(zoomOffset || 0));
  return String(template || '')
    .replaceAll('{z}', String(z))
    .replaceAll('{x}', '0')
    .replaceAll('{y}', '0')
    .replaceAll('{TileMatrix}', String(z))
    .replaceAll('{TileRow}', '0')
    .replaceAll('{TileCol}', '0');
}
