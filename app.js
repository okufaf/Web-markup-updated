/* =========================================================
   АВТОРИЗАЦИЯ
   Сначала сервер (/api/*). Если сервер недоступен — локальный
   режим в localStorage (для работы только с фронтом).
   ========================================================= */
const LS_AVATAR_PREFIX = 'ttz_avatar_';   // dataURL аватарки по email (только UI)
const LS_ACCOUNTS = 'av_local_accounts';
const LS_SESSION = 'av_local_session';
let currentUser = null;
let authMode = 'local'; // Live Server / index → local; Node API → server
let apiAvailable = null; // null = ещё не проверяли

const ICON_PLUS = `<svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" stroke-width="2.2" fill="none"><path d="M12 5v14M5 12h14"/></svg>`;
const ICON_FOLDER = `<svg viewBox="0 0 24 24" width="15" height="15" stroke="currentColor" stroke-width="2" fill="none"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>`;
const ICON_FOLDER_OUT = `<svg viewBox="0 0 24 24" width="12" height="12" stroke="currentColor" stroke-width="2" fill="none"><path d="M9 14l-4-4 4-4"/><path d="M5 10h11a4 4 0 0 1 0 8h-1"/></svg>`;

function isNetworkAuthError(err) {
    return !err?.status && (err?.name === 'TypeError' || /fetch|network|failed/i.test(String(err?.message || '')));
}

/** Сервер недоступен / это не наш API (Live Server, file://, 404) → локальный режим */
function shouldUseLocalAuth(err) {
    if (!err) return true;
    const business = new Set([
        'EMAIL_EXISTS', 'WEAK_PASSWORD', 'INVALID_CREDENTIALS',
        'INVALID_EMAIL', 'INVALID_PROFILE', 'UNAUTHORIZED',
    ]);
    if (business.has(err.code)) return false;
    if (isNetworkAuthError(err)) return true;
    if (!err.status || err.status === 404 || err.status === 405 || err.status >= 500) return true;
    if (err.status && !business.has(err.code) && err.code === 'REQUEST_FAILED') return true;
    return !err.code || err.message === 'REQUEST_FAILED';
}

/** Live Server и открытие index.html не дают /api — работаем только локально */
async function ensureAuthBackend() {
    if (apiAvailable !== null) return apiAvailable;
    if (location.protocol === 'file:') {
        apiAvailable = false;
        authMode = 'local';
        return false;
    }
    try {
        const res = await fetch('/api/me', {
            method: 'GET',
            credentials: 'include',
            headers: { Accept: 'application/json' },
        });
        const ct = (res.headers.get('content-type') || '').toLowerCase();
        if (!ct.includes('application/json')) {
            apiAvailable = false;
            authMode = 'local';
            return false;
        }
        const data = await res.json().catch(() => null);
        // наш API: { user } или { error: 'UNAUTHORIZED' }
        apiAvailable = !!(data && (data.user || data.error));
    } catch {
        apiAvailable = false;
    }
    if (!apiAvailable) authMode = 'local';
    return apiAvailable;
}

function publicLocalUser(row) {
    return {
        email: row.email,
        firstName: row.firstName,
        lastName: row.lastName,
        organization: row.organization,
        role: row.role,
        lastLogin: row.lastLogin || null,
    };
}

function readLocalAccounts() {
    try {
        const raw = JSON.parse(localStorage.getItem(LS_ACCOUNTS) || '{"users":[]}');
        return Array.isArray(raw.users) ? raw.users : [];
    } catch {
        return [];
    }
}

function writeLocalAccounts(users) {
    localStorage.setItem(LS_ACCOUNTS, JSON.stringify({ users }));
}

async function hashPassword(password) {
    const text = String(password);
    if (globalThis.crypto?.subtle) {
        const data = new TextEncoder().encode(text);
        const digest = await crypto.subtle.digest('SHA-256', data);
        return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, '0')).join('');
    }
    // fallback для file:// (нет Web Crypto)
    let hash = 2166136261;
    for (let i = 0; i < text.length; i++) {
        hash ^= text.charCodeAt(i);
        hash = Math.imul(hash, 16777619);
    }
    return 'fnv_' + (hash >>> 0).toString(16);
}

function setLocalSession(email, remember) {
    const payload = JSON.stringify({ email, ts: Date.now() });
    if (remember) {
        localStorage.setItem(LS_SESSION, payload);
        sessionStorage.removeItem(LS_SESSION);
    } else {
        sessionStorage.setItem(LS_SESSION, payload);
        localStorage.removeItem(LS_SESSION);
    }
}

function clearLocalSession() {
    localStorage.removeItem(LS_SESSION);
    sessionStorage.removeItem(LS_SESSION);
}

function readLocalSessionEmail() {
    try {
        const raw = localStorage.getItem(LS_SESSION) || sessionStorage.getItem(LS_SESSION);
        if (!raw) return null;
        const parsed = JSON.parse(raw);
        return parsed?.email || null;
    } catch {
        return null;
    }
}

async function localRegister({ firstName, lastName, email, organization, role, password }) {
    const users = readLocalAccounts();
    if (users.some((u) => u.email === email)) {
        const err = new Error('EMAIL_EXISTS');
        err.code = 'EMAIL_EXISTS';
        err.status = 409;
        throw err;
    }
    const passwordHash = await hashPassword(password);
    const user = {
        email,
        firstName,
        lastName,
        organization,
        role,
        passwordHash,
        lastLogin: new Date().toLocaleString('ru-RU'),
    };
    users.push(user);
    writeLocalAccounts(users);
    setLocalSession(email, true);
    authMode = 'local';
    return { user: publicLocalUser(user) };
}

async function localLogin({ email, password, remember }) {
    const users = readLocalAccounts();
    const user = users.find((u) => u.email === email);
    if (!user) {
        const err = new Error('INVALID_CREDENTIALS');
        err.code = 'INVALID_CREDENTIALS';
        err.status = 401;
        throw err;
    }
    const passwordHash = await hashPassword(password);
    if (user.passwordHash !== passwordHash) {
        const err = new Error('INVALID_CREDENTIALS');
        err.code = 'INVALID_CREDENTIALS';
        err.status = 401;
        throw err;
    }
    user.lastLogin = new Date().toLocaleString('ru-RU');
    writeLocalAccounts(users);
    setLocalSession(email, !!remember);
    authMode = 'local';
    return { user: publicLocalUser(user) };
}

function localRestoreSession() {
    const email = readLocalSessionEmail();
    if (!email) return null;
    const user = readLocalAccounts().find((u) => u.email === email);
    if (!user) {
        clearLocalSession();
        return null;
    }
    authMode = 'local';
    return publicLocalUser(user);
}

async function localSaveProfile(patch) {
    const users = readLocalAccounts();
    const idx = users.findIndex((u) => u.email === currentUser?.email);
    if (idx === -1) throw new Error('UNAUTHORIZED');
    const user = users[idx];
    if (typeof patch.firstName === 'string') user.firstName = patch.firstName.trim();
    if (typeof patch.lastName === 'string') user.lastName = patch.lastName.trim();
    if (typeof patch.organization === 'string') user.organization = patch.organization.trim();
    if (typeof patch.role === 'string') user.role = patch.role.trim();
    if (patch.newPassword) user.passwordHash = await hashPassword(patch.newPassword);
    users[idx] = user;
    writeLocalAccounts(users);
    return { user: publicLocalUser(user) };
}

function localDeleteAccount(email) {
    writeLocalAccounts(readLocalAccounts().filter((u) => u.email !== email));
    clearLocalSession();
}

async function apiFetch(url, options = {}) {
    const res = await fetch(url, {
        credentials: 'include',
        headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
        ...options,
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
        const err = new Error(data.message || data.error || 'REQUEST_FAILED');
        err.status = res.status;
        err.code = data.error;
        throw err;
    }
    return data;
}

function getCurrentEmail() {
    return currentUser?.email || null;
}

function historyKey(email) { return 'ttz_history_' + email; }
function getHistory(email) {
    return JSON.parse(localStorage.getItem(historyKey(email)) || '[]');
}
function logAction(type, text, meta = {}) {
    const email = getCurrentEmail();
    if (!email) return;
    const list = getHistory(email);
    list.unshift({ type, text, date: new Date().toLocaleString('ru-RU'), ts: Date.now(), ...meta });
    localStorage.setItem(historyKey(email), JSON.stringify(list.slice(0, 400)));
    const accountView = document.getElementById('view-account');
    if (accountView && accountView.style.display !== 'none') {
        renderHistoryFeed();
        renderAccountStats();
    }
}

function validatePassword(password) {
    if (!password || password.length < 8) return 'Пароль должен содержать минимум 8 символов.';
    if (!/[a-zа-яё]/.test(password)) return 'Пароль должен содержать строчную букву.';
    if (!/[A-ZА-ЯЁ]/.test(password)) return 'Пароль должен содержать заглавную букву.';
    if (!/[^a-zA-Zа-яА-ЯёЁ0-9]/.test(password)) return 'Пароль должен содержать спецсимвол.';
    return null;
}

const ICON_EYE = `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>`;
const ICON_EYE_OFF = `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>`;

function togglePasswordVisibility(btn) {
    const field = btn.closest('.password-field');
    const input = field?.querySelector('input');
    if (!input) return;
    const show = input.type === 'password';
    input.type = show ? 'text' : 'password';
    field.classList.toggle('is-visible', show);
    btn.setAttribute('aria-label', show ? 'Скрыть пароль' : 'Показать пароль');
    btn.setAttribute('title', show ? 'Скрыть пароль' : 'Показать пароль');
    btn.innerHTML = show ? ICON_EYE_OFF : ICON_EYE;
}

function initPasswordToggles() {
    document.querySelectorAll('.password-field').forEach(field => {
        const btn = field.querySelector('.password-toggle');
        const input = field.querySelector('input');
        if (!btn || !input || btn.dataset.bound) return;
        btn.dataset.bound = '1';
        btn.innerHTML = ICON_EYE;
        btn.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            togglePasswordVisibility(btn);
            input.focus({ preventScroll: true });
        });
    });
}

function processedKey() { return 'ttz_processed_' + getCurrentEmail(); }
function getProcessedFiles() {
    return JSON.parse(localStorage.getItem(processedKey()) || '[]');
}
function saveProcessedFile(record) {
    const email = getCurrentEmail();
    if (!email) return;
    const list = getProcessedFiles();
    list.unshift(record);
    localStorage.setItem(processedKey(), JSON.stringify(list.slice(0, 50)));
}
async function storeProcessedUpload(file, processId) {
    const id = processId || ('proc_' + Date.now());
    const meta = {
        id, name: file.name,
        date: new Date().toLocaleString('ru-RU'),
        mime: file.type || 'application/octet-stream',
        hasData: true,
    };
    try {
        const db = await openProcDB();
        const buf = await file.arrayBuffer();
        await idbPut(db, { id, kind: 'original', name: file.name, mime: meta.mime, date: meta.date, data: buf });
    } catch {
        meta.hasData = false;
        meta.stub = true;
    }
    saveProcessedFile(meta);
    return id;
}
function idbPut(db, record) {
    return new Promise((resolve, reject) => {
        const tx = db.transaction('files', 'readwrite');
        tx.objectStore('files').put(record);
        tx.oncomplete = resolve;
        tx.onerror = () => reject(tx.error);
    });
}
function idbGet(db, id) {
    return new Promise((resolve, reject) => {
        const tx = db.transaction('files', 'readonly');
        const r = tx.objectStore('files').get(id);
        r.onsuccess = () => resolve(r.result);
        r.onerror = () => reject(r.error);
    });
}
async function storeProcessedResult(processId, sourceFileName) {
    const geojson = collectAllFeaturesAsGeoJSON();
    const resultName = sourceFileName.replace(/\.[^.]+$/, '') + '_обработан.geojson';
    const text = JSON.stringify(geojson, null, 2);
    const buf = new TextEncoder().encode(text);
    try {
        const db = await openProcDB();
        await idbPut(db, {
            id: processId + '_result',
            parentId: processId,
            kind: 'result',
            name: resultName,
            mime: 'application/geo+json',
            date: new Date().toLocaleString('ru-RU'),
            data: buf,
        });
        const list = getProcessedFiles();
        const rec = list.find(f => f.id === processId);
        if (rec) {
            rec.hasResult = true;
            rec.resultName = resultName;
            localStorage.setItem(processedKey(), JSON.stringify(list.slice(0, 50)));
        }
    } catch { /* ignore */ }
}
function openProcDB() {
    return new Promise((resolve, reject) => {
        const req = indexedDB.open('ttz_processed_db', 1);
        req.onupgradeneeded = () => req.result.createObjectStore('files', { keyPath: 'id' });
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
    });
}
async function downloadProcessedFile(id) {
    try {
        const db = await openProcDB();
        const rec = await idbGet(db, id + '_result');
        if (rec?.data) {
            downloadBlob(new Blob([rec.data], { type: rec.mime || 'application/geo+json' }), rec.name);
            return;
        }
    } catch { /* fallback */ }
    const meta = getProcessedFiles().find(f => f.id === id);
    if (!meta) { alert('Файл не найден в истории загрузок.'); return; }
    alert('Обработанный результат для этого снимка не сохранён. Повторите обработку снимка.');
}

async function openProcessedFile(id) {
    if (!mapInitialized) {
        initMap();
        loadFoldersState();
        mapInitialized = true;
    }
    const hasObjects = layersRegistry.some(e => e.group.getLayers().length > 0);
    if (hasObjects) {
        const ok = confirm('Открыть файл на карте? Все несохранённые изменения в рабочей области будут удалены.');
        if (!ok) return;
    }
    try {
        const db = await openProcDB();
        const rec = await idbGet(db, id + '_result');
        if (!rec?.data) { alert('Обработанный файл не найден. Повторите обработку снимка.'); return; }
        const geojson = JSON.parse(new TextDecoder().decode(rec.data));
        clearMapWorkspace({ keepFolders: true });
        loadGeoJSONResults(geojson);
        switchMainTab('map');
        switchSidebar('layers');
        showToast('Файл открыт в рабочей области карты');
        logAction('process', `Открыт обработанный файл на карте`);
    } catch (e) {
        console.error(e);
        alert('Не удалось открыть обработанный файл.');
    }
}

function clearMapWorkspace({ keepFolders = false } = {}) {
    clearSelection();
    hideFieldDetail();
    clearVertexMarkers();
    discardCreateDraft();
    createSessionActive = false;
    undoStack = [];
    redoStack = [];
    if (overlaysLayerGroup) overlaysLayerGroup.clearLayers();
    if (textLayerGroup) textLayerGroup.clearLayers();
    if (fieldLabelsLayerGroup) fieldLabelsLayerGroup.clearLayers();

    layersRegistry.forEach(entry => {
        entry.group.clearLayers();
        if (map?.hasLayer(entry.group)) map.removeLayer(entry.group);
    });
    layersRegistry = [];
    DEFAULT_LAYERS.forEach(l => addLayer(l.id, l.name, l.color, []));
    if (!keepFolders) foldersRegistry = [];
    analysisComplete = false;
    activeLayerId = 'points';
    expandedLayers = new Set(['points', 'crops']);
    renderFoldersList();
    renderLayersList(document.getElementById('layer-search')?.value);
    renderLegend();
    renderFieldLabels();
    populateDrawLayerSelect();
}

function resolveLayerEntryForImport(props, index) {
    const layerId = props?.layerId;
    const layerName = props?.layer || 'Результат обработки';
    if (layerId) {
        const byId = findLayerEntry(layerId);
        if (byId) return byId;
    }
    const byName = layersRegistry.find(l => l.name === layerName);
    if (byName) return byName;
    const std = DEFAULT_LAYERS.find(l => l.name === layerName || l.id === layerId);
    if (std) {
        const entry = findLayerEntry(std.id);
        if (entry) return entry;
    }
    const id = 'imported_' + Date.now() + '_' + index;
    const color = props?.color || '#3388ff';
    const group = L.featureGroup().addTo(map);
    const entry = { id, name: layerName, color, group, visible: true, folderId: props?.folderId || null, detected: true };
    layersRegistry.push(entry);
    return entry;
}

function loadGeoJSONResults(geojson) {
    if (!geojson?.features?.length || !map) return;
    const bounds = [];
    if (Array.isArray(geojson.folders) && geojson.folders.length) {
        foldersRegistry = geojson.folders.map(f => ({
            id: f.id,
            name: f.name,
            visible: f.visible !== false,
            collapsed: !!f.collapsed,
        }));
    }
    geojson.features.forEach((feature, i) => {
        const props = feature.properties || {};
        const entry = resolveLayerEntryForImport(props, i);
        entry.detected = true;
        const layerId = entry.id;
        L.geoJSON(feature, {
            style: {
                color: entry.color,
                weight: displaySettings.lineWidth,
                fillColor: entry.color,
                fillOpacity: (props.isPointObject || layerId === 'points') ? 0.55 : 0.35,
            },
            onEachFeature: (f, layer) => {
                initFieldMeta(layer, layerId);
                const meta = layer._fieldMeta;
                if (props.name) meta.name = props.name;
                if (props.objectNumber != null) meta.objectNumber = props.objectNumber;
                if (Array.isArray(props.crops)) meta.crops = props.crops;
                else if (!layerSupportsCrop(layerId)) meta.crops = [];
                if (props.confirmedCrop !== undefined) meta.confirmedCrop = props.confirmedCrop;
                if (props.confirmed != null) meta.confirmed = !!props.confirmed;
                if (props.source) meta.source = props.source;
                if (props.source === 'manual') meta.crops = [];
                if (props.objectFolderId) meta.objectFolderId = props.objectFolderId;
                if (props.isPointObject || layerId === 'points') layer._isPointObject = true;
                bindFeatureEvents(layer, layerId);
                layer.addTo(entry.group);
                const b = layer.getBounds?.();
                if (b?.isValid()) bounds.push(b);
            },
        });
    });
    analysisComplete = true;
    if (bounds.length) {
        const combined = bounds.reduce((acc, b) => acc.extend(b), L.latLngBounds(bounds[0]));
        map.fitBounds(combined, { maxZoom: 16, padding: [40, 40] });
    }
    saveFoldersState();
    renderLayersList(document.getElementById('layer-search')?.value);
    renderLegend();
    renderFieldLabels();
    populateDrawLayerSelect();
}

function statsKey() { return 'ttz_stats_' + getCurrentEmail(); }
function getStats() {
    return JSON.parse(localStorage.getItem(statsKey()) || '{"exports":0,"processed":0}');
}
function incStat(name) {
    const email = getCurrentEmail();
    if (!email) return;
    const s = getStats();
    s[name] = (s[name] || 0) + 1;
    localStorage.setItem(statsKey(), JSON.stringify(s));
    renderAccountStats();
}
function renderAccountStats() {
    const s = getStats();
    const exp = document.getElementById('stat-exports');
    const proc = document.getElementById('stat-processed');
    if (exp) exp.innerText = s.exports || 0;
    if (proc) proc.innerText = s.processed || 0;
}

const BUILTIN_CROP_LABELS = {
    soybean: 'Соя', sugar_beet: 'Сахарная свёкла', barley: 'Ячмень', rapeseed: 'Рапс',
    oat: 'Овёс', corn: 'Кукуруза', rice: 'Рис', wheat: 'Пшеница', sunflower: 'Подсолнечник', potato: 'Картофель',
};
/** @deprecated use getCropLabel / getAllCropOptions — kept as live merge for old code paths */
let CROP_LABELS = { ...BUILTIN_CROP_LABELS };
let CROP_KEYS = Object.keys(CROP_LABELS);

function customCropsKey() { return 'ttz_custom_crops_' + (getCurrentEmail() || 'anon'); }
function getCustomCrops() {
    try { return JSON.parse(localStorage.getItem(customCropsKey()) || '{}') || {}; }
    catch { return {}; }
}
function saveCustomCrops(map) {
    localStorage.setItem(customCropsKey(), JSON.stringify(map || {}));
    refreshCropCaches();
}
function refreshCropCaches() {
    CROP_LABELS = { ...BUILTIN_CROP_LABELS, ...getCustomCrops() };
    CROP_KEYS = Object.keys(CROP_LABELS);
}
function getCropLabel(key) {
    if (!key) return '';
    return BUILTIN_CROP_LABELS[key] || getCustomCrops()[key] || CROP_LABELS[key] || key;
}
const CROP_STAR_SVG = `<span class="crop-star" title="Своя культура" aria-label="своя культура"><svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M12 3L13.4302 8.31181C13.6047 8.96 13.692 9.28409 13.8642 9.54905C14.0166 9.78349 14.2165 9.98336 14.451 10.1358C14.7159 10.308 15.04 10.3953 15.6882 10.5698L21 12L15.6882 13.4302C15.04 13.6047 14.7159 13.692 14.451 13.8642C14.2165 14.0166 14.0166 14.2165 13.8642 14.451C13.692 14.7159 13.6047 15.04 13.4302 15.6882L12 21L10.5698 15.6882C10.3953 15.04 10.308 14.7159 10.1358 14.451C9.98336 14.2165 9.78349 14.0166 9.54905 13.8642C9.28409 13.692 8.96 13.6047 8.31181 13.4302L3 12L8.31181 10.5698C8.96 10.3953 9.28409 10.308 9.54905 10.1358C9.78349 9.98336 9.98336 9.78349 10.1358 9.54905C10.308 9.28409 10.3953 8.96 10.5698 8.31181L12 3Z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg></span>`;
function formatCropOptionLabel(key, label, custom) {
    const name = label || getCropLabel(key);
    // в <option> SVG не рендерится — звёздочка Unicode
    return custom ? `${name} ✦` : name;
}
function formatCropDisplay(key) {
    if (!key) return '';
    const name = getCropLabel(key);
    return isCustomCropKey(key) ? `${name}${CROP_STAR_SVG}` : name;
}
function getAllCropOptions() {
    refreshCropCaches();
    const list = Object.entries(BUILTIN_CROP_LABELS).map(([key, label]) => ({ key, label, custom: false }));
    Object.entries(getCustomCrops()).forEach(([key, label]) => list.push({ key, label, custom: true }));
    return list;
}
function isCustomCropKey(key) {
    return Boolean(key && !BUILTIN_CROP_LABELS[key] && getCustomCrops()[key]);
}
function addCustomCrop(label) {
    const name = String(label || '').trim();
    if (!name) return null;
    const map = getCustomCrops();
    // reuse key if same label exists
    const existing = Object.entries(map).find(([, v]) => v.toLowerCase() === name.toLowerCase());
    if (existing) return existing[0];
    const builtin = Object.entries(BUILTIN_CROP_LABELS).find(([, v]) => v.toLowerCase() === name.toLowerCase());
    if (builtin) return builtin[0];
    const key = 'custom_' + Date.now().toString(36);
    map[key] = name;
    saveCustomCrops(map);
    return key;
}
function deleteCustomCrop(key) {
    if (!isCustomCropKey(key)) return false;
    const map = getCustomCrops();
    delete map[key];
    saveCustomCrops(map);
    return true;
}

function generateCropProbabilities() {
    refreshCropCaches();
    const keys = Object.keys(BUILTIN_CROP_LABELS);
    const raw = keys.map(() => Math.random());
    const sum = raw.reduce((a, b) => a + b, 0);
    return keys.map((key, i) => ({ key, pct: (raw[i] / sum) * 100 }))
        .sort((a, b) => b.pct - a.pct);
}

function getTopCrop(meta) {
    if (meta?.confirmedCrop) {
        const pct = meta.crops?.find(c => c.key === meta.confirmedCrop)?.pct;
        return { key: meta.confirmedCrop, pct: pct != null ? pct : 100 };
    }
    if (!meta?.crops || meta.crops.length === 0) return { key: '', pct: 0 };
    return meta.crops[0];
}

const DZZ_DEFAULT_SERVICE = 'https://www.dzz.by/arcgis/rest/services/georesursDDZ/Polya_all/ImageServer';
const DZZ_DEFAULT_TILE_URL = `${DZZ_DEFAULT_SERVICE}/tile/{z}/{y}/{x}`;

function isLegacyDzzUrl(url) {
    const value = String(url || '').trim();
    if (!value) return true;
    return /dzz\.by\/tiles\//i.test(value) || value === 'https://www.dzz.by/tiles/{z}/{x}/{y}.jpg';
}

function resolveDzzTileTemplate(urlTemplate) {
    let url = String(urlTemplate || '').trim();
    if (!url || isLegacyDzzUrl(url)) url = DZZ_DEFAULT_TILE_URL;

    const isDzzOrArcGis = /dzz\.by/i.test(url) || /\/arcgis\/rest\/services\//i.test(url) || /WMTS|ImageServer|{TileMatrix}/i.test(url);
    if (!isDzzOrArcGis) {
        return { url, zoomOffset: 0, minNativeZoom: 0, maxNativeZoom: 22, maxZoom: 22 };
    }

    url = url.replace(/^http:\/\//i, 'https://');
    const isWmtsTile = /\/WMTS\/tile\//i.test(url) || /request=GetTile/i.test(url);
    if (!isWmtsTile) {
        url = url.replace(/\/WMTS(?:\/1\.0\.0\/WMTSCapabilities\.xml)?\/?$/i, '');
        url = url.replace(/\/+$/, '');
        if (/\/(ImageServer|MapServer)$/i.test(url) && !url.includes('{z}') && !url.includes('{TileMatrix}')) {
            url = `${url}/tile/{z}/{y}/{x}`;
        }
    }

    url = url.replaceAll('{Style}', 'default');
    url = url.replaceAll('{TileMatrixSet}', /GoogleMapsCompatible/i.test(url) ? 'GoogleMapsCompatible' : 'default028mm');
    url = url.replaceAll('{TileMatrix}', '{z}');
    url = url.replaceAll('{TileRow}', '{y}');
    url = url.replaceAll('{TileCol}', '{x}');

    if (/\/(ImageServer|MapServer)\/tile\//i.test(url) && /\{z\}\/\{x\}\/\{y\}/.test(url)) {
        url = url.replace('{z}/{x}/{y}', '{z}/{y}/{x}');
    }

    const isGmc = /GoogleMapsCompatible/i.test(url);
    const usesServiceLevels = !isGmc && (/Polya_all/i.test(url) || /default028mm/i.test(url) || /\/ImageServer\/tile\//i.test(url));
    return {
        url,
        zoomOffset: usesServiceLevels ? -8 : 0,
        minNativeZoom: usesServiceLevels ? 8 : 0,
        maxNativeZoom: isGmc ? 19 : 22,
        maxZoom: 22,
    };
}

/** XYZ/WMTS для пользовательской подложки. EPSG:4326 не получает смещение зума dzz (−8). */
function resolveXyzTileTemplate(urlTemplate) {
    let url = String(urlTemplate || '').trim();
    if (!url) return null;
    url = url.replace(/^http:\/\//i, 'https://');
    url = url.replaceAll('{TileMatrix}', '{z}');
    url = url.replaceAll('{TileRow}', '{y}');
    url = url.replaceAll('{TileCol}', '{x}');
    url = url.replaceAll('{Style}', 'default');
    if (url.includes('{TileMatrixSet}') && /dzz\.by|default028mm|GoogleMapsCompatible|GoogleCRS84Quad/i.test(url)) {
        url = url.replaceAll('{TileMatrixSet}',
            /GoogleMapsCompatible/i.test(url) ? 'GoogleMapsCompatible'
                : /GoogleCRS84Quad/i.test(url) ? 'GoogleCRS84Quad'
                    : 'default028mm');
    }
    if (!url.includes('{z}') && !url.includes('{TileMatrix}')) return null;
    const isArcGisTile = /\/(ImageServer|MapServer)\/tile\//i.test(url);
    if (isArcGisTile && /\{z\}\/\{x\}\/\{y\}/.test(url)) {
        url = url.replace('{z}/{x}/{y}', '{z}/{y}/{x}');
    }
    const is4326 = /GoogleCRS84Quad/i.test(url) || basemapExtra.customCrs === 'EPSG:4326';
    const isGmc = /GoogleMapsCompatible/i.test(url);
    const isDzzPolya = /dzz\.by/i.test(url) && /Polya_all/i.test(url) && !isGmc && !is4326;
    const uses028 = /default028mm/i.test(url) && !is4326;
    const storedOffset = Number.isFinite(basemapExtra.customZoomOffset) ? basemapExtra.customZoomOffset : 0;
    return {
        url,
        zoomOffset: is4326 ? storedOffset : (isDzzPolya || uses028 ? -8 : 0),
        minNativeZoom: is4326
            ? (Number.isFinite(basemapExtra.customMinNativeZoom) ? basemapExtra.customMinNativeZoom : 0)
            : (isDzzPolya || uses028 ? 8 : 0),
        maxNativeZoom: is4326
            ? (Number.isFinite(basemapExtra.customMaxNativeZoom) ? basemapExtra.customMaxNativeZoom : 21)
            : (isGmc ? 19 : (isDzzPolya ? 22 : 19)),
        maxZoom: 22,
    };
}

function dzzBasicHeader(login, password) {
    return 'Basic ' + btoa(unescape(encodeURIComponent(`${login}:${password || ''}`)));
}

function toSameOriginDzzUrl(url) {
    try {
        const parsed = new URL(url, window.location.href);
        if (!/^(www\.)?dzz\.by$/i.test(parsed.hostname)) return url;
        return `${window.location.origin}/api/dzz${parsed.pathname}${parsed.search}`;
    } catch {
        return url;
    }
}

const DZZ_MERCATOR_MAX = 20037508.342789244;
const DZZ_CACHE_MIN_Z = 10;
const DZZ_CACHE_MAX_Z = 14;
const DZZ_VIEW_ZOOM = 16;
const DZZ_EMPTY_TILE_BYTES = 2048;
const DZZ_TILE_TIMEOUT_MS = 12000;
const DZZ_CAPTURE_TIMEOUT_MS = 20000;
const DZZ_MAX_INFLIGHT = 6;
const DZZ_PREFETCH_SLOTS = 2;
const DZZ_TILE_CACHE_MAX = 480;
const DZZ_PREFETCH_MAX = 16;
const DZZ_PREFETCH_MAX_Z = 20;
const DZZ_TRANSPARENT_PIXEL = 'data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==';
const DZZ_SITE_LABELS = {
    berestovica_polya: 'Берестовица',
    Berezovski_rn_polya: 'Берёзовский р-н',
    myadel_polya: 'Мядель',
    Smolevichy_polya: 'Смолевичи',
};

let dzzSites = [];
let dzzActiveSiteId = '';
let dzzSitesRequestId = 0;
let dzzTileGridOn = false;
let dzzTileGridLayer = null;
let dzzDockMode = 'sites';
let dzzDockOpen = false;
let dzzHealthAvailable = true;
let dzzHealthTimer = 0;
let dzzStatusInflight = false;

function dzzImageServerRoot(url) {
    const match = String(url || '').match(/^(https:\/\/[^/]+\/arcgis\/rest\/services\/[^/]+\/[^/]+\/ImageServer)/i);
    return match ? match[1] : DZZ_DEFAULT_SERVICE;
}

function dzzFetch(url, signal) {
    return fetch(toSameOriginDzzUrl(url), { credentials: 'same-origin', signal });
}

function dzzFetchWithTimeout(url, ms = DZZ_TILE_TIMEOUT_MS, externalSignal) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), ms);
    const onAbort = () => ctrl.abort();
    if (externalSignal) {
        if (externalSignal.aborted) ctrl.abort();
        else externalSignal.addEventListener('abort', onAbort, { once: true });
    }
    return dzzFetch(url, ctrl.signal).finally(() => {
        clearTimeout(timer);
        if (externalSignal) externalSignal.removeEventListener('abort', onAbort);
    });
}

function dzzWait(ms, signal) {
    return new Promise((resolve, reject) => {
        if (signal?.aborted) {
            reject(Object.assign(new Error('Aborted'), { name: 'AbortError' }));
            return;
        }
        const timer = setTimeout(resolve, ms);
        const onAbort = () => {
            clearTimeout(timer);
            reject(Object.assign(new Error('Aborted'), { name: 'AbortError' }));
        };
        if (signal) signal.addEventListener('abort', onAbort, { once: true });
    });
}

async function dzzFetchResilient(url, ms = DZZ_TILE_TIMEOUT_MS, signal, attempts = 3) {
    let lastErr;
    for (let i = 0; i < attempts; i++) {
        if (signal?.aborted) {
            throw Object.assign(new Error('Aborted'), { name: 'AbortError' });
        }
        try {
            const res = await dzzFetchWithTimeout(url, ms, signal);
            if (res.status === 401) {
                const body = await res.clone().json().catch(() => ({}));
                if (body.error === 'DZZ_NOT_CONNECTED' && i < attempts - 1) {
                    await restoreDzzSession({ skipHealth: true });
                    if (dzzSession.connected) continue;
                }
                return res;
            }
            if (res.ok || (res.status < 500 && res.status !== 429)) return res;
            lastErr = new Error('TILE_HTTP_' + res.status);
        } catch (err) {
            if (err?.name === 'AbortError') throw err;
            lastErr = err;
        }
        if (i < attempts - 1) await dzzWait(400 * (i + 1), signal);
    }
    if (lastErr) throw lastErr;
    throw new Error('DZZ_FETCH');
}

const dzzTileCache = new Map();
const dzzInflightByKey = new Map();
const dzzHighQueue = [];
const dzzLowQueue = [];
let dzzInflight = 0;
let dzzPrefetchInflight = 0;
let dzzPrefetchTimer = 0;

function dzzCachePeek(key) {
    return dzzTileCache.get(key) || null;
}

function dzzCacheGet(key) {
    const hit = dzzTileCache.get(key);
    if (!hit) return null;
    dzzTileCache.delete(key);
    dzzTileCache.set(key, hit);
    return hit;
}

function dzzCacheSet(key, blob) {
    if (!blob || blob.size < 80) return;
    if (dzzTileCache.has(key)) dzzTileCache.delete(key);
    dzzTileCache.set(key, blob);
    while (dzzTileCache.size > DZZ_TILE_CACHE_MAX) {
        dzzTileCache.delete(dzzTileCache.keys().next().value);
    }
}

function dzzPumpQueue() {
    while (dzzInflight < DZZ_MAX_INFLIGHT) {
        const high = dzzHighQueue.shift();
        if (high) {
            high();
            continue;
        }
        if (dzzPrefetchInflight >= DZZ_PREFETCH_SLOTS) break;
        const low = dzzLowQueue.shift();
        if (!low) break;
        low();
    }
}

function dzzLimit(task, priority = 0) {
    const isLow = priority > 0;
    return new Promise((resolve, reject) => {
        const run = () => {
            dzzInflight += 1;
            if (isLow) dzzPrefetchInflight += 1;
            Promise.resolve()
                .then(task)
                .then(resolve, reject)
                .finally(() => {
                    dzzInflight -= 1;
                    if (isLow) dzzPrefetchInflight -= 1;
                    dzzPumpQueue();
                });
        };
        if (isLow) {
            if (dzzLowQueue.length >= 28) dzzLowQueue.shift();
            dzzLowQueue.push(run);
        } else {
            dzzHighQueue.push(run);
        }
        dzzPumpQueue();
    });
}

function dzzEnsureTileBlob(key, loader, priority = 0) {
    const hit = dzzCachePeek(key);
    if (hit) return Promise.resolve(hit);
    const existing = dzzInflightByKey.get(key);
    if (existing) return existing.promise;
    const rec = { promise: null };
    rec.promise = dzzLimit(async () => {
        const again = dzzCachePeek(key);
        if (again) return again;
        const blob = await loader();
        dzzCacheSet(key, blob);
        return blob;
    }, priority).finally(() => {
        if (dzzInflightByKey.get(key) === rec) dzzInflightByKey.delete(key);
    });
    dzzInflightByKey.set(key, rec);
    return rec.promise;
}

function dzzPreviewCacheKey(root, coords) {
    return `${root}|${coords.z}/${coords.x}/${coords.y}|256-png`;
}

function dzzHiCacheKey(root, coords, size) {
    return `${root}|${coords.z}/${coords.x}/${coords.y}|${size}-png`;
}

function dzzFindCachedAncestor(root, coords) {
    let z = coords.z;
    let x = coords.x;
    let y = coords.y;
    for (let i = 0; i < 8 && z > 0; i++) {
        z -= 1;
        x = Math.floor(x / 2);
        y = Math.floor(y / 2);
        const blob = dzzCachePeek(dzzPreviewCacheKey(root, { z, x, y }));
        if (blob && blob.size >= DZZ_EMPTY_TILE_BYTES) return { coords: { z, x, y }, blob };
    }
    return null;
}

function dzzUpscaleFromAncestor(blob, ancestor, child) {
    return new Promise((resolve, reject) => {
        const img = new Image();
        const url = URL.createObjectURL(blob);
        img.onload = () => {
            URL.revokeObjectURL(url);
            const k = child.z - ancestor.z;
            const factor = 2 ** k;
            const srcSize = Math.max(1, img.naturalWidth / factor);
            const sx = (child.x - ancestor.x * factor) * srcSize;
            const sy = (child.y - ancestor.y * factor) * srcSize;
            const canvas = document.createElement('canvas');
            canvas.width = 256;
            canvas.height = 256;
            const ctx = canvas.getContext('2d');
            ctx.imageSmoothingEnabled = true;
            ctx.imageSmoothingQuality = 'high';
            ctx.drawImage(img, sx, sy, srcSize, srcSize, 0, 0, 256, 256);
            canvas.toBlob((out) => (out ? resolve(out) : reject(new Error('upscale'))), 'image/png');
        };
        img.onerror = () => {
            URL.revokeObjectURL(url);
            reject(new Error('upscale'));
        };
        img.src = url;
    });
}

function dzzLoadPreviewBlob(layer, coords, priority = 0) {
    const root = layer._serviceRoot;
    const key = dzzPreviewCacheKey(root, coords);
    const z = coords.z;
    const useExportFirst = z > DZZ_CACHE_MAX_Z || z < DZZ_CACHE_MIN_Z;
    return dzzEnsureTileBlob(key, async () => {
        const fetchBlob = (url) => dzzFetchResilient(url, DZZ_TILE_TIMEOUT_MS, null).then((res) => {
            if (!res.ok) throw new Error('TILE_HTTP_' + res.status);
            return res.blob();
        });
        const exportUrl = dzzExportImageUrl(root, coords, 256, 'png');
        if (useExportFirst) {
            try {
                return await fetchBlob(exportUrl);
            } catch {
                return fetchBlob(layer.getTileUrl(coords));
            }
        }
        try {
            const blob = await fetchBlob(layer.getTileUrl(coords));
            if (blob.size < DZZ_EMPTY_TILE_BYTES) return fetchBlob(exportUrl);
            return blob;
        } catch {
            return fetchBlob(exportUrl);
        }
    }, priority);
}

function dzzClearPrefetchQueue() {
    if (dzzPrefetchTimer) {
        clearTimeout(dzzPrefetchTimer);
        dzzPrefetchTimer = 0;
    }
    dzzLowQueue.length = 0;
}

function dzzTilesInView(z, pad = 1) {
    if (!map) return [];
    const bounds = map.getBounds();
    const nw = map.project(bounds.getNorthWest(), z);
    const se = map.project(bounds.getSouthEast(), z);
    const minX = Math.floor(Math.min(nw.x, se.x) / 256) - pad;
    const maxX = Math.floor(Math.max(nw.x, se.x) / 256) + pad;
    const minY = Math.floor(Math.min(nw.y, se.y) / 256) - pad;
    const maxY = Math.floor(Math.max(nw.y, se.y) / 256) + pad;
    const { nx, ny } = tileGridSize(z);
    const out = [];
    for (let y = minY; y <= maxY; y++) {
        if (y < 0 || y >= ny) continue;
        for (let x = minX; x <= maxX; x++) {
            out.push({ z, x: ((x % nx) + nx) % nx, y });
        }
    }
    const c = getMapTileCoords(map.getCenter(), z);
    out.sort((a, b) => (Math.abs(a.x - c.x) + Math.abs(a.y - c.y)) - (Math.abs(b.x - c.x) + Math.abs(b.y - c.y)));
    return out;
}

function scheduleDzzPrefetch() {
    if (currentBasemap !== 'dzz' || !map || !tileDzz || !dzzSession.connected) return;
    clearTimeout(dzzPrefetchTimer);
    dzzPrefetchTimer = setTimeout(runDzzPrefetch, 320);
}

function runDzzPrefetch() {
    dzzPrefetchTimer = 0;
    if (currentBasemap !== 'dzz' || !map || !tileDzz || !dzzSession.connected) return;
    if (map._animatingZoom || dzzToolsActive()) return;
    const z = Math.max(0, Math.round(map.getZoom()));
    const jobs = dzzTilesInView(z, z >= 15 ? 1 : 0);
    if (z >= DZZ_CACHE_MAX_Z && z < DZZ_PREFETCH_MAX_Z) {
        const childZ = z + 1;
        const parent = getMapTileCoords(map.getCenter(), z);
        jobs.push(
            { z: childZ, x: parent.x * 2, y: parent.y * 2 },
            { z: childZ, x: parent.x * 2 + 1, y: parent.y * 2 },
            { z: childZ, x: parent.x * 2, y: parent.y * 2 + 1 },
            { z: childZ, x: parent.x * 2 + 1, y: parent.y * 2 + 1 },
        );
    }
    let scheduled = 0;
    for (const coords of jobs) {
        if (scheduled >= DZZ_PREFETCH_MAX) break;
        if (!isDzzTileInCoverage(coords)) continue;
        const key = dzzPreviewCacheKey(tileDzz._serviceRoot, coords);
        if (dzzCachePeek(key) || dzzInflightByKey.has(key)) continue;
        scheduled += 1;
        dzzLoadPreviewBlob(tileDzz, coords, 1).catch(() => {});
    }
}

function leafletTileTo3857(coords, tileSize = 256) {
    const n = 2 ** coords.z;
    const res = (2 * DZZ_MERCATOR_MAX) / (tileSize * n);
    const xmin = coords.x * tileSize * res - DZZ_MERCATOR_MAX;
    const ymax = DZZ_MERCATOR_MAX - coords.y * tileSize * res;
    return { xmin, ymin: ymax - tileSize * res, xmax: xmin + tileSize * res, ymax };
}

function dzzToolsActive() {
    return activeTool === 'aoi' || activeTool === 'ruler' || activeTool === 'compass'
        || activeTool === 'freehand' || !!activeDrawHandler || !!aoiDrawHandler;
}

function dzzExportPixelSize(zoom, map) {
    if (zoom >= 18 && map && !map._animatingZoom && !dzzToolsActive()) return 512;
    return 256;
}

function dzzExportImageUrl(root, coords, size = 256, format = 'png') {
    const box = leafletTileTo3857(coords);
    const bbox = `${box.xmin},${box.ymin},${box.xmax},${box.ymax}`;
    const fmt = format === 'jpg' ? 'jpg' : 'png';
    const transparent = fmt === 'png' ? '&transparent=true' : '';
    const interpolation = size >= 512 ? 'RSP_CubicConvolution' : 'RSP_BilinearInterpolation';
    return `${root}/exportImage?bbox=${bbox}&bboxSR=3857&imageSR=3857&size=${size},${size}&format=${fmt}${transparent}&interpolation=${interpolation}&adjustAspectRatio=false&f=image`;
}

function isDzzTileInCoverage(coords) {
    if (!dzzSites.length) return true;
    const box = leafletTileTo3857(coords);
    const sw = L.CRS.EPSG3857.unproject(L.point(box.xmin, box.ymin));
    const ne = L.CRS.EPSG3857.unproject(L.point(box.xmax, box.ymax));
    const tileBounds = L.latLngBounds(sw, ne);
    return dzzSites.some((site) => site.bounds.intersects(tileBounds));
}

function humanizeDzzSiteName(name) {
    if (DZZ_SITE_LABELS[name]) return DZZ_SITE_LABELS[name];
    return String(name || 'Участок')
        .replace(/_polya$/i, '')
        .replace(/_rn_/gi, ' р-н ')
        .replace(/_/g, ' ')
        .trim();
}

function formatDzzCoords(lat, lng) {
    return `${Number(lat).toFixed(5)}°N ${Number(lng).toFixed(5)}°E`;
}

function escapeHtml(value) {
    return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

function boundsFromRing(ring) {
    const latlngs = (ring || []).map((pt) => [pt[1], pt[0]]);
    return latlngs.length ? L.latLngBounds(latlngs) : null;
}

let dzzSession = { connected: false };
let displaySettings = { pointSize: 5, lineWidth: 2, fillOpacity: 0.35, coordColor: '#ff3366', basemap: 'satellite' };
let basemapExtra = {
    dzzUrl: DZZ_DEFAULT_TILE_URL,
    customName: '',
    customUrl: '',
    customLogin: '',
    customPassword: '',
    customCrs: 'EPSG:3857',
    customZoomOffset: 0,
    customMinNativeZoom: 0,
    customMaxNativeZoom: 19,
};
function displaySettingsKey() { return 'ttz_display_' + getCurrentEmail(); }
function basemapExtraKey() { return 'ttz_basemap_extra_' + getCurrentEmail(); }

function persistBasemapExtra() {
    localStorage.setItem(basemapExtraKey(), JSON.stringify({
        dzzUrl: basemapExtra.dzzUrl || DZZ_DEFAULT_TILE_URL,
        customName: basemapExtra.customName || '',
        customUrl: basemapExtra.customUrl || '',
        customLogin: basemapExtra.customLogin || '',
        customPassword: basemapExtra.customPassword || '',
        customCrs: basemapExtra.customCrs === 'EPSG:4326' ? 'EPSG:4326' : 'EPSG:3857',
        customZoomOffset: Number.isFinite(basemapExtra.customZoomOffset) ? basemapExtra.customZoomOffset : 0,
        customMinNativeZoom: Number.isFinite(basemapExtra.customMinNativeZoom) ? basemapExtra.customMinNativeZoom : 0,
        customMaxNativeZoom: Number.isFinite(basemapExtra.customMaxNativeZoom) ? basemapExtra.customMaxNativeZoom : 19,
    }));
}

function loadBasemapExtraToForm() {
    const saved = JSON.parse(localStorage.getItem(basemapExtraKey()) || 'null');
    if (saved) {
        basemapExtra = {
            dzzUrl: DZZ_DEFAULT_TILE_URL,
            customName: '',
            customUrl: '',
            customLogin: '',
            customPassword: '',
            customCrs: 'EPSG:3857',
            customZoomOffset: 0,
            customMinNativeZoom: 0,
            customMaxNativeZoom: 19,
            ...saved,
        };
    }
    basemapExtra.dzzLogin = '';
    basemapExtra.dzzPassword = '';
    if (isLegacyDzzUrl(basemapExtra.dzzUrl)) basemapExtra.dzzUrl = DZZ_DEFAULT_TILE_URL;
    else basemapExtra.dzzUrl = resolveDzzTileTemplate(basemapExtra.dzzUrl).url;
    persistBasemapExtra();
    const setVal = (id, val) => { const el = document.getElementById(id); if (el) el.value = val || ''; };
    setVal('opt-dzz-login', '');
    setVal('opt-dzz-password', '');
    setVal('opt-dzz-url', basemapExtra.dzzUrl || DZZ_DEFAULT_TILE_URL);
    setVal('opt-custom-basemap-name', basemapExtra.customName);
    setVal('opt-custom-basemap-url', basemapExtra.customUrl);
    setVal('opt-custom-basemap-login', basemapExtra.customLogin);
    setVal('opt-custom-basemap-password', basemapExtra.customPassword);
    updateBasemapExtraVisibility(displaySettings.basemap || 'satellite');
    initPasswordToggles();
}

function readBasemapExtraFromForm() {
    const rawDzzUrl = document.getElementById('opt-dzz-url')?.value.trim() || DZZ_DEFAULT_TILE_URL;
    const resolvedDzzUrl = resolveDzzTileTemplate(rawDzzUrl).url;
    const dzzUrlInput = document.getElementById('opt-dzz-url');
    if (dzzUrlInput) dzzUrlInput.value = resolvedDzzUrl;
    basemapExtra = {
        dzzUrl: resolvedDzzUrl,
        customName: document.getElementById('opt-custom-basemap-name')?.value.trim() || '',
        customUrl: document.getElementById('opt-custom-basemap-url')?.value.trim() || '',
        customLogin: document.getElementById('opt-custom-basemap-login')?.value.trim() || '',
        customPassword: document.getElementById('opt-custom-basemap-password')?.value || '',
        customCrs: basemapExtra.customCrs === 'EPSG:4326' ? 'EPSG:4326' : 'EPSG:3857',
        customZoomOffset: Number.isFinite(basemapExtra.customZoomOffset) ? basemapExtra.customZoomOffset : 0,
        customMinNativeZoom: Number.isFinite(basemapExtra.customMinNativeZoom) ? basemapExtra.customMinNativeZoom : 0,
        customMaxNativeZoom: Number.isFinite(basemapExtra.customMaxNativeZoom) ? basemapExtra.customMaxNativeZoom : 19,
    };
}

function updateBasemapExtraVisibility(value) {
    const dzz = document.getElementById('basemap-dzz-block');
    const custom = document.getElementById('basemap-custom-block');
    // dzz.by credentials always available on Settings tab
    if (dzz) dzz.style.display = 'block';
    if (custom) custom.style.display = value === 'custom' ? 'block' : 'none';
}

async function onBasemapSelectChange(value) {
    updateBasemapExtraVisibility(value);
    if (value === 'dzz') {
        if (dzzSession.connected) {
            setBasemap('dzz');
            return;
        }
        const login = (document.getElementById('opt-dzz-login')?.value || '').trim();
        const password = document.getElementById('opt-dzz-password')?.value || '';
        if (!login || !password) {
            showToast('Укажите логин и пароль dzz.by');
            const select = document.getElementById('opt-basemap');
            if (select) select.value = currentBasemap || 'satellite';
            return;
        }
        await testDzzAccess();
        return;
    }
    if (value === 'custom' && !(document.getElementById('opt-custom-basemap-url')?.value || '').trim()) {
        showToast('Укажите URL шаблон дополнительной подложки');
    }
    setBasemap(value);
}

function loadDisplaySettings() {
    const saved = JSON.parse(localStorage.getItem(displaySettingsKey()) || 'null');
    if (saved) displaySettings = { ...displaySettings, ...saved };
    if (typeof displaySettings.fillOpacity !== 'number') displaySettings.fillOpacity = 0.35;
    const ps = document.getElementById('opt-point-size');
    const lw = document.getElementById('opt-line-width');
    const fo = document.getElementById('opt-fill-opacity');
    const cc = document.getElementById('opt-coord-color');
    const bm = document.getElementById('opt-basemap');
    if (ps) { ps.value = displaySettings.pointSize; document.getElementById('point-size-value').innerText = displaySettings.pointSize; }
    if (lw) { lw.value = displaySettings.lineWidth; document.getElementById('line-width-value').innerText = displaySettings.lineWidth; }
    if (fo) {
        const pct = Math.round((displaySettings.fillOpacity ?? 0.35) * 100);
        fo.value = pct;
        document.getElementById('fill-opacity-value').innerText = pct;
    }
    if (cc) cc.value = displaySettings.coordColor;
    if (bm) bm.value = displaySettings.basemap || 'satellite';
    loadBasemapExtraToForm();
    applyDisplaySettings();
}
function getFillOpacity(isPoint = false) {
    const base = typeof displaySettings.fillOpacity === 'number' ? displaySettings.fillOpacity : 0.35;
    return isPoint ? Math.min(0.9, base + 0.2) : base;
}
function applyDisplaySettings() {
    const lw = displaySettings.lineWidth;
    layersRegistry.forEach(entry => {
        entry.group.eachLayer(l => {
            const sel = selectedFeatures.find(s => s.layer === l);
            if (sel) {
                const base = getFeatureBaseStyle(sel.layerId, l);
                const fill = Math.min(0.85, (base.fillOpacity || 0.35) + 0.2);
                l.setStyle({ ...base, weight: lw + 3, color: '#ffffff', fillOpacity: fill });
            } else {
                l.setStyle({ ...getFeatureBaseStyle(entry.id, l), weight: lw });
            }
        });
    });
    if (selectedFeatures.length === 1) showVertexMarkers(selectedFeatures[0].layer, selectedFeatures[0].layerId);
}

/* =========================================================
   АУТЕНТИФИКАЦИЯ: вход / регистрация
   ========================================================= */
function toggleMode(mode) {
    const loginForm = document.getElementById('form-login');
    const registerForm = document.getElementById('form-register');
    const loginText = document.getElementById('text-login');
    const registerText = document.getElementById('text-register');

    document.getElementById('login-error').style.display = 'none';
    document.getElementById('register-error').style.display = 'none';

    if (mode === 'register') {
        loginForm.classList.remove('active'); loginText.classList.remove('active');
        registerForm.classList.add('active'); registerText.classList.add('active');
    } else {
        registerForm.classList.remove('active'); registerText.classList.remove('active');
        loginForm.classList.add('active'); loginText.classList.add('active');
    }
}

async function handleLogin(event) {
    event.preventDefault();
    const email = document.getElementById('login-email').value.trim().toLowerCase();
    const password = document.getElementById('login-password').value;
    const remember = document.getElementById('login-remember').checked;
    const errorBlock = document.getElementById('login-error');
    const button = event.target.querySelector('button[type="submit"]');

    errorBlock.style.display = 'none';
    errorBlock.innerText = 'Неверный email или пароль.';
    button.innerText = 'Проверка...';
    button.style.opacity = '0.7';

    try {
        let data;
        const useApi = await ensureAuthBackend();
        if (useApi) {
            try {
                data = await apiFetch('/api/login', {
                    method: 'POST',
                    body: JSON.stringify({ email, password, remember }),
                });
                authMode = 'server';
                clearLocalSession();
            } catch (e) {
                if (!shouldUseLocalAuth(e)) throw e;
                data = await localLogin({ email, password, remember });
            }
        } else {
            data = await localLogin({ email, password, remember });
        }
        currentUser = data.user;
        logAction('login', 'Успешный вход в систему');
        enterApp();
    } catch (e) {
        console.error('login failed', e);
        if (e.code === 'INVALID_CREDENTIALS' || e.status === 401) {
            errorBlock.innerText = 'Неверный email или пароль. Если почта уже зарегистрирована — проверьте пароль.';
        } else {
            errorBlock.innerText = 'Не удалось войти. Попробуйте ещё раз.';
        }
        errorBlock.style.display = 'block';
    } finally {
        button.innerText = 'Войти';
        button.style.opacity = '1';
    }
    return false;
}

async function handleRegister(event) {
    event.preventDefault();
    const firstName = document.getElementById('reg-firstname').value.trim();
    const lastName = document.getElementById('reg-lastname').value.trim();
    const email = document.getElementById('reg-email').value.trim().toLowerCase();
    const organization = document.getElementById('reg-org').value.trim();
    const role = document.getElementById('reg-role').value.trim();
    const password = document.getElementById('reg-password').value;
    const password2 = document.getElementById('reg-password2').value;
    const errorBlock = document.getElementById('register-error');
    const button = event.target.querySelector('button[type="submit"]');

    errorBlock.style.display = 'none';

    if (password !== password2) {
        errorBlock.innerText = 'Пароли не совпадают.';
        errorBlock.style.display = 'block';
        return false;
    }
    const pwdErr = validatePassword(password);
    if (pwdErr) {
        errorBlock.innerText = pwdErr;
        errorBlock.style.display = 'block';
        return false;
    }

    button.innerText = 'Создание аккаунта...';
    button.style.opacity = '0.7';

    try {
        let data;
        const useApi = await ensureAuthBackend();
        if (useApi) {
            try {
                data = await apiFetch('/api/register', {
                    method: 'POST',
                    body: JSON.stringify({ firstName, lastName, email, organization, role, password }),
                });
                authMode = 'server';
                clearLocalSession();
            } catch (e) {
                if (!shouldUseLocalAuth(e)) throw e;
                data = await localRegister({ firstName, lastName, email, organization, role, password });
            }
        } else {
            data = await localRegister({ firstName, lastName, email, organization, role, password });
        }
        currentUser = data.user;
        logAction('account', 'Аккаунт создан');
        logAction('login', 'Успешный вход в систему');
        enterApp();
    } catch (e) {
        console.error('register failed', e);
        if (e.code === 'EMAIL_EXISTS' || e.status === 409) {
            document.getElementById('login-email').value = email;
            document.getElementById('login-password').value = '';
            toggleMode('login');
            const loginErr = document.getElementById('login-error');
            loginErr.innerText = 'Этот email уже зарегистрирован. Войдите с паролем от аккаунта.';
            loginErr.style.display = 'block';
            document.getElementById('login-password').focus();
        } else if (e.code === 'WEAK_PASSWORD') {
            errorBlock.innerText = 'Пароль: минимум 8 символов, заглавные и строчные буквы, спецсимвол.';
            errorBlock.style.display = 'block';
        } else {
            errorBlock.innerText = 'Не удалось создать аккаунт. Проверьте данные и попробуйте снова.';
            errorBlock.style.display = 'block';
        }
    } finally {
        button.innerText = 'Зарегистрироваться';
        button.style.opacity = '1';
    }
    return false;
}

async function handleLogout() {
    if (!confirm('Выйти из аккаунта?')) return;
    logAction('account', 'Выход из системы');
    try {
        if (authMode === 'server') await apiFetch('/api/logout', { method: 'POST' });
    } catch { /* ignore */ }
    clearLocalSession();
    currentUser = null;
    authMode = 'server';
    document.getElementById('screen-app').style.display = 'none';
    document.getElementById('screen-auth').style.display = 'flex';
    document.getElementById('loginForm').reset();
    toggleMode('login');
}

function avatarKey(email) { return LS_AVATAR_PREFIX + email; }
function getAvatar(email) { return localStorage.getItem(avatarKey(email)); }
function setAvatar(email, dataUrl) { localStorage.setItem(avatarKey(email), dataUrl); }

function applyAvatarUI(email) {
    const dataUrl = getAvatar(email);
    const ini = initials(currentAccount() || { email });
    [document.getElementById('card-avatar'), document.getElementById('sidebar-avatar')].forEach(el => {
        if (!el) return;
        if (dataUrl) {
            el.style.backgroundImage = `url(${dataUrl})`;
            el.style.backgroundSize = 'cover';
            el.style.backgroundPosition = 'center';
            el.style.color = 'transparent';
        } else {
            el.style.backgroundImage = '';
            el.style.color = '#fff';
            el.innerText = ini;
        }
    });
}

function handleAvatarFile(file) {
    const email = getCurrentEmail();
    if (!email || !file) return;
    if (!file.type.startsWith('image/')) { alert('Выберите изображение.'); return; }
    const reader = new FileReader();
    reader.onload = () => {
        setAvatar(email, reader.result);
        applyAvatarUI(email);
        logAction('account', 'Обновлена аватарка');
        showToast('Аватарка обновлена');
    };
    reader.readAsDataURL(file);
}

function removeAvatar(silent = false) {
    const email = getCurrentEmail();
    if (!email) return;
    if (!getAvatar(email)) { if (!silent) showToast('Аватарка не задана'); return; }
    if (!silent && !confirm('Удалить аватарку?')) return;
    localStorage.removeItem(avatarKey(email));
    applyAvatarUI(email);
    logAction('account', 'Удалена аватарка');
    showToast('Аватарка удалена');
}

function onAvatarClick() {
    const email = getCurrentEmail();
    if (!email) return;
    const has = Boolean(getAvatar(email));
    openAppModal({
        title: 'Аватарка',
        bodyHtml: has
            ? '<p class="modal-text">Загрузите новое изображение или удалите текущую аватарку.</p>'
            : '<p class="modal-text">Загрузите изображение для аватарки профиля.</p>',
        actions: [
            ...(has ? [{ label: 'Удалить', className: 'mini-btn mini-btn-blue', onClick: () => { closeAppModal(); removeAvatar(true); } }] : []),
            { label: 'Загрузить', className: 'mini-btn mini-btn-red', onClick: () => { closeAppModal(); document.getElementById('avatar-file-input')?.click(); } },
            { label: 'Отмена', className: 'mini-btn', onClick: () => closeAppModal() },
        ],
    });
}

function clearUserLocalData(email) {
    if (!email) return;
    [
        historyKey(email), statsKey(), processedKey(), foldersKey(),
        layerMetaKey(), objectFoldersKey(), displaySettingsKey(), avatarKey(email),
    ].forEach(k => localStorage.removeItem(k));
}

async function deleteAccount() {
    if (!currentUser) return;
    const email = getCurrentEmail();
    if (!confirm('Удалить аккаунт безвозвратно? Все данные будут удалены.')) return;
    const confirmText = prompt('Введите DELETE для подтверждения');
    if (confirmText !== 'DELETE') return;
    try {
        if (authMode === 'local') localDeleteAccount(email);
        else {
            try {
                await apiFetch('/api/account', { method: 'DELETE' });
            } catch (e) {
                if (isNetworkAuthError(e)) localDeleteAccount(email);
                else throw e;
            }
        }
        clearUserLocalData(email);
        clearLocalSession();
        currentUser = null;
        authMode = 'server';
        document.getElementById('screen-app').style.display = 'none';
        document.getElementById('screen-auth').style.display = 'flex';
        document.getElementById('loginForm').reset();
        toggleMode('login');
        showToast('Аккаунт удалён');
    } catch {
        alert('Не удалось удалить аккаунт. Попробуйте позже.');
    }
}

/* =========================================================
   ПЕРЕХОД В ПРИЛОЖЕНИЕ И ЗАПОЛНЕНИЕ ДАННЫХ АККАУНТА
   ========================================================= */
let mapInitialized = false;

function enterApp() {
    refreshCropCaches();
    document.getElementById('screen-auth').style.display = 'none';
    document.getElementById('screen-app').style.display = 'flex';
    switchMainTab('map');
    document.getElementById('map-area')?.classList.add('tool-select');
    renderAccountHeader();
    renderAccountForm();
    renderAccountStats();
    renderHistoryFeed();
    loadDisplaySettings();
    if (!mapInitialized) { initMap(); loadFoldersState(); mapInitialized = true; }
    restoreDzzSession().then(() => {
        if (map) setBasemap(displaySettings.basemap || 'satellite', true);
        updateDzzNetworkStatus();
    });
    initSegControls();
    updateMlNetworkStatus();
    updateDzzNetworkStatus();
    setTimeout(() => { if (window.map) map.invalidateSize(); }, 50);
}

function currentAccount() {
    return currentUser;
}

function initials(acc) {
    const f = acc.firstName ? acc.firstName[0].toUpperCase() : '';
    const l = acc.lastName ? acc.lastName[0].toUpperCase() : '';
    return (f + l) || 'AV';
}

function renderAccountHeader() {
    const acc = currentAccount();
    if (!acc) return;
    const ini = initials(acc);
    document.getElementById('card-avatar').innerText = ini;
    const sidebarAv = document.getElementById('sidebar-avatar');
    if (sidebarAv) sidebarAv.innerText = ini;
    document.getElementById('user-display-name').innerText = `${acc.firstName || ''} ${acc.lastName || ''}`.trim() || acc.email;
    document.getElementById('user-display-role-org').innerText = `${acc.role || '—'} · ${acc.organization || '—'}`;
    applyAvatarUI(acc.email);
}

function renderAccountForm() {
    const acc = currentAccount();
    if (!acc) return;
    document.getElementById('prof-name').value = acc.firstName || '';
    document.getElementById('prof-lastname').value = acc.lastName || '';
    document.getElementById('prof-email').value = acc.email || '';
    document.getElementById('prof-org').value = acc.organization || '';
    document.getElementById('prof-role').value = acc.role || '';
    document.getElementById('prof-new-password').value = '';
    document.getElementById('prof-new-password2').value = '';
}

async function saveProfile() {
    if (!currentUser) return;

    const newPass = document.getElementById('prof-new-password').value;
    const newPass2 = document.getElementById('prof-new-password2').value;
    if (newPass || newPass2) {
        if (newPass !== newPass2) {
            alert('Новый пароль должен совпадать в обоих полях.');
            return;
        }
        const pwdErr = validatePassword(newPass);
        if (pwdErr) { alert(pwdErr); return; }
    }

    const body = {
        firstName: document.getElementById('prof-name').value.trim(),
        lastName: document.getElementById('prof-lastname').value.trim(),
        organization: document.getElementById('prof-org').value.trim(),
        role: document.getElementById('prof-role').value.trim(),
    };
    if (newPass) body.newPassword = newPass;

    try {
        let data;
        if (authMode === 'local') {
            data = await localSaveProfile(body);
        } else {
            try {
                data = await apiFetch('/api/profile', {
                    method: 'POST',
                    body: JSON.stringify(body),
                });
            } catch (e) {
                if (!isNetworkAuthError(e)) throw e;
                data = await localSaveProfile(body);
                authMode = 'local';
            }
        }
        currentUser = data.user;
        if (newPass) logAction('account', 'Изменён пароль');
        logAction('account', 'Обновлены данные профиля');
        renderAccountHeader();
        renderAccountForm();
        showToast('Профиль сохранён');
    } catch (e) {
        if (e.code === 'WEAK_PASSWORD') {
            alert('Пароль: минимум 8 символов, заглавные и строчные буквы, спецсимвол.');
        } else {
            alert('Не удалось сохранить профиль.');
        }
    }
}

/* =========================================================
   ИСТОРИЯ АКТИВНОСТИ (лента, а не фейковая таблица файлов)
   ========================================================= */
const ICON_NAVY = '#010635';
const HISTORY_ICONS = {
    login: `<svg fill="${ICON_NAVY}" viewBox="0 0 512 512" width="16" height="16" xmlns="http://www.w3.org/2000/svg"><path d="M432,80H192a16,16,0,0,0-16,16V240H329.37l-64-64L288,153.37l91.31,91.32a16,16,0,0,1,0,22.62L288,358.63,265.37,336l64-64H176V416a16,16,0,0,0,16,16H432a16,16,0,0,0,16-16V96A16,16,0,0,0,432,80Z"/><rect x="64" y="240" width="112" height="32"/></svg>`,
    logout: `<svg fill="${ICON_NAVY}" viewBox="0 0 512 512" width="16" height="16" xmlns="http://www.w3.org/2000/svg"><path d="M160,240H320V96a16,16,0,0,0-16-16H64A16,16,0,0,0,48,96V416a16,16,0,0,0,16,16H304a16,16,0,0,0,16-16V272H160Z"/><path d="M459.31,244.69,368,153.37,345.37,176l64,64H320v32h89.37l-64,64L368,358.63l91.31-91.32a16,16,0,0,0,0-22.62Z"/></svg>`,
    export: `<svg viewBox="0 0 21 21" width="16" height="16" xmlns="http://www.w3.org/2000/svg" fill="none"><g fill="none" stroke="${ICON_NAVY}" stroke-linecap="round" stroke-linejoin="round" transform="translate(4 3)" stroke-width="1.3"><path d="m8.5 14.5h2c1.1045695 0 2-.8954305 2-2v-8l-4-4h-6c-1.1045695 0-2 .8954305-2 2v10c0 1.1045695.8954305 2 2 2h2"/><path d="m3.5 7.5 3-3 3 3"/><path d="m6.5 4.5v11"/></g></svg>`,
    process: `<svg viewBox="0 0 24 24" width="16" height="16" xmlns="http://www.w3.org/2000/svg" fill="none" stroke="${ICON_NAVY}" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="miter"><rect x="9" y="9" width="6" height="6"/><rect x="5" y="5" width="14" height="14"/><line x1="2" y1="9" x2="5" y2="9"/><line x1="2" y1="15" x2="5" y2="15"/><line x1="19" y1="9" x2="22" y2="9"/><line x1="19" y1="15" x2="22" y2="15"/><line x1="15" y1="2" x2="15" y2="5"/><line x1="9" y1="2" x2="9" y2="5"/><line x1="15" y1="19" x2="15" y2="22"/><line x1="9" y1="19" x2="9" y2="22"/></svg>`,
    account: `<svg fill="${ICON_NAVY}" viewBox="0 0 512 512" width="16" height="16" xmlns="http://www.w3.org/2000/svg"><path d="M256 256a112 112 0 10-112-112 112 112 0 00112 112zm0 32c-69.4 0-208 34.9-208 104v40h416v-40c0-69.1-138.6-104-208-104z"/></svg>`,
    tool: `<svg fill="${ICON_NAVY}" viewBox="0 0 512 512" width="16" height="16" xmlns="http://www.w3.org/2000/svg"><path d="M501.1 395.7L367.7 262.3c19.1-50.8 10.5-109.5-26.2-146.2-36.7-36.7-95.4-45.3-146.2-26.2L281.5 175.9 175.9 281.5 89.7 195.3c-19.1 50.8-10.5 109.5 26.2 146.2 36.7 36.7 95.4 45.3 146.2 26.2l133.4 133.4c12.5 12.5 32.8 12.5 45.3 0l60.3-60.3c12.5-12.5 12.5-32.8 0-45.3z"/></svg>`,
};

function normalizeHistoryItem(item) {
    // входы/выходы — в раздел «Аккаунт», но иконки разные
    const copy = { ...item };
    const text = copy.text || '';
    if (copy.type === 'login') {
        copy.filterType = 'account';
        copy.iconKey = /выход/i.test(text) ? 'logout' : 'login';
    } else if (copy.type === 'account') {
        copy.filterType = 'account';
        if (/выход/i.test(text)) copy.iconKey = 'logout';
        else if (/вход/i.test(text)) copy.iconKey = 'login';
        else copy.iconKey = 'account';
    } else if (copy.type === 'upload') {
        copy.filterType = 'process';
        copy.iconKey = 'process';
    } else if (copy.type === 'map') {
        copy.filterType = 'tool';
        copy.iconKey = 'tool';
    } else {
        copy.filterType = copy.type;
        copy.iconKey = HISTORY_ICONS[copy.type] ? copy.type : 'tool';
    }
    return copy;
}

function parseHistoryDate(str) {
    // ru-RU locale: "10.07.2026, 12:34:56" or similar
    if (!str) return 0;
    const m = String(str).match(/(\d{1,2})[./](\d{1,2})[./](\d{4})(?:[,\s]+(\d{1,2}):(\d{2})(?::(\d{2}))?)?/);
    if (!m) return Date.parse(str) || 0;
    const [, d, mo, y, h = '0', mi = '0', s = '0'] = m;
    return new Date(+y, +mo - 1, +d, +h, +mi, +s).getTime() || 0;
}

/** Нормализация для поиска: «11.07.2026, 12:30» → «11 07 2026 12 30» + цифры «110720261230» */
function historySearchBlob(item) {
    const parts = [
        item.text, item.date, item.filterType, item.type,
        item.exportFormat, item.processId, item.resultName, item.name,
    ].filter(Boolean).map(String);
    const raw = parts.join(' ').toLowerCase();
    const spaced = raw
        .replace(/[./,;:_-]+/g, ' ')
        .replace(/\s+/g, ' ')
        .trim();
    const digits = raw.replace(/\D+/g, '');
    // варианты даты из ts
    let fromTs = '';
    if (item.ts) {
        const d = new Date(item.ts);
        if (!Number.isNaN(d.getTime())) {
            const dd = String(d.getDate()).padStart(2, '0');
            const mm = String(d.getMonth() + 1).padStart(2, '0');
            const yyyy = String(d.getFullYear());
            fromTs = `${dd} ${mm} ${yyyy} ${dd}.${mm}.${yyyy} ${dd}${mm}${yyyy}`;
        }
    }
    return {
        raw,
        spaced: `${spaced} ${fromTs}`.trim(),
        digits: digits + (fromTs.replace(/\D+/g, '')),
    };
}

function historyMatchesQuery(item, query) {
    if (!query) return true;
    const q = query.trim().toLowerCase();
    if (!q) return true;
    const blob = historySearchBlob(item);

    // 1) прямое вхождение как ввели
    if (blob.raw.includes(q)) return true;

    // 2) без пунктуации: «11.07» / «11 07» / «11-07»
    const qSpaced = q.replace(/[./,;:_-]+/g, ' ').replace(/\s+/g, ' ').trim();
    if (qSpaced && blob.spaced.includes(qSpaced)) return true;
    // токены через AND
    const tokens = qSpaced.split(' ').filter(Boolean);
    if (tokens.length > 1 && tokens.every(t => blob.spaced.includes(t))) return true;

    // 3) только цифры: «1107» / «11072026»
    const qDigits = q.replace(/\D+/g, '');
    if (qDigits.length >= 2 && blob.digits.includes(qDigits)) return true;

    // 4) фрагмент даты без ведущих нулей: «7.7.2026» vs «07.07.2026»
    const qLoose = qSpaced.replace(/\b0(\d)\b/g, '$1');
    const hayLoose = blob.spaced.replace(/\b0(\d)\b/g, '$1');
    if (qLoose && hayLoose.includes(qLoose)) return true;

    return false;
}

function renderHistoryFeed() {
    const email = getCurrentEmail();
    if (!email) return;
    // показываем все действия аккаунта: вход, профиль, инструменты, карта, экспорт, загрузка…
    const raw = getHistory(email).map(normalizeHistoryItem);
    const feed = document.getElementById('history-feed');
    if (!feed) return;
    const stats = document.getElementById('history-stats');
    const filterEl = document.getElementById('history-filter');
    const searchEl = document.getElementById('history-search');
    const sortEl = document.getElementById('history-sort');
    const filter = filterEl ? filterEl.value : 'all';
    const query = (searchEl?.value || '').trim();
    const sortMode = sortEl?.value || 'newest';

    let list = (filter === 'all') ? raw.slice() : raw.filter(i => i.filterType === filter || i.type === filter);
    if (query) list = list.filter(i => historyMatchesQuery(i, query));
    list.sort((a, b) => {
        const ta = a.ts || parseHistoryDate(a.date);
        const tb = b.ts || parseHistoryDate(b.date);
        return sortMode === 'oldest' ? ta - tb : tb - ta;
    });

    const counts = { account: 0, export: 0, process: 0, tool: 0 };
    raw.forEach(item => {
        if (item.filterType === 'account' || item.type === 'login') counts.account++;
        else if (item.filterType === 'export') counts.export++;
        else if (item.filterType === 'process' || item.type === 'upload') counts.process++;
        else counts.tool++;
    });
    if (stats) stats.innerHTML = `
        <span class="stat-badge stat-green">${counts.account} акк.</span>
        <span class="stat-badge stat-red">${counts.export} эксп.</span>
        <span class="stat-badge stat-blue">${counts.process} обраб.</span>
        <span class="stat-badge stat-blue">${counts.tool} инстр.</span>
    `;

    if (list.length === 0) {
        feed.innerHTML = query
            ? '<div class="history-empty">Ничего не найдено</div>'
            : '<div class="history-empty">Пока нет действий на аккаунте</div>';
        return;
    }

    feed.innerHTML = list.map(item => `
        <div class="history-row">
            <div class="history-icon type-${item.filterType || item.type}">${HISTORY_ICONS[item.iconKey] || HISTORY_ICONS.tool || HISTORY_ICONS.account || '•'}</div>
            <div>
                <div class="history-text">${item.text}</div>
                <div class="history-date">${item.date}</div>
                ${item.processId ? `<div class="history-actions">
                    <button type="button" class="history-open" onclick="openProcessedFile('${item.processId}')">Открыть</button>
                    <button type="button" class="history-download" onclick="downloadProcessedFile('${item.processId}')">Скачать результат</button>
                </div>` : ''}
            </div>
        </div>
    `).join('');
}

/* =========================================================
   ВКЛАДКИ ВЕРХНЕГО УРОВНЯ (Карта / Аккаунт)
   ========================================================= */
function switchMainTab(tabId) {
    document.querySelectorAll('.view-container').forEach(view => view.style.display = 'none');
    const target = document.getElementById(`view-${tabId}`);
    target.style.display = 'flex';
    if (tabId === 'map') target.classList.add('active');
    else document.getElementById('view-map').classList.remove('active');

    const accountBtn = document.getElementById('sidebar-account-btn');
    if (accountBtn) accountBtn.classList.toggle('active', tabId === 'account');

    if (tabId === 'map' && window.map) {
        setTimeout(() => map.invalidateSize(), 100);
    }
    if (tabId === 'account') {
        renderAccountHeader();
        renderAccountForm();
        renderAccountStats();
        renderHistoryFeed();
    }
}

function switchSidebar(panelId, event) {
    switchMainTab('map');
    document.querySelectorAll('.icon-btn[data-panel]').forEach(btn => btn.classList.remove('active'));
    if (event) event.currentTarget.classList.add('active');
    document.querySelectorAll('.panel-content').forEach(panel => panel.classList.remove('active'));
    document.getElementById(`panel-${panelId}`).classList.add('active');
}

/* =========================================================
   КАРТА: инициализация, слои, инструменты
   ========================================================= */
let map, tileSatellite, tileScheme, tileDzz, tileCustom;
let currentBasemap = 'satellite';
let tileCustomSig = '';
let mapCrsCode = 'EPSG:3857';

const AuthTileLayer = L.TileLayer.extend({
    initialize(url, options = {}) {
        this._authUser = options.authUser || '';
        this._authPass = options.authPass || '';
        L.TileLayer.prototype.initialize.call(this, url, options);
    },
    getTileUrl(coords) {
        let url = L.TileLayer.prototype.getTileUrl.call(this, coords);
        if (this._authUser) url = url.replaceAll('{user}', encodeURIComponent(this._authUser));
        if (this._authPass) url = url.replaceAll('{pass}', encodeURIComponent(this._authPass));
        if (url.includes('{TileMatrix}')) {
            const z = coords.z + (this.options.zoomOffset || 0);
            url = url.replaceAll('{TileMatrix}', String(z));
        }
        return url;
    },
    createTile(coords, done) {
        const tile = document.createElement('img');
        tile.alt = '';
        tile.setAttribute('role', 'presentation');

        const url = this.getTileUrl(coords);
        const proxied = toSameOriginDzzUrl(url);
        const finishOk = () => done(null, tile);
        const finishErr = () => done(new Error('tile error'), tile);
        const needsAuthFetch = !!(this._authUser || proxied !== url);
        const isDzzProxy = proxied !== url;

        const applyBlob = (blob) => {
            if (tile._blobUrl) URL.revokeObjectURL(tile._blobUrl);
            tile._blobUrl = URL.createObjectURL(blob);
            tile.onload = finishOk;
            tile.onerror = finishErr;
            tile.src = tile._blobUrl;
        };

        const fetchTile = (requestUrl, headers, mode, credentials) =>
            fetch(requestUrl, { headers, mode, credentials }).then((res) => {
                if (!res.ok) throw new Error('TILE_HTTP_' + res.status);
                return res.blob();
            });

        if (needsAuthFetch) {
            const headers = {};
            if (this._authUser && !isDzzProxy) {
                headers.Authorization = dzzBasicHeader(this._authUser, this._authPass);
            }
            fetchTile(proxied, headers, 'cors', 'same-origin')
                .then(applyBlob)
                .catch(() => {
                    if (isDzzProxy) throw new Error('tile error');
                    const directHeaders = this._authUser
                        ? { Authorization: dzzBasicHeader(this._authUser, this._authPass) }
                        : {};
                    return fetchTile(url, directHeaders, 'cors', 'omit').then(applyBlob);
                })
                .catch(finishErr);
        } else {
            L.DomEvent.on(tile, 'load', L.Util.bind(this._tileOnLoad, this, done, tile));
            L.DomEvent.on(tile, 'error', L.Util.bind(this._tileOnError, this, done, tile));
            tile.src = url;
        }
        return tile;
    },
});

const DzzOrthoLayer = L.TileLayer.extend({
    initialize(url, options = {}) {
        this._serviceRoot = dzzImageServerRoot(url);
        this._dzzSig = options.dzzSig || '';
        L.TileLayer.prototype.initialize.call(this, url, options);
    },
    getTileUrl(coords) {
        let url = L.TileLayer.prototype.getTileUrl.call(this, coords);
        if (url.includes('{TileMatrix}')) {
            const z = coords.z + (this.options.zoomOffset || 0);
            url = url.replaceAll('{TileMatrix}', String(z));
        }
        return url;
    },
    createTile(coords, done) {
        const tile = document.createElement('img');
        tile.alt = '';
        tile.setAttribute('role', 'presentation');
        const abort = new AbortController();
        tile._dzzAbort = abort;
        let doneOnce = false;
        const finishOk = () => {
            if (doneOnce) return;
            doneOnce = true;
            done(null, tile);
        };
        abort.signal.addEventListener('abort', finishOk, { once: true });
        const applyBlob = (blob) => {
            if (abort.signal.aborted) {
                finishOk();
                return;
            }
            if (!blob || blob.size < 80) {
                finishOk();
                tile.src = DZZ_TRANSPARENT_PIXEL;
                return;
            }
            if (tile._blobUrl) URL.revokeObjectURL(tile._blobUrl);
            tile._blobUrl = URL.createObjectURL(blob);
            tile.onload = finishOk;
            tile.onerror = finishOk;
            tile.src = tile._blobUrl;
        };
        const transparent = () => {
            finishOk();
            if (abort.signal.aborted) return;
            tile.src = DZZ_TRANSPARENT_PIXEL;
        };

        if (!isDzzTileInCoverage(coords)) {
            transparent();
            return tile;
        }

        const z = coords.z;
        const root = this._serviceRoot;
        const hiSize = dzzExportPixelSize(z, this._map);
        const previewKey = dzzPreviewCacheKey(root, coords);
        const hiKey = dzzHiCacheKey(root, coords, hiSize);
        let quality = 0;

        const applyIfBetter = (blob, level) => {
            if (level < quality) return;
            quality = level;
            applyBlob(blob);
        };

        const cachedHi = hiSize > 256 ? dzzCacheGet(hiKey) : null;
        if (cachedHi) {
            applyIfBetter(cachedHi, 3);
            return tile;
        }
        const cachedPreview = dzzCacheGet(previewKey);
        if (cachedPreview) {
            applyIfBetter(cachedPreview, 2);
        } else {
            const ancestor = dzzFindCachedAncestor(root, coords);
            if (ancestor) {
                dzzUpscaleFromAncestor(ancestor.blob, ancestor.coords, coords)
                    .then((blob) => applyIfBetter(blob, 1))
                    .catch(() => finishOk());
            } else {
                finishOk();
            }
        }

        if (!cachedPreview) {
            dzzLoadPreviewBlob(this, coords, 0)
                .then((blob) => applyIfBetter(blob, 2))
                .catch(() => { if (quality === 0) transparent(); });
        }

        if (hiSize > 256) {
            const hiUrl = dzzExportImageUrl(root, coords, hiSize, 'png');
            dzzEnsureTileBlob(hiKey, () => dzzFetchResilient(hiUrl, DZZ_TILE_TIMEOUT_MS, null).then((res) => {
                if (!res.ok) throw new Error('TILE_HTTP_' + res.status);
                return res.blob();
            }), 0).then((hi) => applyIfBetter(hi, 3)).catch(() => {});
        }
        return tile;
    },
    _removeTile(key) {
        const tile = this._tiles?.[key]?.el;
        if (tile?._dzzAbort) {
            try { tile._dzzAbort.abort(); } catch { /* ignore */ }
        }
        if (tile?._blobUrl) {
            URL.revokeObjectURL(tile._blobUrl);
            tile._blobUrl = '';
        }
        return L.TileLayer.prototype._removeTile.call(this, key);
    },
});

const DzzTileGridLayer = L.GridLayer.extend({
    createTile(coords) {
        const tile = document.createElement('div');
        tile.className = 'dzz-tile-cell';
        tile.dataset.z = String(coords.z);
        tile.dataset.x = String(coords.x);
        tile.dataset.y = String(coords.y);
        const label = document.createElement('span');
        label.textContent = `${coords.z}/${coords.x}/${coords.y}`;
        tile.appendChild(label);
        return tile;
    },
});

function parseDzzSites(data) {
    const features = Array.isArray(data?.features) ? data.features : [];
    return features.map((feat, index) => {
        const name = feat.attributes?.Name || feat.attributes?.name || `Участок ${index + 1}`;
        const ring = feat.geometry?.rings?.[0];
        const bounds = boundsFromRing(ring);
        if (!bounds || !bounds.isValid()) return null;
        const center = bounds.getCenter();
        return {
            id: String(feat.attributes?.OBJECTID ?? name),
            name,
            title: humanizeDzzSiteName(name),
            lat: center.lat,
            lng: center.lng,
            center,
            bounds,
        };
    }).filter(Boolean);
}

function setDzzConnStatus(text) {
    const el = document.getElementById('dzz-conn-status');
    if (el) el.textContent = text || '';
}

function dzzDockStorageKey() {
    return 'ttz_dzz_dock_' + getCurrentEmail();
}

function loadDzzDockState() {
    try {
        const saved = JSON.parse(sessionStorage.getItem(dzzDockStorageKey()) || 'null');
        if (!saved) return;
        dzzDockMode = saved.mode === 'tiles' ? 'tiles' : 'sites';
        dzzDockOpen = !!saved.open;
    } catch { /* ignore */ }
}

function persistDzzDockState() {
    sessionStorage.setItem(dzzDockStorageKey(), JSON.stringify({
        mode: dzzDockMode,
        open: dzzDockOpen,
    }));
}

function updateDzzDockSummary() {
    const el = document.getElementById('dzz-dock-summary');
    if (!el) return;
    if (dzzDockMode === 'tiles' && map) {
        const t = getMapTileCoords();
        el.textContent = `${t.z}/${t.x}/${t.y}`;
        el.title = `Тайл ${t.z}/${t.x}/${t.y}`;
        return;
    }
    const site = dzzSites.find((item) => item.id === dzzActiveSiteId);
    if (site) {
        el.textContent = site.title;
        el.title = site.title;
        return;
    }
    el.textContent = dzzSites.length ? `${dzzSites.length} участок(ов)` : 'dzz.by';
    el.title = el.textContent;
}

function applyDzzDockUi() {
    const bar = document.getElementById('dzz-sites-bar');
    const sitesTab = document.getElementById('dzz-tab-sites');
    const tilesTab = document.getElementById('dzz-tab-tiles');
    const sitesPane = document.getElementById('dzz-sites-pane');
    const tilesPane = document.getElementById('dzz-tiles-pane');
    const toggle = document.getElementById('dzz-dock-toggle');
    const summary = document.getElementById('dzz-dock-summary');
    if (!bar) return;
    bar.classList.toggle('is-open', dzzDockOpen);
    const sitesOn = dzzDockOpen && dzzDockMode === 'sites';
    const tilesOn = dzzDockOpen && dzzDockMode === 'tiles';
    if (sitesTab) {
        sitesTab.classList.toggle('is-active', sitesOn);
        sitesTab.setAttribute('aria-selected', sitesOn ? 'true' : 'false');
    }
    if (tilesTab) {
        tilesTab.classList.toggle('is-active', tilesOn);
        tilesTab.setAttribute('aria-selected', tilesOn ? 'true' : 'false');
    }
    if (sitesPane) sitesPane.hidden = !sitesOn;
    if (tilesPane) tilesPane.hidden = !tilesOn;
    if (toggle) {
        toggle.setAttribute('aria-expanded', dzzDockOpen ? 'true' : 'false');
        toggle.title = dzzDockOpen ? 'Свернуть панель' : 'Развернуть панель';
    }
    if (summary) summary.title = dzzDockOpen ? 'Свернуть панель' : 'Развернуть панель';
    updateDzzDockSummary();
    if (map) setTimeout(() => map.invalidateSize(), 240);
}

function setDzzDockMode(mode) {
    const next = mode === 'tiles' ? 'tiles' : 'sites';
    if (dzzDockOpen && dzzDockMode === next) dzzDockOpen = false;
    else {
        dzzDockMode = next;
        dzzDockOpen = true;
    }
    persistDzzDockState();
    applyDzzDockUi();
}

function toggleDzzDock() {
    dzzDockOpen = !dzzDockOpen;
    persistDzzDockState();
    applyDzzDockUi();
}

function revealDzzDock(mode) {
    dzzDockMode = mode === 'tiles' ? 'tiles' : 'sites';
    dzzDockOpen = true;
    persistDzzDockState();
    applyDzzDockUi();
}

function renderDzzSites() {
    const bar = document.getElementById('dzz-sites-bar');
    const list = document.getElementById('dzz-sites-list');
    const settingsWrap = document.getElementById('dzz-sites-settings');
    const settingsList = document.getElementById('dzz-sites-settings-list');
    const visible = currentBasemap === 'dzz';

    if (bar) {
        bar.hidden = !visible;
        bar.classList.toggle('is-visible', visible);
        if (visible) {
            if (!bar.dataset.dockReady) {
                loadDzzDockState();
                bar.dataset.dockReady = '1';
            }
            applyDzzDockUi();
        } else {
            bar.classList.remove('is-open');
            delete bar.dataset.dockReady;
        }
    }
    if (settingsWrap) settingsWrap.hidden = dzzSites.length === 0;

    const chipHtml = dzzSites.length
        ? dzzSites.map((site) => {
            const active = site.id === dzzActiveSiteId ? ' is-active' : '';
            const coords = formatDzzCoords(site.lat, site.lng);
            return `<button type="button" class="dzz-site-chip${active}" data-dzz-site="${escapeHtml(site.id)}" title="${escapeHtml(site.title)}">
            <strong>${escapeHtml(site.title)}</strong>
            <small>${escapeHtml(coords)}</small>
        </button>`;
        }).join('')
        : '<span class="dzz-dock-empty">Участки появятся после загрузки покрытия</span>';
    if (list) list.innerHTML = chipHtml;

    if (settingsList) {
        settingsList.innerHTML = dzzSites.map((site) => {
            const active = site.id === dzzActiveSiteId ? ' is-active' : '';
            return `<div class="dzz-site-row${active}" data-dzz-site="${escapeHtml(site.id)}">
                <div class="dzz-site-row-text">
                    <strong>${escapeHtml(site.title)}</strong>
                    <small>${escapeHtml(formatDzzCoords(site.lat, site.lng))}</small>
                </div>
                <span class="dzz-site-row-go">Перейти</span>
            </div>`;
        }).join('');
    }

    applyDzzTileGridLayer();
    updateDzzDockSummary();
    if (map && visible) setTimeout(() => map.invalidateSize(), 50);
}

function hideDzzSites() {
    dzzSites = [];
    dzzActiveSiteId = '';
    renderDzzSites();
}

function disconnectDzz() {
    apiFetch('/api/dzz/disconnect', { method: 'POST' }).catch(() => {});
    dzzSession.connected = false;
    const loginEl = document.getElementById('opt-dzz-login');
    const passwordEl = document.getElementById('opt-dzz-password');
    const basemapEl = document.getElementById('opt-basemap');
    if (loginEl) loginEl.value = '';
    if (passwordEl) passwordEl.value = '';
    if (basemapEl) basemapEl.value = 'satellite';
    hideDzzSites();
    setDzzConnStatus('Сессия dzz.by завершена. Можно работать с обычной картой.');
    displaySettings.basemap = 'satellite';
    readBasemapExtraFromForm();
    localStorage.setItem(displaySettingsKey(), JSON.stringify(displaySettings));
    persistBasemapExtra();
    setBasemap('satellite', true);
    applyDzzTileGridLayer();
    updateDzzNetworkStatus();
    logAction('tool', 'Выход из dzz.by, возврат к обычной карте');
    showToast('Вышли из dzz.by. Открыта обычная карта');
}

function goToDzzSite(siteId, silent = false) {
    const site = dzzSites.find((item) => String(item.id) === String(siteId));
    if (!site || !map) return;
    dzzActiveSiteId = site.id;
    renderDzzSites();
    if (!silent) revealDzzDock('sites');
    const zoom = Math.min(18, Math.max(DZZ_VIEW_ZOOM, Math.round(map.getZoom())));
    map.flyTo(site.center, zoom, { duration: 0.75 });
    if (!silent) {
        showToast(`Переход: ${site.title}`);
        logAction('tool', `Переход к участку dzz.by: ${site.title}`);
    }
}

function dzzTileInputsFocused() {
    const ids = ['opt-dzz-tile-z', 'opt-dzz-tile-x', 'opt-dzz-tile-y', 'dzz-bar-z', 'dzz-bar-x', 'dzz-bar-y'];
    return ids.some((id) => document.activeElement?.id === id);
}

function currentMapCrs() {
    return mapCrsCode === 'EPSG:4326' ? 'EPSG:4326' : 'EPSG:3857';
}

function leafletCrsFor(code) {
    return code === 'EPSG:4326' ? L.CRS.EPSG4326 : L.CRS.EPSG3857;
}

function tileGridSize(z) {
    const zoom = Math.max(0, Math.round(Number(z) || 0));
    if (currentMapCrs() === 'EPSG:4326') {
        return { nx: 2 ** (zoom + 1), ny: 2 ** zoom };
    }
    const n = 2 ** zoom;
    return { nx: n, ny: n };
}

function wantedCrsForBasemap(value) {
    if (value === 'custom') {
        const url = String(basemapExtra.customUrl || '');
        if (/GoogleCRS84Quad/i.test(url)) return 'EPSG:4326';
        if (basemapExtra.customCrs === 'EPSG:4326' && /WMTS/i.test(url) && !/GoogleMapsCompatible|3857/i.test(url)) {
            return 'EPSG:4326';
        }
        return 'EPSG:3857';
    }
    return 'EPSG:3857';
}

function updateCrsDisplay() {
    const el = document.getElementById('crs-display');
    if (el) el.textContent = currentMapCrs();
}

function getMapTileCoords(latlng, zoom) {
    if (!map) return { z: 0, x: 0, y: 0 };
    const z = Math.max(0, Math.min(22, Math.round(zoom != null ? zoom : map.getZoom())));
    const p = map.project(latlng || map.getCenter(), z);
    const { nx, ny } = tileGridSize(z);
    return {
        z,
        x: Math.min(nx - 1, Math.max(0, Math.floor(p.x / 256))),
        y: Math.min(ny - 1, Math.max(0, Math.floor(p.y / 256))),
    };
}

function dzzTileCenterLatLng(z, x, y) {
    return map.unproject(L.point((x + 0.5) * 256, (y + 0.5) * 256), z);
}

function fillDzzTileForm(z, x, y) {
    const pairs = [
        ['opt-dzz-tile-z', z],
        ['dzz-bar-z', z],
        ['opt-dzz-tile-x', x],
        ['dzz-bar-x', x],
        ['opt-dzz-tile-y', y],
        ['dzz-bar-y', y],
    ];
    pairs.forEach(([id, value]) => {
        const el = document.getElementById(id);
        if (el && document.activeElement !== el) el.value = String(value);
    });
}

function updateTileDisplay(latlng) {
    const el = document.getElementById('tile-display');
    if (!el || !map) return;
    const t = getMapTileCoords(latlng, map.getZoom());
    el.textContent = `z/x/y ${t.z}/${t.x}/${t.y}`;
}

function highlightCenterTile() {
    if (!dzzTileGridLayer || !map) return;
    const t = getMapTileCoords();
    const root = dzzTileGridLayer._container;
    if (!root) return;
    root.querySelectorAll('.dzz-tile-cell.is-center').forEach((el) => el.classList.remove('is-center'));
    root.querySelectorAll(`.dzz-tile-cell[data-z="${t.z}"][data-x="${t.x}"][data-y="${t.y}"]`).forEach((el) => {
        el.classList.add('is-center');
    });
}

function updateDzzTileHud() {
    if (!map) return;
    const t = getMapTileCoords();
    updateTileDisplay(map.getCenter());
    const current = document.getElementById('dzz-tile-current');
    if (current) current.textContent = `Текущий тайл: ${t.z}/${t.x}/${t.y}`;
    if (!dzzTileInputsFocused()) fillDzzTileForm(t.z, t.x, t.y);
    highlightCenterTile();
    updateDzzDockSummary();
}

function readDzzTileForm() {
    const num = (id) => {
        const el = document.getElementById(id);
        return el && el.value !== '' ? Number(el.value) : NaN;
    };
    const z = Number.isFinite(num('dzz-bar-z')) ? num('dzz-bar-z') : num('opt-dzz-tile-z');
    const x = Number.isFinite(num('dzz-bar-x')) ? num('dzz-bar-x') : num('opt-dzz-tile-x');
    const y = Number.isFinite(num('dzz-bar-y')) ? num('dzz-bar-y') : num('opt-dzz-tile-y');
    return { z, x, y };
}

function goToDzzTile(z, x, y, silent = false) {
    if (!map) return;
    z = Math.round(Number(z));
    x = Math.round(Number(x));
    y = Math.round(Number(y));
    const { nx, ny } = tileGridSize(z);
    if (!Number.isFinite(z) || z < 0 || z > 22) {
        showToast('Укажите зум z от 0 до 22');
        return;
    }
    if (!Number.isFinite(x) || !Number.isFinite(y) || x < 0 || y < 0 || x >= nx || y >= ny) {
        showToast(`Для z=${z} индекс: x 0…${nx - 1}, y 0…${ny - 1}`);
        return;
    }
    dzzActiveSiteId = '';
    renderDzzSites();
    fillDzzTileForm(z, x, y);
    map.setView(dzzTileCenterLatLng(z, x, y), z, { animate: true });
    highlightCenterTile();
    if (!silent) {
        revealDzzDock('tiles');
        showToast(`Тайл ${z}/${x}/${y}`);
        logAction('tool', `Переход к тайлу ${z}/${x}/${y}`);
    }
}

function goToDzzTileFromForm() {
    const t = readDzzTileForm();
    goToDzzTile(t.z, t.x, t.y);
}

function shiftDzzTile(dx, dy) {
    const t = getMapTileCoords();
    const { nx, ny } = tileGridSize(t.z);
    const x = ((t.x + dx) % nx + nx) % nx;
    const y = Math.min(ny - 1, Math.max(0, t.y + dy));
    goToDzzTile(t.z, x, y);
}

function applyDzzTileGridLayer() {
    if (!map) return;
    const show = dzzTileGridOn && currentBasemap === 'dzz';
    const btn = document.getElementById('dzz-grid-toggle');
    const chk = document.getElementById('opt-dzz-tile-grid');
    if (btn) {
        btn.classList.toggle('is-active', dzzTileGridOn);
        btn.setAttribute('aria-pressed', dzzTileGridOn ? 'true' : 'false');
    }
    if (chk) chk.checked = dzzTileGridOn;
    if (show) {
        if (!dzzTileGridLayer) {
            dzzTileGridLayer = new DzzTileGridLayer({
                pane: 'dzzGridPane',
                tileSize: 256,
                minZoom: 3,
                maxZoom: 22,
                zIndex: 3,
            });
        }
        if (!map.hasLayer(dzzTileGridLayer)) dzzTileGridLayer.addTo(map);
        setTimeout(highlightCenterTile, 50);
    } else if (dzzTileGridLayer && map.hasLayer(dzzTileGridLayer)) {
        map.removeLayer(dzzTileGridLayer);
    }
}

function setDzzTileGrid(on) {
    dzzTileGridOn = !!on;
    applyDzzTileGridLayer();
}

function toggleDzzTileGrid() {
    setDzzTileGrid(!dzzTileGridOn);
}

function bindDzzTileFormSync() {
    ['z', 'x', 'y'].forEach((axis) => {
        const a = document.getElementById(`opt-dzz-tile-${axis}`);
        const b = document.getElementById(`dzz-bar-${axis}`);
        const sync = (from, to) => {
            if (!from || !to || from.dataset.syncBound) return;
            from.dataset.syncBound = '1';
            from.addEventListener('input', () => { to.value = from.value; });
            from.addEventListener('keydown', (e) => {
                if (e.key === 'Enter') {
                    e.preventDefault();
                    goToDzzTileFromForm();
                }
            });
        };
        sync(a, b);
        sync(b, a);
    });
}

function focusDzzCoverage() {
    if (!map || !dzzSites.length) return;
    const view = map.getBounds();
    const visible = dzzSites.some((site) => view.intersects(site.bounds));
    if (visible) return;
    if (dzzSites.length === 1) {
        goToDzzSite(dzzSites[0].id, true);
        return;
    }
    const all = L.latLngBounds(dzzSites[0].bounds);
    dzzSites.slice(1).forEach((site) => all.extend(site.bounds));
    map.fitBounds(all.pad(0.2), { maxZoom: 14, padding: [48, 48], animate: true });
}

async function loadDzzSites(urlTemplate, opts = {}) {
    const { silent = false, focus = true } = opts;
    const requestId = ++dzzSitesRequestId;
    const root = dzzImageServerRoot(urlTemplate || DZZ_DEFAULT_TILE_URL);
    const query = `${root}/query?where=1%3D1&outFields=Name&returnGeometry=true&outSR=4326&f=json`;
    try {
        const res = await dzzFetchResilient(query, DZZ_TILE_TIMEOUT_MS);
        if (requestId !== dzzSitesRequestId) return false;
        if (!res.ok) throw new Error('HTTP ' + res.status);
        const data = await res.json();
        if (data.error) throw new Error(data.error.message || 'DZZ_QUERY');
        dzzSites = parseDzzSites(data);
        dzzActiveSiteId = '';
        renderDzzSites();
        if (tileDzz && dzzSites.length) {
            const all = L.latLngBounds(dzzSites[0].bounds);
            dzzSites.slice(1).forEach((site) => all.extend(site.bounds));
            tileDzz.options.bounds = all.pad(0.05);
        }
        if (focus) focusDzzCoverage();
        setDzzConnStatus(dzzSites.length
            ? `Подключено: ${dzzSites.length} участок(ов) ортофото`
            : 'Подключение есть, но каталог участков пуст');
        if (!silent && dzzSites.length) showToast(`Найдено участков dzz.by: ${dzzSites.length}`);
        return true;
    } catch (err) {
        if (requestId !== dzzSitesRequestId) return false;
        dzzSites = [];
        renderDzzSites();
        setDzzConnStatus('Не удалось загрузить участки dzz.by');
        if (!silent) showToast('Не удалось получить участки dzz.by');
        console.warn(err);
        return false;
    }
}

function dzzErrorMessage(err) {
    if (err?.code === 'INVALID_CREDENTIALS') return 'Неверные логин или пароль dzz.by';
    if (err?.code === 'INVALID_URL') return 'Некорректный адрес подключения. Укажите URL ImageServer dzz.by';
    if (err?.code === 'MISSING_CREDENTIALS') return 'Укажите логин, пароль и адрес подключения';
    if (err?.code === 'DZZ_NOT_CONNECTED') return 'Сначала проверьте подключение к dzz.by';
    if (err?.code === 'WMTS_FETCH_FAILED' || err?.code === 'WMTS_PARSE' || err?.code === 'NO_CONTENTS') {
        return err.message || 'Не удалось разобрать WMTSCapabilities.xml';
    }
    if (err?.code === 'WMTS_TOO_LARGE') return 'WMTSCapabilities.xml слишком большой';
    if (err?.code === 'SERVICE_UNAVAILABLE') return 'Сервис dzz.by недоступен. Попробуйте позже.';
    if (err?.code === 'TLS_ERROR') return 'Не удалось проверить сертификат dzz.by. Перезапустите сервер командой npm start.';
    if (isNetworkAuthError(err) || err?.status >= 500) {
        return 'Сервис dzz.by недоступен. Проверьте запуск сервера приложения и попробуйте позже.';
    }
    if (err?.message && !/^[A-Z_]+$/.test(err.message)) return err.message;
    return 'Не удалось подключиться к dzz.by';
}

let wmtsCatalog = { dzz: null, custom: null };

function wmtsPrefix(source) {
    return source === 'dzz' ? 'opt-dzz-wmts' : 'opt-custom-wmts';
}

function wmtsMatrixLabel(matrix) {
    const bits = [matrix.id];
    if (matrix.wellKnown && matrix.wellKnown !== matrix.id) bits.push(matrix.wellKnown);
    if (matrix.crs) bits.push(matrix.crs);
    if (matrix.httpStatus === 520) bits.push('нет (520)');
    else if (matrix.reachable === false) bits.push('недоступна');
    else if (matrix.supported === false) bits.push('другая CRS');
    return bits.join(' · ');
}

function buildWmtsRestUrlClient(layer, matrix, styleId) {
    const format = (layer.formats || []).find((item) => /png/i.test(item)) || layer.formats?.[0] || 'image/png';
    const resource = (layer.resourceUrls || []).find((item) => item.resourceType === 'tile' && item.format === format)
        || (layer.resourceUrls || []).find((item) => item.resourceType === 'tile')
        || (layer.resourceUrls || [])[0];
    let template = resource?.template || layer.fallbackTemplate || '';
    if (!template) return '';
    const style = styleId || layer.defaultStyle || 'default';
    template = template
        .replaceAll('{Style}', style)
        .replaceAll('{style}', style)
        .replaceAll('{TileMatrixSet}', matrix.id)
        .replaceAll('{tileMatrixSet}', matrix.id)
        .replaceAll('{Layer}', layer.id)
        .replaceAll('{layer}', layer.id)
        .replaceAll('{Format}', format)
        .replaceAll('{format}', format)
        .replaceAll('{TileRow}', '{y}')
        .replaceAll('{TileCol}', '{x}')
        .replaceAll('{tileRow}', '{y}')
        .replaceAll('{tileCol}', '{x}');
    const token = matrix.tileMatrixPlaceholder && matrix.tileMatrixPlaceholder !== '{TileMatrix}'
        ? matrix.tileMatrixPlaceholder
        : (matrix.numericIds !== false ? '{z}' : '{TileMatrix}');
    template = template.replaceAll('{TileMatrix}', token).replaceAll('{tileMatrix}', token);
    return template;
}

function currentWmtsLayer(source) {
    const data = wmtsCatalog[source];
    if (!data) return null;
    const id = document.getElementById(`${wmtsPrefix(source)}-layer`)?.value || data.suggested?.layerId;
    return data.layers.find((layer) => layer.id === id) || data.layers[0] || null;
}

function updateWmtsHint(source) {
    const data = wmtsCatalog[source];
    const layer = currentWmtsLayer(source);
    const hint = document.getElementById(`${wmtsPrefix(source)}-hint`);
    if (!hint || !data || !layer) return;
    const matrixId = document.getElementById(`${wmtsPrefix(source)}-matrix`)?.value;
    const matrix = data.tileMatrixSets.find((item) => item.id === matrixId);
    if (!matrix) {
        hint.textContent = '';
        return;
    }
    if (matrix.wellKnown === 'GoogleMapsCompatible' && (source === 'dzz' || matrix.httpStatus === 520)) {
        hint.textContent = 'GoogleMapsCompatible: dzz.by отвечает 520, этой матрицы нет. Можно выбрать, но готовые тайлы не придут — ортофото пойдёт через exportImage.';
        return;
    }
    if (!matrix.supported) {
        hint.textContent = `Проекция ${matrix.crs}. Нужны EPSG:3857 или EPSG:4326.`;
        return;
    }
    if (matrix.crs === 'EPSG:4326') {
        if (source === 'dzz') {
            hint.textContent = 'EPSG:4326: dzz.by остаётся в Web Mercator. Эту матрицу не применяйте.';
            return;
        }
        hint.textContent = `EPSG:4326 (градусы): карта переключится из Web Mercator. Смещение зума ${matrix.zoomOffset}, уровни ${matrix.minNativeZoom}–${matrix.maxNativeZoom}.`;
        return;
    }
    hint.textContent = `REST {z}/{y}/{x}, смещение зума ${matrix.zoomOffset}, уровни ${matrix.minNativeZoom}–${matrix.maxNativeZoom}.`;
}

function renderWmtsMatrixAndStyle(source) {
    const data = wmtsCatalog[source];
    const layer = currentWmtsLayer(source);
    const prefix = wmtsPrefix(source);
    const matrixSel = document.getElementById(`${prefix}-matrix`);
    const styleSel = document.getElementById(`${prefix}-style`);
    if (!data || !layer) return;
    const setById = new Map(data.tileMatrixSets.map((item) => [item.id, item]));
    const matrices = (layer.tileMatrixSetIds?.length ? layer.tileMatrixSetIds : data.tileMatrixSets.map((item) => item.id))
        .map((id) => setById.get(id))
        .filter(Boolean);
    const suggestedId = data.suggested?.matrixSetId;
    if (matrixSel) {
        matrixSel.innerHTML = matrices.map((matrix) => {
            const selected = matrix.id === suggestedId ? ' selected' : '';
            return `<option value="${escapeHtml(matrix.id)}"${selected}>${escapeHtml(wmtsMatrixLabel(matrix))}</option>`;
        }).join('');
    }
    if (styleSel) {
        const styles = layer.styles?.length ? layer.styles : [{ id: layer.defaultStyle || 'default', title: 'default' }];
        styleSel.innerHTML = styles.map((style) => {
            const selected = style.id === (data.suggested?.styleId || layer.defaultStyle) ? ' selected' : '';
            return `<option value="${escapeHtml(style.id)}"${selected}>${escapeHtml(style.title || style.id)}</option>`;
        }).join('');
    }
    updateWmtsHint(source);
}

function fillWmtsSelects(source) {
    const data = wmtsCatalog[source];
    const panel = document.getElementById(source === 'dzz' ? 'dzz-wmts-panel' : 'custom-wmts-panel');
    if (panel) panel.hidden = !data?.layers?.length;
    if (!data?.layers?.length) return;
    const layerSel = document.getElementById(`${wmtsPrefix(source)}-layer`);
    const suggested = data.suggested || {};
    if (layerSel) {
        layerSel.innerHTML = data.layers.map((layer) => {
            const selected = layer.id === suggested.layerId ? ' selected' : '';
            return `<option value="${escapeHtml(layer.id)}"${selected}>${escapeHtml(layer.title || layer.id)}</option>`;
        }).join('');
    }
    renderWmtsMatrixAndStyle(source);
}

function onWmtsLayerChange(source) {
    renderWmtsMatrixAndStyle(source);
}

function onWmtsMatrixChange(source) {
    updateWmtsHint(source);
}

async function loadWmtsCatalog(source, opts = {}) {
    const silent = !!opts.silent;
    const isDzz = source === 'dzz';
    const url = isDzz
        ? (document.getElementById('opt-dzz-url')?.value.trim() || basemapExtra.dzzUrl || DZZ_DEFAULT_SERVICE)
        : (document.getElementById('opt-custom-basemap-url')?.value.trim() || basemapExtra.customUrl);
    const statusEl = document.getElementById(isDzz ? 'dzz-wmts-status' : 'custom-wmts-status');
    const setStatus = (text) => { if (statusEl) statusEl.textContent = text || ''; };
    if (!url) {
        setStatus('Укажите адрес сервиса');
        if (!silent) showToast('Укажите адрес WMTS или ImageServer');
        return null;
    }
    if (isDzz && !dzzSession.connected) {
        setStatus('Сначала проверьте подключение к dzz.by');
        if (!silent) showToast('Сначала проверьте подключение к dzz.by');
        return null;
    }
    setStatus('Загрузка WMTSCapabilities.xml…');
    try {
        const body = { url };
        if (!isDzz) {
            body.login = document.getElementById('opt-custom-basemap-login')?.value.trim() || '';
            body.password = document.getElementById('opt-custom-basemap-password')?.value || '';
        }
        const data = await apiFetch('/api/wmts/capabilities', {
            method: 'POST',
            body: JSON.stringify(body),
        });
        wmtsCatalog[source] = data;
        fillWmtsSelects(source);
        setStatus(data.suggested?.warning || `Слоёв: ${data.layers.length}, матриц: ${data.tileMatrixSets.length}`);
        return data;
    } catch (err) {
        wmtsCatalog[source] = null;
        fillWmtsSelects(source);
        const msg = dzzErrorMessage(err);
        setStatus(msg);
        if (!silent) showToast(msg);
        return null;
    }
}

function applyWmtsSelection(source) {
    const data = wmtsCatalog[source];
    const layer = currentWmtsLayer(source);
    if (!data || !layer) {
        showToast('Сначала загрузите WMTSCapabilities.xml');
        return;
    }
    const prefix = wmtsPrefix(source);
    const matrixId = document.getElementById(`${prefix}-matrix`)?.value;
    const styleId = document.getElementById(`${prefix}-style`)?.value || layer.defaultStyle;
    const matrix = data.tileMatrixSets.find((item) => item.id === matrixId);
    if (!matrix) {
        showToast('Выберите матрицу тайлов');
        return;
    }
    if (!matrix.supported) {
        showToast('Эта матрица не EPSG:3857 и не EPSG:4326.');
        return;
    }
    if (source === 'dzz' && matrix.crs === 'EPSG:4326') {
        showToast('dzz.by работает только в Web Mercator (EPSG:3857).');
        return;
    }
    const tileUrl = buildWmtsRestUrlClient(layer, matrix, styleId);
    if (!tileUrl || (!tileUrl.includes('{z}') && !tileUrl.includes('{TileMatrix}'))) {
        showToast('Не удалось собрать REST URL тайлов');
        return;
    }
    if (matrix.wellKnown === 'GoogleMapsCompatible' && source === 'dzz') {
        showToast('GoogleMapsCompatible у dzz.by отвечает 520. Тайлы этой матрицы не придут.');
    }
    if (source === 'dzz') {
        const urlEl = document.getElementById('opt-dzz-url');
        if (urlEl) urlEl.value = tileUrl;
        basemapExtra.dzzUrl = tileUrl;
        persistBasemapExtra();
        if (dzzSession.connected) setBasemap('dzz', true);
        setDzzConnStatus(`WMTS: ${layer.title || layer.id} / ${matrix.id}`);
    } else {
        const urlEl = document.getElementById('opt-custom-basemap-url');
        if (urlEl) urlEl.value = tileUrl;
        const nameEl = document.getElementById('opt-custom-basemap-name');
        if (nameEl && !nameEl.value.trim()) nameEl.value = layer.title || 'WMTS';
        basemapExtra.customCrs = matrix.crs === 'EPSG:4326' ? 'EPSG:4326' : 'EPSG:3857';
        basemapExtra.customZoomOffset = Number.isFinite(matrix.zoomOffset) ? matrix.zoomOffset : 0;
        basemapExtra.customMinNativeZoom = Number.isFinite(matrix.minNativeZoom) ? matrix.minNativeZoom : 0;
        basemapExtra.customMaxNativeZoom = Number.isFinite(matrix.maxNativeZoom) ? matrix.maxNativeZoom : 19;
        readBasemapExtraFromForm();
        persistBasemapExtra();
        const select = document.getElementById('opt-basemap');
        if (select) select.value = 'custom';
        displaySettings.basemap = 'custom';
        setBasemap('custom');
    }
    if (!(matrix.wellKnown === 'GoogleMapsCompatible' && source === 'dzz')) {
        const crsNote = matrix.crs === 'EPSG:4326' ? ' · карта в EPSG:4326' : '';
        showToast(`WMTS: ${matrix.id}${crsNote}`);
    }
    logAction('tool', `WMTS слой ${layer.id}, матрица ${matrix.id}`);
}

async function restoreDzzSession(opts = {}) {
    const skipHealth = !!opts.skipHealth;
    try {
        const data = await apiFetch('/api/dzz/status');
        dzzSession.connected = !!data.connected;
        if (data.url) {
            const current = document.getElementById('opt-dzz-url')?.value.trim() || basemapExtra.dzzUrl || '';
            const keepWmts = /\/WMTS\/tile\//i.test(current);
            if (!keepWmts) {
                basemapExtra.dzzUrl = data.url;
                const urlEl = document.getElementById('opt-dzz-url');
                if (urlEl) urlEl.value = data.url;
            }
        }
        if (dzzSession.connected) {
            setDzzConnStatus('Сессия dzz.by активна на сервере');
            loadWmtsCatalog('dzz', { silent: true });
        }
    } catch {
        // Сервер мог быть перезапущен: cookie и диск ещё поднимут сессию.
    }
    if (!skipHealth) updateDzzNetworkStatus();
    return dzzSession.connected;
}

async function testDzzAccess() {
    const login = (document.getElementById('opt-dzz-login')?.value || '').trim();
    const password = document.getElementById('opt-dzz-password')?.value || '';
    const url = (document.getElementById('opt-dzz-url')?.value || '').trim() || DZZ_DEFAULT_TILE_URL;
    if (!login || !password) {
        setDzzConnStatus('Укажите логин и пароль dzz.by');
        showToast('Укажите логин и пароль dzz.by');
        return false;
    }
    setDzzConnStatus('Проверка подключения…');
    try {
        const data = await apiFetch('/api/dzz/connect', {
            method: 'POST',
            body: JSON.stringify({ login, password, url }),
        });
        const passwordEl = document.getElementById('opt-dzz-password');
        if (passwordEl) passwordEl.value = '';
        dzzSession.connected = true;
        basemapExtra.dzzUrl = data.url || resolveDzzTileTemplate(url).url;
        const urlEl = document.getElementById('opt-dzz-url');
        if (urlEl) urlEl.value = basemapExtra.dzzUrl;
        persistBasemapExtra();
        const select = document.getElementById('opt-basemap');
        if (select) select.value = 'dzz';
        displaySettings.basemap = 'dzz';
        localStorage.setItem(displaySettingsKey(), JSON.stringify(displaySettings));
        setBasemap('dzz', true);
        updateDzzNetworkStatus();
        showToast('Ортофото dzz.by подключено');
        loadWmtsCatalog('dzz', { silent: true });
        return true;
    } catch (err) {
        dzzSession.connected = false;
        const msg = dzzErrorMessage(err);
        setDzzConnStatus(msg);
        showToast(msg);
        const select = document.getElementById('opt-basemap');
        if (select && currentBasemap !== 'dzz') select.value = currentBasemap || 'satellite';
        return false;
    }
}

document.addEventListener('click', (e) => {
    const target = e.target.closest('[data-dzz-site]');
    if (!target) return;
    goToDzzSite(target.getAttribute('data-dzz-site'));
});
let layersRegistry = [];
let foldersRegistry = [];
let expandedLayers = new Set();
let activeLayerId = null;
let activeTool = 'select';
let rulerPoints = [];
let rulerLine = null, rulerMarkers = [], rulerLabel = null, rulerTicks = [];
let selectedFeatures = [];
let selectedFieldLayer = null;
let selectedFieldLayerId = null;
let vertexMarkers = [];
let activeDrawHandler = null;
let compassCenter = null;
let compassLayer = null;
let textLayerGroup = null;
let overlaysLayerGroup = null;
let uploadedFile = null;
let aoiLayer = null;
let aoiBounds = null;
let aoiDrawHandler = null;
let lastMapCapture = null;
let undoStack = [];
let selectedOverlay = null;
let editDrawMode = null;
let freehandActive = false;
let freehandPath = [];
let freehandPreviewLayer = null;
let brushCursorLayer = null;
let createSessionActive = false;
let draftCreatePolygon = null;
let draftCreateLayerId = null;
let pendingFolderAssign = null;
let eraserLastLatLng = null;
let eraserUndoBefore = null;
let eraserTargetLayer = null;
let eraserDidChange = false;
let _modalActionHandlers = [];
let compassPreviewCircle = null;
let compassPreviewLabel = null;
let mapMouseMoveHandler = null;
let redoStack = [];
let analysisComplete = false;
let fieldLabelsLayerGroup = null;
let rulerPreviewGroup = null;
let mapDisplay = { labels: true, coords: true };
let fieldDetailCollapsed = false;
let collapsedGroups = new Set();
const POINT_RADIUS_M = 5; // только для авто-детекции (симуляция анализа)
// точечный слой рисуется вручную так же, как остальные — без сжатия формы

const DETECTION_CONFIG = [
    { id: 'crops', opt: 'opt-crops', kind: 'polygon' },
    { id: 'points', opt: 'opt-points', kind: 'point' },
    { id: 'double_sow', opt: 'opt-double-sow', kind: 'polygon' },
    { id: 'withering', opt: 'opt-withering', kind: 'polygon' },
    { id: 'edge_strip', opt: 'opt-edge-strip', kind: 'polygon' },
    { id: 'nutrition', opt: 'opt-nutrition', kind: 'polygon' },
    { id: 'seeder_skip', opt: 'opt-seeder-skip', kind: 'polygon' },
    { id: 'hail', opt: 'opt-hail', kind: 'polygon' },
    { id: 'flood', opt: 'opt-flood', kind: 'polygon' },
    { id: 'watercourse', opt: 'opt-watercourse', kind: 'polygon' },
    { id: 'weeds', opt: 'opt-weeds', kind: 'polygon' },
];

/** Маппинг label YOLO → id слоя на карте (контракт Agriculture-Vision API). */
const ML_LABEL_TO_LAYER = {
    field: 'crops',
    double_plant: 'double_sow',
    drydown: 'withering',
    endrow: 'edge_strip',
    nutrient_deficiency: 'nutrition',
    planter_skip: 'seeder_skip',
    storm_damage: 'hail',
    water: 'flood',
    waterway: 'watercourse',
    weed_cluster: 'weeds',
};
const SEGFORMER_FIELD_LAYER = 'crops';

function getMapGeoBounds() {
    if (aoiBounds && aoiBounds.isValid()) {
        return {
            south: aoiBounds.getSouth(),
            north: aoiBounds.getNorth(),
            west: aoiBounds.getWest(),
            east: aoiBounds.getEast(),
        };
    }
    const b = map.getBounds();
    return {
        south: b.getSouth(),
        north: b.getNorth(),
        west: b.getWest(),
        east: b.getEast(),
    };
}

/** Пиксели снимка → lat/lng в CRS захвата (3857 или 4326). */
function pixelRingToLatLng(ring, imageHw, geoBounds) {
    const [h, w] = imageHw;
    const dh = Math.max(1, h - 1);
    const dw = Math.max(1, w - 1);
    const captureCrs = lastMapCapture?.mode === 'dzz-export'
        ? 'EPSG:3857'
        : (lastMapCapture?.crs || currentMapCrs());
    const crs = captureCrs === 'EPSG:4326' ? L.CRS.EPSG4326 : L.CRS.EPSG3857;
    const topLeft = crs.project(L.latLng(geoBounds.north, geoBounds.west));
    const bottomRight = crs.project(L.latLng(geoBounds.south, geoBounds.east));
    return ring.map(([x, y]) => {
        const mx = topLeft.x + (x / dw) * (bottomRight.x - topLeft.x);
        const my = topLeft.y + (y / dh) * (bottomRight.y - topLeft.y);
        const ll = crs.unproject(L.point(mx, my));
        return [ll.lat, ll.lng];
    });
}

function isDetectionLayerEnabled(layerId) {
    const cfg = DETECTION_CONFIG.find(c => c.id === layerId);
    if (!cfg) return true;
    const el = document.getElementById(cfg.opt);
    return el ? el.checked : true;
}

async function fetchMlHealth() {
    const res = await fetch('/api/v1/segmentation/health', { credentials: 'include' });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
        throw new Error(data.detail || 'ML health failed');
    }
    return data;
}

function getSelectedArchitecture() {
    const checked = document.querySelector('input[name="seg-architecture"]:checked');
    return checked?.value || localStorage.getItem('ttz_ml_architecture') || 'yolo';
}

function onSegArchitectureChange() {
    const arch = getSelectedArchitecture();
    localStorage.setItem('ttz_ml_architecture', arch);
}

function onSegThresholdInput(value) {
    const pct = parseInt(value, 10) || 40;
    const label = document.getElementById('seg-threshold-value');
    if (label) label.innerText = pct + '%';
    const seg = document.getElementById('seg-threshold');
    if (seg && String(seg.value) !== String(pct)) seg.value = String(pct);
    localStorage.setItem('ttz_seg_threshold', String(pct));
}

function getSegmentationThreshold() {
    const seg = document.getElementById('seg-threshold');
    const confPct = parseInt(seg?.value || '40', 10);
    return Math.min(1, Math.max(0, confPct / 100));
}

function setSegmentButtonsEnabled(enabled) {
    ['btn-segment-yolo', 'btn-segment-segformer', 'upload-process-btn', 'map-btn-aoi'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.disabled = !enabled;
    });
}

function setMapSegStatus(text, isError = false) {
    const el = document.getElementById('map-seg-status');
    if (!el) return;
    el.textContent = text;
    el.style.color = isError ? '#dc2626' : '#64748b';
}

function setMapSegProgress(pct) {
    const wrap = document.getElementById('map-seg-progress');
    const bar = document.getElementById('map-seg-progress-bar');
    if (!wrap || !bar) return;
    if (pct == null) {
        wrap.style.display = 'none';
        bar.style.width = '0%';
        return;
    }
    wrap.style.display = 'block';
    bar.style.width = Math.max(0, Math.min(100, pct)) + '%';
}

function initSegControls() {
    const savedArch = localStorage.getItem('ttz_ml_architecture') || 'yolo';
    const radio = document.querySelector(`input[name="seg-architecture"][value="${savedArch}"]`);
    if (radio) radio.checked = true;
    const savedThr = localStorage.getItem('ttz_seg_threshold');
    const thr = savedThr ? parseInt(savedThr, 10) : 40;
    onSegThresholdInput(String(Number.isFinite(thr) ? thr : 40));
    updateAoiStatus();
    setSegmentButtonsEnabled(true);
}

function updateAoiStatus() {
    if (aoiBounds && aoiBounds.isValid()) {
        setMapSegStatus('Область выделена — можно сегментировать');
    } else {
        setMapSegStatus('Выделите область на карте или сегментируйте весь кадр');
    }
}

function clearAoiSelection() {
    if (aoiDrawHandler) {
        try { aoiDrawHandler.disable(); } catch { /* ignore */ }
        aoiDrawHandler = null;
    }
    if (aoiLayer && map) map.removeLayer(aoiLayer);
    aoiLayer = null;
    aoiBounds = null;
    updateAoiStatus();
    showToast('Область сброшена');
    logAction('tool', 'Сброшена область сегментации');
}

function startAoiSelection() {
    if (!map || !window.L?.Draw) {
        alert('Карта ещё не готова');
        return;
    }
    deactivateCurrentTool();
    activeTool = 'aoi';
    document.querySelectorAll('.tool-btn[data-tool]').forEach(btn => btn.classList.remove('active'));

    if (aoiDrawHandler) {
        try { aoiDrawHandler.disable(); } catch { /* ignore */ }
    }

    aoiDrawHandler = new L.Draw.Rectangle(map, {
        shapeOptions: {
            color: '#e14059',
            weight: 2,
            fillColor: '#e14059',
            fillOpacity: 0.12,
            dashArray: '6 4',
        },
    });
    aoiDrawHandler.enable();
    setMapSegStatus('Потяните прямоугольник на карте…');
    showToast('Потяните прямоугольник на карте');
    logAction('tool', 'Выделение области для сегментации');

    map.once(L.Draw.Event.CREATED, (e) => {
        if (aoiLayer) map.removeLayer(aoiLayer);
        aoiLayer = e.layer;
        aoiLayer.addTo(map);
        aoiBounds = aoiLayer.getBounds();
        aoiDrawHandler = null;
        raiseWorkingOverlays();
        updateAoiStatus();
        showToast('Область выделена');
        logAction('tool', 'Область сегментации выделена');
    });
}

const MAP_CAPTURE_TILE = 256;
const MAP_CAPTURE_MAX_EDGE = 2048;
const MAP_CAPTURE_MAX_ZOOM = 18;

function getActiveBasemapTileUrl(z, x, y, forceEsri = false) {
    if (!forceEsri && currentBasemap === 'scheme') {
        const s = ['a', 'b', 'c'][(x + y) % 3];
        return `https://${s}.tile.openstreetmap.org/${z}/${x}/${y}.png`;
    }
    if (!forceEsri && currentBasemap === 'dzz') {
        const root = dzzImageServerRoot(basemapExtra.dzzUrl);
        if (z > DZZ_CACHE_MAX_Z || z < DZZ_CACHE_MIN_Z) {
            return dzzExportImageUrl(root, { z, x, y }, 256, 'png');
        }
        const serviceZ = z - 8;
        if (serviceZ >= 0) return `${root}/tile/${serviceZ}/${y}/${x}`;
    }
    if (!forceEsri && currentBasemap === 'custom' && basemapExtra.customUrl) {
        const resolved = resolveXyzTileTemplate(basemapExtra.customUrl);
        const serviceZ = z + (resolved?.zoomOffset || 0);
        return (resolved?.url || '')
            .replaceAll('{z}', String(serviceZ))
            .replaceAll('{x}', String(x))
            .replaceAll('{y}', String(y));
    }
    if (forceEsri && currentMapCrs() === 'EPSG:4326') return '';
    return `https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/${z}/${y}/${x}`;
}

function loadCorsImage(url) {
    return new Promise((resolve, reject) => {
        const img = new Image();
        img.crossOrigin = 'anonymous';
        img.onload = () => resolve(img);
        img.onerror = () => reject(new Error(`Не удалось загрузить тайл: ${url}`));
        img.src = url;
    });
}

function loadCaptureTileImage(url) {
    if (currentBasemap !== 'dzz') return loadCorsImage(url);
    return dzzFetchResilient(url, DZZ_TILE_TIMEOUT_MS)
        .then((res) => {
            if (!res.ok) throw new Error('TILE_HTTP_' + res.status);
            return res.blob();
        })
        .then((blob) => new Promise((resolve, reject) => {
            const img = new Image();
            const obj = URL.createObjectURL(blob);
            img.onload = () => {
                URL.revokeObjectURL(obj);
                resolve(img);
            };
            img.onerror = () => {
                URL.revokeObjectURL(obj);
                reject(new Error('dzz tile'));
            };
            img.src = obj;
        }));
}

function chooseCaptureZoom(bounds) {
    let z = Math.min(MAP_CAPTURE_MAX_ZOOM, Math.max(1, Math.round(map.getZoom())));
    while (z < MAP_CAPTURE_MAX_ZOOM) {
        const nw = map.project(bounds.getNorthWest(), z + 1);
        const se = map.project(bounds.getSouthEast(), z + 1);
        const w = Math.abs(se.x - nw.x);
        const h = Math.abs(se.y - nw.y);
        if (Math.max(w, h) > MAP_CAPTURE_MAX_EDGE) break;
        z += 1;
    }
    while (z < MAP_CAPTURE_MAX_ZOOM) {
        const nw = map.project(bounds.getNorthWest(), z);
        const se = map.project(bounds.getSouthEast(), z);
        if (Math.min(Math.abs(se.x - nw.x), Math.abs(se.y - nw.y)) >= 256) break;
        z += 1;
    }
    return z;
}

async function captureDzzRegionAsFile(bounds) {
    const root = dzzImageServerRoot(basemapExtra.dzzUrl);
    const sw = L.CRS.EPSG3857.project(bounds.getSouthWest());
    const ne = L.CRS.EPSG3857.project(bounds.getNorthEast());
    const xmin = Math.min(sw.x, ne.x);
    const xmax = Math.max(sw.x, ne.x);
    const ymin = Math.min(sw.y, ne.y);
    const ymax = Math.max(sw.y, ne.y);
    const aspect = (xmax - xmin) / Math.max(1, ymax - ymin);
    let w = MAP_CAPTURE_MAX_EDGE;
    let h = MAP_CAPTURE_MAX_EDGE;
    if (aspect >= 1) h = Math.max(64, Math.round(w / aspect));
    else w = Math.max(64, Math.round(h * aspect));
    const url = `${root}/exportImage?bbox=${xmin},${ymin},${xmax},${ymax}&bboxSR=3857&imageSR=3857&size=${w},${h}&format=jpg&f=image`;
    const res = await dzzFetchResilient(url, DZZ_CAPTURE_TIMEOUT_MS);
    if (!res.ok) throw new Error('DZZ_CAPTURE_' + res.status);
    const blob = await res.blob();
    if (!blob || blob.size < 400) throw new Error('DZZ_CAPTURE_EMPTY');
    lastMapCapture = {
        mode: 'dzz-export',
        zoom: map.getZoom(),
        crs: 'EPSG:3857',
        width: w,
        height: h,
        geoBounds: {
            north: bounds.getNorth(),
            south: bounds.getSouth(),
            west: bounds.getWest(),
            east: bounds.getEast(),
        },
    };
    return new File([blob], `map_aoi_dzz_${Date.now()}.jpg`, { type: 'image/jpeg' });
}

async function captureMapRegionAsFile() {
    if (!map) throw new Error('Карта ещё не готова');

    let bounds = (aoiBounds && aoiBounds.isValid()) ? aoiBounds : map.getBounds();
    bounds = L.latLngBounds(
        [
            Math.max(bounds.getSouth(), map.getBounds().getSouth()),
            Math.max(bounds.getWest(), map.getBounds().getWest()),
        ],
        [
            Math.min(bounds.getNorth(), map.getBounds().getNorth()),
            Math.min(bounds.getEast(), map.getBounds().getEast()),
        ],
    );
    if (!bounds.isValid() || bounds.getSouth() >= bounds.getNorth() || bounds.getWest() >= bounds.getEast()) {
        bounds = map.getBounds();
    }

    if (currentBasemap === 'dzz' && dzzSession.connected) {
        try {
            return await captureDzzRegionAsFile(bounds);
        } catch (err) {
            console.warn('dzz capture fallback', err);
        }
    }

    const zoom = chooseCaptureZoom(bounds);
    const nwPix = map.project(bounds.getNorthWest(), zoom);
    const sePix = map.project(bounds.getSouthEast(), zoom);
    const minX = Math.min(nwPix.x, sePix.x);
    const maxX = Math.max(nwPix.x, sePix.x);
    const minY = Math.min(nwPix.y, sePix.y);
    const maxY = Math.max(nwPix.y, sePix.y);

    let outW = Math.max(64, Math.round(maxX - minX));
    let outH = Math.max(64, Math.round(maxY - minY));
    const scale = Math.min(1, MAP_CAPTURE_MAX_EDGE / Math.max(outW, outH));
    outW = Math.max(64, Math.round(outW * scale));
    outH = Math.max(64, Math.round(outH * scale));

    const tileMinX = Math.floor(minX / MAP_CAPTURE_TILE);
    const tileMaxX = Math.floor((maxX - 1e-6) / MAP_CAPTURE_TILE);
    const tileMinY = Math.floor(minY / MAP_CAPTURE_TILE);
    const tileMaxY = Math.floor((maxY - 1e-6) / MAP_CAPTURE_TILE);
    const { nx, ny } = tileGridSize(zoom);

    const mosaicW = (tileMaxX - tileMinX + 1) * MAP_CAPTURE_TILE;
    const mosaicH = (tileMaxY - tileMinY + 1) * MAP_CAPTURE_TILE;
    const mosaic = document.createElement('canvas');
    mosaic.width = mosaicW;
    mosaic.height = mosaicH;
    const mctx = mosaic.getContext('2d');
    mctx.fillStyle = '#1a1a1a';
    mctx.fillRect(0, 0, mosaicW, mosaicH);

    const allowEsriFallback = currentMapCrs() !== 'EPSG:4326';
    const jobs = [];
    for (let ty = tileMinY; ty <= tileMaxY; ty++) {
        for (let tx = tileMinX; tx <= tileMaxX; tx++) {
            const wrappedX = ((tx % nx) + nx) % nx;
            if (ty < 0 || ty >= ny) continue;
            const url = getActiveBasemapTileUrl(zoom, wrappedX, ty);
            const dx = (tx - tileMinX) * MAP_CAPTURE_TILE;
            const dy = (ty - tileMinY) * MAP_CAPTURE_TILE;
            jobs.push(
                loadCaptureTileImage(url)
                    .then(img => { mctx.drawImage(img, dx, dy); })
                    .catch(() => {
                        if (!allowEsriFallback) return;
                        return loadCorsImage(getActiveBasemapTileUrl(zoom, wrappedX, ty, true))
                            .then(img => { mctx.drawImage(img, dx, dy); })
                            .catch(() => { /* битый тайл */ });
                    }),
            );
        }
    }
    await Promise.all(jobs);

    const cropX = minX - tileMinX * MAP_CAPTURE_TILE;
    const cropY = minY - tileMinY * MAP_CAPTURE_TILE;
    const srcW = Math.max(1, maxX - minX);
    const srcH = Math.max(1, maxY - minY);

    const out = document.createElement('canvas');
    out.width = outW;
    out.height = outH;
    const octx = out.getContext('2d');
    octx.imageSmoothingEnabled = true;
    octx.imageSmoothingQuality = 'high';
    octx.drawImage(mosaic, cropX, cropY, srcW, srcH, 0, 0, outW, outH);

    const geoBounds = {
        north: bounds.getNorth(),
        south: bounds.getSouth(),
        west: bounds.getWest(),
        east: bounds.getEast(),
    };
    lastMapCapture = {
        mode: 'tiles',
        zoom,
        crs: currentMapCrs(),
        width: outW,
        height: outH,
        geoBounds: { ...geoBounds },
    };

    const blob = await new Promise((resolve, reject) => {
        out.toBlob(b => (b ? resolve(b) : reject(new Error('toBlob failed'))), 'image/jpeg', 0.92);
    });
    return new File([blob], `map_aoi_${Date.now()}.jpg`, { type: 'image/jpeg' });
}

async function callSegmentationApi(file, architecture, threshold) {
    const form = new FormData();
    form.append('file', file, file.name || 'upload.png');
    const params = new URLSearchParams({
        architecture,
        include_mask_png: 'false',
        include_geojson: 'false',
        threshold: String(threshold),
    });
    const res = await fetch(`/api/v1/segmentation/segment?${params}`, {
        method: 'POST',
        body: form,
        credentials: 'include',
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
        const detail = typeof data.detail === 'string'
            ? data.detail
            : JSON.stringify(data.detail || data);
        throw new Error(detail || `HTTP ${res.status}`);
    }
    return data;
}

function applyApiSegmentationResult(result, architecture, geoBounds) {
    const allBounds = [];
    let count = 0;
    const imageHw = result.image_hw || [512, 512];

    if (architecture === 'segformer' && result.navigable?.valid && result.navigable.polygon_px?.length >= 3) {
        if (isDetectionLayerEnabled(SEGFORMER_FIELD_LAYER)) {
            const coords = pixelRingToLatLng(result.navigable.polygon_px, imageHw, geoBounds);
            const poly = addDetectedPolygon(SEGFORMER_FIELD_LAYER, coords);
            if (poly) {
                allBounds.push(poly.getBounds());
                count++;
            }
        }
    } else if (Array.isArray(result.detections)) {
        for (const det of result.detections) {
            if (det.valid === false || !det.polygon_px?.length) continue;
            const layerId = ML_LABEL_TO_LAYER[det.label];
            if (!layerId || !isDetectionLayerEnabled(layerId)) continue;
            const coords = pixelRingToLatLng(det.polygon_px, imageHw, geoBounds);
            const poly = addDetectedPolygon(layerId, coords);
            if (poly) {
                allBounds.push(poly.getBounds());
                count++;
            }
        }
    }

    return { count, allBounds };
}

function finalizeAnalysisOnMap(allBounds) {
    analysisComplete = true;
    if (allBounds.length) {
        const bounds = allBounds.reduce(
            (acc, b) => acc.extend(b),
            L.latLngBounds(allBounds[0].getSouthWest(), allBounds[0].getNorthEast()),
        );
        map.fitBounds(bounds, { maxZoom: 15, padding: [30, 30] });
    }
    renderLayersList(document.getElementById('layer-search')?.value);
    renderLegend();
    renderFieldLabels();
    populateDrawLayerSelect();
}

function foldersKey() { return 'ttz_folders_' + getCurrentEmail(); }
function layerMetaKey() { return 'ttz_layer_meta_' + getCurrentEmail(); }
function objectFoldersKey() { return 'ttz_object_folders_' + getCurrentEmail(); }

function saveFoldersState() {
    const email = getCurrentEmail();
    if (!email) return;
    localStorage.setItem(foldersKey(), JSON.stringify(foldersRegistry));
    const meta = layersRegistry.map(l => ({ id: l.id, folderId: l.folderId }));
    localStorage.setItem(layerMetaKey(), JSON.stringify(meta));
    const objectFolders = [];
    layersRegistry.forEach(entry => {
        entry.group.eachLayer(layer => {
            if (layer._fieldMeta?.objectFolderId) {
                objectFolders.push({
                    layerId: entry.id,
                    metaId: layer._fieldMeta.id,
                    folderId: layer._fieldMeta.objectFolderId,
                });
            }
        });
    });
    localStorage.setItem(objectFoldersKey(), JSON.stringify(objectFolders));
}

function loadFoldersState() {
    const email = getCurrentEmail();
    if (!email) return;
    try {
        const saved = JSON.parse(localStorage.getItem(foldersKey()) || '[]');
        if (Array.isArray(saved) && saved.length) foldersRegistry = saved;
        const meta = JSON.parse(localStorage.getItem(layerMetaKey()) || '[]');
        meta.forEach(m => {
            const entry = findLayerEntry(m.id);
            if (entry) entry.folderId = m.folderId || null;
        });
        const objectFolders = JSON.parse(localStorage.getItem(objectFoldersKey()) || '[]');
        objectFolders.forEach(ref => {
            const entry = findLayerEntry(ref.layerId);
            if (!entry) return;
            entry.group.eachLayer(layer => {
                if (layer._fieldMeta?.id === ref.metaId) layer._fieldMeta.objectFolderId = ref.folderId;
            });
        });
        renderFoldersList();
        renderLayersList(document.getElementById('layer-search')?.value);
    } catch { /* ignore */ }
}

function isLayerListedInSidebar(entry) {
    if (!entry) return false;
    if (entry.detected) return true;
    if (isCustomLayer(entry)) return true;
    if (String(entry.id).startsWith('imported_')) return true;
    return false;
}

const NO_CROP_LAYER_IDS = new Set([
    'points', 'seeder_skip', 'watercourse', 'edge_strip', 'flood', 'weeds',
]);
function layerSupportsCrop(layerId) {
    return !NO_CROP_LAYER_IDS.has(layerId);
}

function getNextObjectNumber() {
    let max = 0;
    layersRegistry.forEach(entry => {
        entry.group.eachLayer(layer => {
            if (layer._fieldMeta?.objectNumber) max = Math.max(max, layer._fieldMeta.objectNumber);
        });
    });
    return max + 1;
}

function initFieldMeta(layer, layerId, opts = {}) {
    const num = getNextObjectNumber();
    const hasCrop = layerSupportsCrop(layerId);
    const manual = !!opts.manual;
    layer._fieldMeta = {
        id: 'field_' + Date.now() + '_' + Math.random().toString(36).slice(2, 7),
        objectNumber: num,
        name: `Объект ${num}`,
        source: manual ? 'manual' : 'detected',
        crops: (hasCrop && !manual) ? generateCropProbabilities() : [],
        confirmedCrop: null,
        confirmed: false,
        objectFolderId: null,
    };
    return layer._fieldMeta;
}

function isManualField(layer) {
    return layer?._fieldMeta?.source === 'manual';
}

/** Папка, в которой «живёт» весь слой: folderId или все объекты в одной папке. */
function getLayerHomeFolderId(entry) {
    if (!entry) return null;
    if (entry.folderId) return entry.folderId;
    const layers = entry.group.getLayers();
    if (!layers.length) return null;
    let folder = null;
    for (const layer of layers) {
        ensureFieldMeta(layer, entry.id);
        const fid = layer._fieldMeta.objectFolderId || null;
        if (fid == null) return null;
        if (folder == null) folder = fid;
        else if (folder !== fid) return null;
    }
    return folder;
}

const STANDARD_LAYER_IDS = new Set([
    'points', 'crops', 'double_sow', 'withering', 'edge_strip', 'nutrition',
    'seeder_skip', 'hail', 'flood', 'watercourse', 'weeds',
]);
function isCustomLayer(entry) {
    return entry && !STANDARD_LAYER_IDS.has(entry.id);
}

const DEFAULT_LAYERS = [
    { id: 'points', name: 'Точечные объекты', color: '#e14059', coords: [] },
    { id: 'crops', name: 'Культурные растения', color: '#f59e0b', coords: [] },
    { id: 'double_sow', name: 'Двойной посев', color: '#a855f7', coords: [] },
    { id: 'withering', name: 'Усыхание посева', color: '#84cc16', coords: [] },
    { id: 'edge_strip', name: 'Краевая полоса', color: '#06b6d4', coords: [] },
    { id: 'nutrition', name: 'Дефицит питания', color: '#f97316', coords: [] },
    { id: 'seeder_skip', name: 'Пропуск сеялки', color: '#ec4899', coords: [] },
    { id: 'hail', name: 'Повреждение бурей', color: '#6366f1', coords: [] },
    { id: 'flood', name: 'Затопление', color: '#0ea5e9', coords: [] },
    { id: 'watercourse', name: 'Водоток', color: '#14b8a6', coords: [] },
    { id: 'weeds', name: 'Скопление сорняков', color: '#22c55e', coords: [] },
];

function createBasemapTileLayers() {
    const basemapCommon = {
        maxZoom: 22,
        minZoom: 3,
        keepBuffer: 2,
        updateWhenZooming: false,
        updateWhenIdle: true,
        crossOrigin: true,
    };
    tileSatellite = L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}', {
        ...basemapCommon,
        maxNativeZoom: 19,
        attribution: 'Tiles © Esri',
        zIndex: 1,
    });
    tileScheme = L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        ...basemapCommon,
        maxNativeZoom: 19,
        subdomains: 'abc',
        attribution: '© OpenStreetMap',
        zIndex: 1,
    });
}

function bindMapChromeEvents() {
    const coordsDisplay = document.getElementById('coords-display');
    map.on('mousemove', (e) => {
        if (coordsDisplay) coordsDisplay.innerText = `${e.latlng.lat.toFixed(5)}°N ${e.latlng.lng.toFixed(5)}°E`;
        updateTileDisplay(e.latlng);
    });
    map.on('zoomend moveend', () => {
        updateScaleDisplay();
        updateDzzTileHud();
        scheduleDzzPrefetch();
    });
    map.on('click', onMapClick);
    updateScaleDisplay();
    updateCrsDisplay();
    updateDzzTileHud();
}

function createLeafletMap(crsCode, view) {
    const nextCrs = crsCode === 'EPSG:4326' ? 'EPSG:4326' : 'EPSG:3857';
    mapCrsCode = nextCrs;
    const center = view?.center || [53.9, 27.56];
    const zoom = view?.zoom != null ? view.zoom : 13;
    map = L.map('map', {
        crs: leafletCrsFor(nextCrs),
        zoomControl: false,
        minZoom: 3,
        maxZoom: 22,
        worldCopyJump: true,
    }).setView(center, zoom, { animate: false });
    window.map = map;

    map.createPane('dzzGridPane');
    const gridPane = map.getPane('dzzGridPane');
    if (gridPane) {
        gridPane.style.zIndex = 350;
        gridPane.style.pointerEvents = 'none';
    }

    const tilePane = map.getPane('tilePane');
    if (tilePane) tilePane.style.pointerEvents = 'none';

    L.control.zoom({ position: 'bottomleft' }).addTo(map);
    createBasemapTileLayers();
    bindMapChromeEvents();
}

function recreateMap(crsCode) {
    const view = map ? { center: map.getCenter(), zoom: map.getZoom() } : null;
    if (typeof deactivateCurrentTool === 'function') deactivateCurrentTool();
    if (dzzTileGridLayer && map?.hasLayer(dzzTileGridLayer)) {
        map.removeLayer(dzzTileGridLayer);
    }
    dzzTileGridLayer = null;

    if (map) {
        layersRegistry.forEach((entry) => {
            if (entry?.group && map.hasLayer(entry.group)) map.removeLayer(entry.group);
        });
        [textLayerGroup, overlaysLayerGroup, fieldLabelsLayerGroup, aoiLayer].forEach((group) => {
            if (group && map.hasLayer(group)) map.removeLayer(group);
        });
        map.remove();
    }

    tileSatellite = tileScheme = tileDzz = tileCustom = null;
    tileCustomSig = '';
    createLeafletMap(crsCode, view);

    layersRegistry.forEach((entry) => {
        if (entry?.group && entry.visible !== false) entry.group.addTo(map);
    });
    if (textLayerGroup) textLayerGroup.addTo(map);
    if (overlaysLayerGroup) overlaysLayerGroup.addTo(map);
    if (fieldLabelsLayerGroup) fieldLabelsLayerGroup.addTo(map);
    if (aoiLayer) aoiLayer.addTo(map);
    applyDzzTileGridLayer();
    setTimeout(() => { if (map) map.invalidateSize(); }, 50);
}

function ensureMapCrs(crsCode) {
    const next = crsCode === 'EPSG:4326' ? 'EPSG:4326' : 'EPSG:3857';
    if (!map || currentMapCrs() !== next) recreateMap(next);
}

function initMap() {
    createLeafletMap('EPSG:3857');
    tileSatellite.addTo(map);
    currentBasemap = 'satellite';
    bindDzzTileFormSync();

    DEFAULT_LAYERS.forEach(l => addLayer(l.id, l.name, l.color, l.coords));
    activeLayerId = 'points';
    expandedLayers.add('points');
    expandedLayers.add('crops');
    textLayerGroup = L.layerGroup().addTo(map);
    overlaysLayerGroup = L.layerGroup().addTo(map);
    fieldLabelsLayerGroup = L.layerGroup().addTo(map);
    renderFoldersList();
    renderLayersList();
    renderLegend();
    renderFieldLabels();
    initSidebarResize();
    initNetworkStatus();
    populateDrawLayerSelect();
    populateCreateCropSelect();

    document.addEventListener('click', (e) => {
        // во время freehand панель кисти внутри more-menu — не закрывать
        if (activeTool === 'freehand' || createSessionActive || editDrawMode) return;
        const menu = document.getElementById('more-menu');
        const btn = document.getElementById('tool-more-btn');
        if (menu && menu.classList.contains('active') && !menu.contains(e.target) && e.target !== btn && !btn?.contains(e.target)) {
            menu.classList.remove('active');
        }
    });

    document.addEventListener('keydown', onGlobalKeyDown);
}

function ensureFieldMeta(layer, layerId) {
    if (!layer._fieldMeta) initFieldMeta(layer, layerId);
    return layer._fieldMeta;
}

function addLayer(id, name, color, polygonsLatLng, folderId = null) {
    const group = L.featureGroup().addTo(map);
    polygonsLatLng.forEach(coords => {
        const poly = L.polygon(coords, {
            color, weight: displaySettings.lineWidth,
            fillColor: color, fillOpacity: getFillOpacity(false),
        });
        ensureFieldMeta(poly, id);
        bindFeatureEvents(poly, id);
        poly.addTo(group);
    });
    layersRegistry.push({ id, name, color, group, visible: true, folderId, detected: false });
}

function addDetectedPolygon(layerId, coords) {
    const entry = findLayerEntry(layerId);
    if (!entry) return null;
    entry.detected = true;
    const poly = L.polygon(coords, {
        color: entry.color, weight: displaySettings.lineWidth,
        fillColor: entry.color, fillOpacity: getFillOpacity(false),
    });
    ensureFieldMeta(poly, layerId);
    bindFeatureEvents(poly, layerId);
    entry.group.addLayer(poly);
    return poly;
}

function addDetectedPoint(layerId, latlng) {
    const entry = findLayerEntry(layerId);
    if (!entry) return null;
    entry.detected = true;
    const center = Array.isArray(latlng) ? L.latLng(latlng[0], latlng[1]) : latlng;
    const coords = circleToPolygon(center, POINT_RADIUS_M, 16);
    const poly = L.polygon(coords, {
        color: entry.color, weight: displaySettings.lineWidth,
        fillColor: entry.color, fillOpacity: getFillOpacity(true),
    });
    poly._isPointObject = true;
    ensureFieldMeta(poly, layerId);
    bindFeatureEvents(poly, layerId);
    entry.group.addLayer(poly);
    return poly;
}

function createPointObject(entry, center) {
    const coords = circleToPolygon(center, POINT_RADIUS_M, 16);
    const poly = L.polygon(coords, {
        color: entry.color, weight: displaySettings.lineWidth,
        fillColor: entry.color, fillOpacity: getFillOpacity(true),
    });
    poly._isPointObject = true;
    return poly;
}

function applyCropToMeta(meta, cropKey) {
    if (!cropKey) return;
    meta.confirmedCrop = cropKey;
    meta.confirmed = true;
    const existing = meta.crops.find(c => c.key === cropKey);
    if (existing) existing.pct = 100;
    else meta.crops.unshift({ key: cropKey, pct: 100 });
}

function simulateAnalysisResults() {
    const baseLat = 53.898;
    const baseLng = 27.535;
    let detectedCount = 0;
    let idx = 0;
    const allBounds = [];

    DETECTION_CONFIG.forEach(cfg => {
        const el = document.getElementById(cfg.opt);
        if (el && !el.checked) return;
        const dlat = (idx % 4) * 0.004 - 0.006;
        const dlng = Math.floor(idx / 4) * 0.005 - 0.004;
        idx++;
        if (cfg.kind === 'point') {
            const center = [baseLat + dlat, baseLng + dlng];
            const poly = addDetectedPoint(cfg.id, center);
            if (poly) allBounds.push(poly.getBounds());
        } else {
            const s = 0.0025;
            const lat = baseLat + dlat;
            const lng = baseLng + dlng;
            const poly = addDetectedPolygon(cfg.id, [
                [lat, lng], [lat + s, lng], [lat + s, lng + s * 1.2], [lat, lng + s],
            ]);
            if (poly) allBounds.push(poly.getBounds());
        }
        detectedCount++;
    });

    if (detectedCount === 0) {
        showToast('Включите хотя бы один тип распознавания в настройках');
        return false;
    }

    analysisComplete = true;
    if (allBounds.length) {
        const bounds = allBounds.reduce((acc, b) => acc.extend(b), L.latLngBounds(allBounds[0].getSouthWest(), allBounds[0].getNorthEast()));
        map.fitBounds(bounds, { maxZoom: 15, padding: [30, 30] });
    }
    renderLayersList(document.getElementById('layer-search')?.value);
    renderLegend();
    renderFieldLabels();
    populateDrawLayerSelect();
    return true;
}

function pushUndo(action) {
    undoStack.push(action);
    redoStack = [];
    if (undoStack.length > 80) undoStack.shift();
}

function forwardAction(action) {
    if (action.type === 'deleteFeatures') {
        action.items.forEach(({ layer, layerId }) => findLayerEntry(layerId)?.group.removeLayer(layer));
    } else if (action.type === 'addFeature') {
        const entry = findLayerEntry(action.layerId);
        if (entry) { bindFeatureEvents(action.layer, action.layerId); entry.group.addLayer(action.layer); }
    } else if (action.type === 'addOverlay') {
        restoreOverlayLayers(action.layers, action.groupKey);
    } else if (action.type === 'removeOverlay') {
        removeOverlayLayers(action.layers);
    } else if (action.type === 'mergePolygons') {
        const entry = findLayerEntry(action.layerId);
        if (!entry) return;
        action.removed.forEach(({ layer }) => entry.group.removeLayer(layer));
        bindFeatureEvents(action.merged, action.layerId);
        entry.group.addLayer(action.merged);
    } else if (action.type === 'modifyFeature') {
        action.layer.setLatLngs(action.after);
    }
}

function reverseAction(action) {
    if (action.type === 'deleteFeatures') {
        action.items.forEach(({ layer, layerId, meta }) => {
            const entry = findLayerEntry(layerId);
            if (!entry) return;
            if (meta) layer._fieldMeta = meta;
            bindFeatureEvents(layer, layerId);
            entry.group.addLayer(layer);
        });
    } else if (action.type === 'addFeature') {
        findLayerEntry(action.layerId)?.group.removeLayer(action.layer);
    } else if (action.type === 'addOverlay') {
        removeOverlayLayers(action.layers);
        if (selectedOverlay && action.layers.includes(selectedOverlay)) selectedOverlay = null;
    } else if (action.type === 'removeOverlay') {
        restoreOverlayLayers(action.layers, action.groupKey);
    } else if (action.type === 'mergePolygons') {
        const entry = findLayerEntry(action.layerId);
        if (!entry) return;
        if (action.merged) entry.group.removeLayer(action.merged);
        action.removed.forEach(({ layer, meta }) => {
            if (meta) layer._fieldMeta = meta;
            bindFeatureEvents(layer, action.layerId);
            entry.group.addLayer(layer);
        });
    } else if (action.type === 'modifyFeature') {
        action.layer.setLatLngs(action.before);
    }
}

function undoLast() {
    const action = undoStack.pop();
    if (!action) { showToast('Нечего отменять'); return; }
    reverseAction(action);
    redoStack.push(action);
    clearSelection();
    renderLayersList(document.getElementById('layer-search')?.value);
    renderLegend();
    renderFieldLabels();
    hideFieldDetail();
    showToast('Действие отменено');
    logAction('tool', 'Отменено последнее действие на карте');
}

function redoLast() {
    const action = redoStack.pop();
    if (!action) { showToast('Нечего повторить'); return; }
    forwardAction(action);
    undoStack.push(action);
    renderLayersList(document.getElementById('layer-search')?.value);
    renderLegend();
    renderFieldLabels();
    showToast('Действие повторено');
    logAction('tool', 'Повторено действие на карте');
}

function removeOverlayLayers(layers) {
    layers.forEach(l => {
        if (overlaysLayerGroup?.hasLayer(l)) overlaysLayerGroup.removeLayer(l);
        else if (textLayerGroup?.hasLayer(l)) textLayerGroup.removeLayer(l);
        else if (map?.hasLayer(l)) map.removeLayer(l);
    });
}

function onGlobalKeyDown(e) {
    if (e.key === 'Escape') {
        e.preventDefault();
        const appModal = document.getElementById('app-modal');
        const folderPicker = document.getElementById('folder-picker');
        if (appModal && appModal.style.display !== 'none' && appModal.style.display !== '') {
            closeAppModal();
            return;
        }
        if (folderPicker && folderPicker.style.display !== 'none' && folderPicker.style.display !== '') {
            closeFolderPicker();
            return;
        }
        if (e.target.matches('input, textarea, select')) return;
        cancelActiveTool();
        return;
    }
    if (e.target.matches('input, textarea, select')) return;
    if ((e.ctrlKey || e.metaKey) && e.shiftKey && (e.key === 'z' || e.key === 'Z')) {
        e.preventDefault();
        redoLast();
        return;
    }
    if ((e.ctrlKey || e.metaKey) && e.key === 'z') {
        e.preventDefault();
        undoLast();
        return;
    }
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'g') {
        e.preventDefault();
        const next = !(mapDisplay.labels && mapDisplay.coords);
        setMapDisplayOption('labels', next);
        setMapDisplayOption('coords', next);
        showToast(next ? 'Подписи и координаты включены' : 'Подписи и координаты скрыты');
        return;
    }
    if (e.key === 'Delete' || e.key === 'Backspace') {
        e.preventDefault();
        deleteCurrentMapSelection();
    }
}

function cancelActiveTool() {
    clearRulerPreview();
    clearRulerDrawing();
    clearCompassDrawing();
    if (createSessionActive) {
        discardCreateDraft();
        createSessionActive = false;
    }
    stopFreehandEdit();
    destroyPaintSession();
    document.getElementById('more-menu')?.classList.remove('active');
    document.getElementById('edit-area-controls').style.display = 'none';
    editDrawMode = null;
    deactivateCurrentTool();
    setTool('select');
    showToast('Инструмент: Выделение области');
}

function getFeatureBaseStyle(layerId, layer = null) {
    const entry = findLayerEntry(layerId);
    const color = entry?.color || '#3388ff';
    const isPoint = layerId === 'points' || layer?._isPointObject;
    return { color, weight: displaySettings.lineWidth, fillColor: color, fillOpacity: getFillOpacity(isPoint) };
}

function deleteCurrentMapSelection() {
    if (selectedFeatures.length > 0) {
        deleteSelectedFeatures();
        return;
    }
    if (selectedOverlay) {
        const groupKey = textLayerGroup?.hasLayer(selectedOverlay) ? 'text' : 'overlay';
        pushUndo({ type: 'removeOverlay', layers: [selectedOverlay], groupKey });
        removeOverlayLayers([selectedOverlay]);
        selectedOverlay = null;
        showToast('Объект удалён');
        return;
    }
    for (let i = undoStack.length - 1; i >= 0; i--) {
        if (undoStack[i].type === 'addOverlay') {
            const action = undoStack.splice(i, 1)[0];
            pushUndo({ type: 'removeOverlay', layers: action.layers, groupKey: action.groupKey });
            removeOverlayLayers(action.layers);
            showToast('Последняя метка удалена');
            return;
        }
    }
    showToast('Нечего удалить');
}

let suppressMapClick = false;

function bindFeatureEvents(layer, layerId) {
    layer.on('click', (e) => {
        if (activeTool === 'freehand') return;
        if (activeTool !== 'select') return;
        // Блокируем последующий map click (иначе сбрасывается мультивыбор)
        suppressMapClick = true;
        L.DomEvent.stopPropagation(e);
        if (e.originalEvent) {
            L.DomEvent.preventDefault(e.originalEvent);
            L.DomEvent.stopPropagation(e.originalEvent);
        }
        const oe = e.originalEvent || {};
        const multi = !!(oe.ctrlKey || oe.metaKey || oe.shiftKey);
        selectedOverlay = null;
        selectFeature(layer, layerId, multi);
        if (selectedFeatures.length === 1) showFieldDetail(layer, layerId);
        else if (selectedFeatures.length > 1) {
            hideFieldDetail();
            showToast(`Выбрано: ${selectedFeatures.length} · Ctrl/⌘/Shift + клик`);
        }
        setTimeout(() => { suppressMapClick = false; }, 0);
    });
}

function clearSelection() {
    selectedFeatures.forEach(({ layer, layerId }) => {
        layer.setStyle(getFeatureBaseStyle(layerId, layer));
    });
    selectedFeatures = [];
    clearVertexMarkers();
    renderLayersList(document.getElementById('layer-search')?.value);
}

function selectFeature(layer, layerId, multi = false) {
    if (!multi) {
        clearSelection();
        selectedFeatures = [{ layer, layerId }];
    } else {
        const idx = selectedFeatures.findIndex(s => s.layer === layer);
        if (idx >= 0) {
            layer.setStyle(getFeatureBaseStyle(layerId, layer));
            selectedFeatures.splice(idx, 1);
            if (selectedFeatures.length === 1) {
                showVertexMarkers(selectedFeatures[0].layer, selectedFeatures[0].layerId);
                showFieldDetail(selectedFeatures[0].layer, selectedFeatures[0].layerId);
            } else {
                clearVertexMarkers();
                hideFieldDetail();
            }
            renderLayersList(document.getElementById('layer-search')?.value);
            return;
        }
        const sameLayer = selectedFeatures.length === 0 || selectedFeatures.every(s => s.layerId === layerId);
        if (!sameLayer) {
            showToast('Мультивыбор только в пределах одного слоя');
            clearSelection();
            selectedFeatures = [{ layer, layerId }];
        } else {
            selectedFeatures.push({ layer, layerId });
        }
    }
    selectedOverlay = null;
    selectedFeatures.forEach(({ layer: l, layerId: lid }) => {
        const base = getFeatureBaseStyle(lid, l);
        const fill = Math.min(0.85, (base.fillOpacity || 0.35) + 0.2);
        l.setStyle({ ...base, weight: base.weight + 3, color: '#ffffff', fillOpacity: fill });
        if (l.bringToFront) l.bringToFront();
    });
    if (selectedFeatures.length === 1) showVertexMarkers(selectedFeatures[0].layer, selectedFeatures[0].layerId);
    else clearVertexMarkers();
    renderLayersList(document.getElementById('layer-search')?.value);
}

function deleteSelectedFeatures() {
    if (selectedFeatures.length === 0) return;
    const items = selectedFeatures.map(({ layer, layerId }) => ({
        layer, layerId, meta: layer._fieldMeta ? { ...layer._fieldMeta } : null,
    }));
    pushUndo({ type: 'deleteFeatures', items });
    items.forEach(({ layer, layerId }) => {
        const entry = findLayerEntry(layerId);
        if (entry) entry.group.removeLayer(layer);
    });
    clearSelection();
    hideFieldDetail();
    renderLayersList(document.getElementById('layer-search')?.value);
    renderLegend();
    renderFieldLabels();
    showToast('Выделенные объекты удалены');
    logAction('tool', `Удалено объектов: ${items.length}`);
}

function findLayerEntry(id) { return layersRegistry.find(l => l.id === id); }
function findFolder(id) { return foldersRegistry.find(f => f.id === id); }

function renderFolderObjectItems(folderId) {
    // Только «частичные» объекты: слой не целиком в этой папке
    const items = [];
    layersRegistry.forEach(entry => {
        if (!isLayerListedInSidebar(entry)) return;
        const home = getLayerHomeFolderId(entry);
        if (home === folderId) return; // слой целиком — рисуется как слой
        entry.group.eachLayer(layer => {
            ensureFieldMeta(layer, entry.id);
            if (layer._fieldMeta.objectFolderId === folderId) {
                items.push({ layer, layerId: entry.id, layerName: entry.name, color: entry.color, meta: layer._fieldMeta });
            }
        });
    });
    return items.map(({ layer, layerId, layerName, color, meta }) => {
        const isSelected = selectedFeatures.some(s => s.layer === layer);
        const active = selectedFieldLayer === layer || isSelected ? 'active' : '';
        return `<div class="field-item field-item-in-folder ${active}">
            <span class="color-swatch-readonly" style="background:${color}" title="${layerName}"></span>
            <span class="field-item-name" onclick="selectFieldInList('${layerId}', '${meta.id}')">
                <span class="field-layer-tag">${layerName}</span> ${meta.name}
            </span>
            <button class="layer-action" type="button" title="Убрать из папки" onclick="event.stopPropagation(); assignObjectToFolder('${layerId}', '${meta.id}', null)">${ICON_FOLDER_OUT}</button>
            <button class="layer-action layer-action-danger" type="button" title="Удалить объект" onclick="event.stopPropagation(); deleteFieldObject('${layerId}', '${meta.id}')">✕</button>
        </div>`;
    }).join('');
}

function renderFoldersList() {
    const container = document.getElementById('folders-list');
    if (!container) return;
    container.innerHTML = foldersRegistry.map(f => {
        const layers = layersRegistry.filter(l =>
            isLayerListedInSidebar(l) && getLayerHomeFolderId(l) === f.id
        );
        const objectItems = renderFolderObjectItems(f.id);
        return `
            <div class="folder-item" data-folder-id="${f.id}">
                <button class="folder-toggle" type="button" onclick="event.stopPropagation(); toggleFolderCollapsed('${f.id}')">${f.collapsed ? '▸' : '▾'}</button>
                <input type="checkbox" ${f.visible ? 'checked' : ''} onclick="event.stopPropagation(); toggleFolderVisibility('${f.id}')">
                <span class="folder-icon" title="Папка">${ICON_FOLDER}</span>
                <span class="folder-name" ondblclick="startRenameFolder('${f.id}')">${f.name}</span>
                <button class="layer-action layer-action-danger" type="button" title="Удалить папку" onclick="event.stopPropagation(); deleteFolder('${f.id}')">✕</button>
                ${f.collapsed ? '' : `<div class="folder-children">${renderLayerItems(layers, '', { folderContextId: f.id })}${objectItems}</div>`}
            </div>`;
    }).join('');
}

function renderLayerItems(layers, filterText, opts = {}) {
    const query = (filterText || '').toLowerCase();
    return layers
        .filter(l => isLayerListedInSidebar(l) && l.name.toLowerCase().includes(query))
        .map(l => renderSingleLayerRow(l, opts))
        .join('');
}

function renderSingleLayerRow(l, opts = {}) {
    const folderContextId = opts.folderContextId || null;
    const homeFolder = getLayerHomeFolderId(l);
    const allLayers = l.group.getLayers();
    // объекты, видимые в этом контексте
    const visibleFields = [];
    allLayers.forEach(layer => {
        ensureFieldMeta(layer, l.id);
        const of = layer._fieldMeta.objectFolderId || null;
        if (folderContextId) {
            // в папке: либо слой целиком здесь, либо объект привязан к папке
            if (homeFolder === folderContextId || of === folderContextId || l.folderId === folderContextId) {
                visibleFields.push(layer);
            }
        } else {
            // корень: только объекты без папки; слой целиком в папке сюда не попадает
            if (!of) visibleFields.push(layer);
        }
    });

    const count = folderContextId ? visibleFields.length : allLayers.filter(layer => {
        ensureFieldMeta(layer, l.id);
        return !layer._fieldMeta.objectFolderId;
    }).length || (homeFolder ? 0 : allLayers.length);
    // root count: objects not in folders; if split, count outside only
    const displayCount = folderContextId
        ? visibleFields.length
        : allLayers.filter(layer => {
            ensureFieldMeta(layer, l.id);
            return !layer._fieldMeta.objectFolderId;
        }).length;

    const expanded = expandedLayers.has(l.id);
    const locked = !isCustomLayer(l);
    let fieldsHtml = '';
    if (expanded && visibleFields.length > 0) {
        fieldsHtml = visibleFields.map(layer => {
            const meta = layer._fieldMeta;
            const isSelected = selectedFeatures.some(s => s.layer === layer);
            const active = selectedFieldLayer === layer || isSelected ? 'active' : '';
            const inFolder = folderContextId || meta.objectFolderId;
            const plusOrOut = inFolder
                ? `<button class="layer-action" type="button" title="Убрать из папки" onclick="event.stopPropagation(); assignObjectToFolder('${l.id}', '${meta.id}', null)">${ICON_FOLDER_OUT}</button>`
                : `<button class="layer-action layer-action-plus" type="button" title="Добавить в папку" onclick="event.stopPropagation(); assignObjectToFolder('${l.id}', '${meta.id}')">${ICON_PLUS}</button>`;
            return `<div class="field-item ${active}">
                <span class="field-item-name" onclick="selectFieldInList('${l.id}', '${meta.id}')">${meta.name}</span>
                ${plusOrOut}
                <button class="layer-action layer-action-danger" type="button" title="Удалить объект" onclick="event.stopPropagation(); deleteFieldObject('${l.id}', '${meta.id}')">✕</button>
            </div>`;
        }).join('');
    }
    const colorControl = locked
        ? `<span class="color-swatch-readonly" style="background:${l.color}"></span>`
        : `<input type="color" class="color-box" value="${l.color}" onclick="event.stopPropagation()" onchange="changeLayerColor('${l.id}', this.value)">`;
    const renameBtn = locked ? '' : `<button class="layer-action" type="button" title="Переименовать" onclick="event.stopPropagation(); renameLayer('${l.id}')">✎</button>`;
    const deleteBtn = locked ? '' : `<button class="layer-action layer-action-danger" type="button" title="Удалить слой" onclick="event.stopPropagation(); deleteLayer('${l.id}')">✕</button>`;
    const folderBtn = folderContextId
        ? `<button class="layer-action" type="button" title="Убрать слой из папки" onclick="event.stopPropagation(); removeLayerFromFolder('${l.id}')">${ICON_FOLDER_OUT}</button>`
        : `<button class="layer-action layer-action-plus" type="button" title="Добавить слой в папку" onclick="event.stopPropagation(); assignLayerToFolder('${l.id}')">${ICON_PLUS}</button>`;
    return `
        <label class="layer-item ${l.id === activeLayerId ? 'selected' : ''} ${locked ? 'locked' : ''}" data-layer-id="${l.id}">
            <button class="layer-expand" type="button" onclick="event.stopPropagation(); toggleLayerExpanded('${l.id}')">${expanded ? '▾' : '▸'}</button>
            <input type="checkbox" ${l.visible ? 'checked' : ''} onclick="event.stopPropagation(); toggleLayerVisibility('${l.id}')">
            ${colorControl}
            <span class="layer-name" onclick="selectLayerAsActive('${l.id}')" ${locked ? '' : `ondblclick="renameLayer('${l.id}'); event.stopPropagation();"`}>${l.name}</span>
            <span class="layer-count">${displayCount}</span>
            <div class="layer-item-actions">
                ${folderBtn}
                ${renameBtn}
                ${deleteBtn}
            </div>
            ${fieldsHtml ? `<div class="folder-children">${fieldsHtml}</div>` : ''}
        </label>`;
}

function removeLayerFromFolder(layerId) {
    const entry = findLayerEntry(layerId);
    if (!entry) return;
    entry.folderId = null;
    entry.group.eachLayer(layer => {
        ensureFieldMeta(layer, layerId);
        layer._fieldMeta.objectFolderId = null;
    });
    saveFoldersState();
    renderLayersList(document.getElementById('layer-search')?.value);
    showToast('Слой убран из папки');
}

function renderLayersList(filterText) {
    const container = document.getElementById('layers-list');
    const query = (filterText || '').toLowerCase();
    let totalFeatures = 0;
    layersRegistry.filter(isLayerListedInSidebar).forEach(l => { totalFeatures += l.group.getLayers().length; });

    // Корень: слои, которые не целиком лежат в папке
    const rootLayers = layersRegistry.filter(l => {
        if (!isLayerListedInSidebar(l)) return false;
        if (getLayerHomeFolderId(l)) return false;
        return l.name.toLowerCase().includes(query);
    });
    container.innerHTML = renderLayerItems(rootLayers, filterText, {});
    renderFoldersList();
    document.getElementById('layers-count-badge').innerText = `${totalFeatures} объект${totalFeatures === 1 ? '' : 'ов'}`;
}

function deleteFieldObject(layerId, fieldMetaId) {
    const entry = findLayerEntry(layerId);
    if (!entry) return;
    let target = null;
    entry.group.eachLayer(l => {
        ensureFieldMeta(l, layerId);
        if (l._fieldMeta.id === fieldMetaId) target = l;
    });
    if (!target) return;
    if (!confirm('Удалить объект?')) return;
    pushUndo({ type: 'deleteFeatures', items: [{ layer: target, layerId, meta: { ...target._fieldMeta } }] });
    entry.group.removeLayer(target);
    if (selectedFieldLayer === target) hideFieldDetail();
    selectedFeatures = selectedFeatures.filter(s => s.layer !== target);
    clearVertexMarkers();
    renderLayersList(document.getElementById('layer-search')?.value);
    renderLegend();
    renderFieldLabels();
    showToast('Объект удалён');
}

function toggleLayerExpanded(id) {
    if (expandedLayers.has(id)) expandedLayers.delete(id);
    else expandedLayers.add(id);
    renderLayersList(document.getElementById('layer-search')?.value);
}

function createFolder() {
    openAppModal({
        title: 'Новая папка',
        bodyHtml: `<label class="modal-label">Название</label>
            <input type="text" id="modal-folder-name" class="search-input modal-input" placeholder="Например: Поле Север">`,
        actions: [
            { label: 'Создать', className: 'mini-btn mini-btn-red', onClick: () => {
                const name = document.getElementById('modal-folder-name')?.value.trim();
                if (!name) return;
                foldersRegistry.push({ id: 'folder_' + Date.now(), name, visible: true, collapsed: false });
                closeAppModal();
                saveFoldersState();
                renderFoldersList();
                renderLayersList(document.getElementById('layer-search')?.value);
                showToast('Папка создана');
            }},
            { label: 'Отмена', className: 'mini-btn', onClick: () => closeAppModal() },
        ],
        focusId: 'modal-folder-name',
    });
}

function toggleCreateFolderForm() { createFolder(); }

function startRenameFolder(id) {
    const folder = findFolder(id);
    if (!folder) return;
    openAppModal({
        title: 'Переименовать папку',
        bodyHtml: `<label class="modal-label">Название</label>
            <input type="text" id="modal-folder-name" class="search-input modal-input" value="${String(folder.name).replace(/"/g, '&quot;')}">`,
        actions: [
            { label: 'Сохранить', className: 'mini-btn mini-btn-red', onClick: () => {
                const name = document.getElementById('modal-folder-name')?.value.trim();
                if (!name) return;
                folder.name = name;
                closeAppModal();
                saveFoldersState();
                renderFoldersList();
                renderLegend();
                showToast('Папка переименована');
            }},
            { label: 'Отмена', className: 'mini-btn', onClick: () => closeAppModal() },
        ],
        focusId: 'modal-folder-name',
    });
}

function submitCreateFolder() { /* modal UI */ }

function toggleFolderVisibility(id) {
    const folder = findFolder(id);
    if (!folder) return;
    folder.visible = !folder.visible;
    layersRegistry.forEach(entry => {
        const home = getLayerHomeFolderId(entry);
        if (home === id || entry.folderId === id) {
            entry.visible = folder.visible;
            if (folder.visible) entry.group.addTo(map);
            else map.removeLayer(entry.group);
            return;
        }
        // частичные объекты в папке
        entry.group.eachLayer(layer => {
            ensureFieldMeta(layer, entry.id);
            if (layer._fieldMeta.objectFolderId !== id) return;
            if (folder.visible) {
                layer.setStyle({
                    opacity: 1,
                    fillOpacity: getFillOpacity(entry.id === 'points' || layer._isPointObject),
                });
            } else {
                layer.setStyle({ opacity: 0, fillOpacity: 0 });
            }
        });
    });
    saveFoldersState();
    renderLayersList(document.getElementById('layer-search')?.value);
    renderLegend();
    renderFieldLabels();
}

function toggleFolderCollapsed(id) {
    const folder = findFolder(id);
    if (!folder) return;
    folder.collapsed = !folder.collapsed;
    renderFoldersList();
}

function renameFolder(id) {
    const folder = findFolder(id);
    if (!folder) return;
    const next = prompt('Переименовать папку', folder.name);
    if (!next) return;
    folder.name = next.trim() || folder.name;
    saveFoldersState();
    renderFoldersList();
    renderLegend();
}

function deleteFolder(id) {
    const folder = findFolder(id);
    if (!folder || !confirm(`Удалить папку «${folder.name}»? Слои и объекты останутся на карте.`)) return;
    layersRegistry.forEach(l => {
        if (l.folderId === id) l.folderId = null;
        l.group.eachLayer(layer => {
            if (layer._fieldMeta?.objectFolderId === id) layer._fieldMeta.objectFolderId = null;
        });
    });
    foldersRegistry = foldersRegistry.filter(f => f.id !== id);
    saveFoldersState();
    renderFoldersList();
    renderLayersList(document.getElementById('layer-search')?.value);
    renderLegend();
}

function openFolderPicker(title, onPick) {
    const panel = document.getElementById('folder-picker');
    const list = document.getElementById('folder-picker-list');
    const titleEl = document.getElementById('folder-picker-title');
    if (!panel || !list) {
        // fallback prompt
        if (foldersRegistry.length === 0) { alert('Сначала создайте папку.'); return; }
        const names = foldersRegistry.map((f, i) => `${i + 1}. ${f.name}`).join('\n');
        const choice = prompt(`${title}\n0 — убрать из папки\n${names}`, '1');
        if (choice === null) return;
        const num = parseInt(choice, 10);
        if (num === 0) onPick(null);
        else if (num >= 1 && num <= foldersRegistry.length) onPick(foldersRegistry[num - 1].id);
        return;
    }
    if (titleEl) titleEl.textContent = title || 'Выберите папку';
    list.innerHTML = [
        `<button type="button" class="folder-picker-item" data-id="">— Без папки —</button>`,
        ...foldersRegistry.map(f =>
            `<button type="button" class="folder-picker-item" data-id="${f.id}">${f.name}</button>`
        ),
    ].join('');
    list.querySelectorAll('.folder-picker-item').forEach(btn => {
        btn.onclick = () => {
            const id = btn.getAttribute('data-id') || null;
            closeFolderPicker();
            onPick(id || null);
        };
    });
    panel.style.display = 'flex';
}

function closeFolderPicker() {
    const panel = document.getElementById('folder-picker');
    if (panel) panel.style.display = 'none';
    pendingFolderAssign = null;
}

function assignLayerToFolder(layerId) {
    if (foldersRegistry.length === 0) { alert('Сначала создайте папку.'); return; }
    openFolderPicker('Папка для слоя', (folderId) => {
        const entry = findLayerEntry(layerId);
        if (!entry) return;
        entry.folderId = folderId;
        // все объекты слоя тоже «едут» с закреплённым слоем
        entry.group.eachLayer(layer => {
            ensureFieldMeta(layer, layerId);
            layer._fieldMeta.objectFolderId = folderId;
        });
        saveFoldersState();
        renderLayersList(document.getElementById('layer-search')?.value);
        renderLegend();
        showToast(folderId ? 'Слой добавлен в папку' : 'Слой убран из папки');
    });
}

function assignObjectToFolder(layerId, metaId, folderId) {
    const entry = findLayerEntry(layerId);
    if (!entry) return;
    let target = null;
    entry.group.eachLayer(l => {
        ensureFieldMeta(l, layerId);
        if (l._fieldMeta.id === metaId) target = l;
    });
    if (!target) return;

    const apply = (fid) => {
        target._fieldMeta.objectFolderId = fid;
        // recompute: если все объекты в одной папке — слой «целиком» там (не показываем снаружи)
        let allSame = true;
        let common = undefined;
        const layers = entry.group.getLayers();
        if (layers.length) {
            layers.forEach(layer => {
                ensureFieldMeta(layer, layerId);
                const of = layer._fieldMeta.objectFolderId || null;
                if (common === undefined) common = of;
                else if (common !== of) allSame = false;
            });
            entry.folderId = (allSame && common) ? common : null;
        } else {
            entry.folderId = null;
        }
        saveFoldersState();
        renderLayersList(document.getElementById('layer-search')?.value);
        showToast(fid ? 'Объект добавлен в папку (слой закреплён)' : 'Объект убран из папки');
    };

    if (folderId === null) { apply(null); return; }
    if (typeof folderId === 'string') { apply(folderId); return; }
    if (foldersRegistry.length === 0) { alert('Сначала создайте папку.'); return; }
    openFolderPicker('Папка для объекта', apply);
}

function moveFeatureToLayer(layer, fromId, toId) {
    if (!layer || !toId || fromId === toId) return false;
    const from = findLayerEntry(fromId);
    const to = findLayerEntry(toId);
    if (!from || !to) return false;

    from.group.removeLayer(layer);
    to.detected = true;
    const isPoint = toId === 'points' || layer._isPointObject;
    if (toId === 'points') layer._isPointObject = true;
    layer.setStyle({
        color: to.color,
        fillColor: to.color,
        weight: displaySettings.lineWidth,
        fillOpacity: getFillOpacity(isPoint),
    });

    const meta = ensureFieldMeta(layer, toId);
    if (!layerSupportsCrop(toId)) {
        meta.crops = [];
        meta.confirmedCrop = null;
        meta.confirmed = false;
    } else if (!meta.crops?.length) {
        meta.crops = generateCropProbabilities();
    }

    layer.off();
    bindFeatureEvents(layer, toId);
    to.group.addLayer(layer);

    selectedFeatures = selectedFeatures.map(s =>
        s.layer === layer ? { layer, layerId: toId } : s
    );
    if (selectedFieldLayer === layer) {
        selectedFieldLayerId = toId;
        showFieldDetail(layer, toId);
    }
    activeLayerId = toId;
    renderLayersList(document.getElementById('layer-search')?.value);
    renderLegend();
    renderFieldLabels();
    if (selectedFeatures.length === 1) showVertexMarkers(layer, toId);
    showToast(`Объект перенесён в «${to.name}»`);
    return true;
}

function selectFieldInList(layerId, fieldMetaId) {
    const entry = findLayerEntry(layerId);
    if (!entry) return;
    let target = null;
    entry.group.eachLayer(l => {
        ensureFieldMeta(l, layerId);
        if (l._fieldMeta.id === fieldMetaId) target = l;
    });
    if (!target) return;
    selectFeature(target, layerId, false);
    showFieldDetail(target, layerId);
    const bounds = target.getBounds?.();
    if (bounds?.isValid()) map.fitBounds(bounds, { maxZoom: 16, padding: [40, 40] });
}

function calcFieldAreaHa(layer) {
    if (!layer?.getLatLngs) return 0;
    const latlngs = layer.getLatLngs();
    const ring = Array.isArray(latlngs[0]) ? latlngs[0] : latlngs;
    if (ring.length < 3) return 0;
    const pts = ring.map(p => map.project(p));
    let area = 0;
    for (let i = 0; i < pts.length; i++) {
        const j = (i + 1) % pts.length;
        area += pts[i].x * pts[j].y - pts[j].x * pts[i].y;
    }
    const m2 = Math.abs(area);
    return m2 / 10000;
}

function showFieldDetail(layer, layerId) {
    selectedFieldLayer = layer;
    selectedFieldLayerId = layerId;
    const meta = ensureFieldMeta(layer, layerId);
    const panel = document.getElementById('field-detail-panel');
    if (!panel) return;
    panel.style.display = 'block';
    document.getElementById('field-name-input').value = meta.name;
    const areaHa = calcFieldAreaHa(layer);
    document.getElementById('field-area-value').innerText = areaHa >= 0.01
        ? `${areaHa.toFixed(2)} га` : `${Math.round(areaHa * 10000)} м²`;

    const hasCrop = layerSupportsCrop(layerId);
    const resultEl = document.getElementById('field-crop-result');
    const cropWrap = document.querySelector('#field-detail-panel .crop-table-wrap');
    const cropActions = document.querySelector('#field-detail-panel .field-actions');
    if (cropWrap) cropWrap.style.display = hasCrop ? '' : 'none';
    if (cropActions) cropActions.style.display = hasCrop ? '' : 'none';

    if (!hasCrop) {
        if (meta.crops?.length) meta.crops = [];
        meta.confirmedCrop = null;
        meta.confirmed = false;
        resultEl.className = 'field-crop-result muted';
        resultEl.innerHTML = 'Культура не применяется для этого типа объекта';
        const tbody = document.getElementById('crop-table-body');
        if (tbody) tbody.innerHTML = '';
    } else if (isManualField(layer) || meta.source === 'manual') {
        // вручную: без распределения вероятностей
        meta.crops = [];
        meta.source = 'manual';
        resultEl.className = 'field-crop-result';
        resultEl.innerHTML = meta.confirmedCrop
            ? `Культура: <strong>${formatCropDisplay(meta.confirmedCrop)}</strong>`
            : 'Культура не задана — выберите вручную';
        if (cropWrap) cropWrap.style.display = 'none';
        if (cropActions) {
            cropActions.style.display = '';
            const confirmBtn = cropActions.querySelector('button[onclick*="confirmFieldCrop"]');
            if (confirmBtn) confirmBtn.style.display = 'none';
        }
        const tbody = document.getElementById('crop-table-body');
        if (tbody) tbody.innerHTML = '';
    } else {
        if (!meta.crops?.length) meta.crops = generateCropProbabilities();
        const top = getTopCrop(meta);
        const warn = !meta.confirmed && top.pct < 65;
        resultEl.className = 'field-crop-result' + (warn ? ' warn' : '');
        resultEl.innerHTML = meta.confirmed
            ? `Подтверждено: <strong>${formatCropDisplay(meta.confirmedCrop)}</strong>`
            : `Результат: <strong>${formatCropDisplay(top.key)}</strong> (${top.pct.toFixed(1)}%)${warn ? ' ⚠ Требует подтверждения' : ''}`;

        if (cropWrap) cropWrap.style.display = '';
        if (cropActions) {
            cropActions.style.display = '';
            const confirmBtn = cropActions.querySelector('button[onclick*="confirmFieldCrop"]');
            if (confirmBtn) confirmBtn.style.display = '';
        }
        const tbody = document.getElementById('crop-table-body');
        tbody.innerHTML = meta.crops.map(c => `
            <tr class="${c.key === top.key && !meta.confirmed ? 'top-crop' : ''}">
                <td>${formatCropDisplay(c.key)}</td>
                <td>${c.pct.toFixed(2)}%</td>
            </tr>`).join('');
    }
    renderLayersList(document.getElementById('layer-search')?.value);
}

function hideFieldDetail() {
    selectedFieldLayer = null;
    selectedFieldLayerId = null;
    const panel = document.getElementById('field-detail-panel');
    if (panel) panel.style.display = 'none';
}

function saveFieldName() {
    if (!selectedFieldLayer) return;
    const name = document.getElementById('field-name-input').value.trim();
    if (!name) return;
    selectedFieldLayer._fieldMeta.name = name;
    renderLayersList(document.getElementById('layer-search')?.value);
    renderFieldLabels();
    showToast('Название поля сохранено');
}

function confirmFieldCrop() {
    if (!selectedFieldLayer || !layerSupportsCrop(selectedFieldLayerId)) {
        showToast('Для этого объекта культура не задаётся');
        return;
    }
    const meta = selectedFieldLayer._fieldMeta;
    const top = getTopCrop(meta);
    if (!top.key) return;
    meta.confirmedCrop = top.key;
    meta.confirmed = true;
    showFieldDetail(selectedFieldLayer, selectedFieldLayerId);
    renderFieldLabels();
    showToast(`Культура подтверждена: ${getCropLabel(top.key)}`);
}

function buildCropSelectHtml(selectedKey) {
    refreshCropCaches();
    const options = getAllCropOptions();
    const opts = options.map(o =>
        `<option value="${o.key}" ${selectedKey === o.key ? 'selected' : ''}>${formatCropOptionLabel(o.key, o.label, o.custom)}</option>`
    ).join('');
    return `
        <label class="modal-label">Сельхозкультура</label>
        <select id="modal-crop-select" class="search-input modal-input">
            <option value="">— Не задана —</option>
            ${opts}
        </select>
        <label class="modal-label">Своя культура (*)</label>
        <input type="text" id="modal-custom-crop-name" class="search-input modal-input" placeholder="Название новой культуры">
        <button type="button" class="mini-btn mini-btn-blue modal-btn-block" id="modal-add-custom-crop">+ Добавить культуру</button>
        <div id="modal-custom-crop-list" class="custom-crop-list"></div>
        <p class="modal-text modal-hint">Свои культуры отмечены ✦ — модель их не распознаёт, только ручной выбор.</p>
    `;
}

function refreshModalCustomCropList() {
    const list = document.getElementById('modal-custom-crop-list');
    if (!list) return;
    const customs = Object.entries(getCustomCrops());
    if (!customs.length) {
        list.innerHTML = '<div class="modal-hint-muted">Своих культур пока нет</div>';
        return;
    }
    list.innerHTML = customs.map(([key, label]) => `
        <div class="custom-crop-row">
            <span>${label}</span>
            <button type="button" class="layer-action layer-action-danger" data-del-crop="${key}" title="Удалить">✕</button>
        </div>
    `).join('');
    list.querySelectorAll('[data-del-crop]').forEach(btn => {
        btn.onclick = () => {
            const key = btn.getAttribute('data-del-crop');
            deleteCustomCrop(key);
            // update select
            const sel = document.getElementById('modal-crop-select');
            const prev = sel?.value;
            if (sel) {
                const body = document.getElementById('app-modal-body');
                if (body) {
                    const selected = prev === key ? '' : prev;
                    // rebuild options only
                    const options = getAllCropOptions();
                    sel.innerHTML = '<option value="">— Не задана —</option>' +
                        options.map(o => `<option value="${o.key}" ${selected === o.key ? 'selected' : ''}>${formatCropOptionLabel(o.key, o.label, o.custom)}</option>`).join('');
                }
            }
            refreshModalCustomCropList();
            populateCreateCropSelect();
            showToast('Своя культура удалена');
        };
    });
}

function wireCropModalExtras() {
    const addBtn = document.getElementById('modal-add-custom-crop');
    if (addBtn) {
        addBtn.onclick = () => {
            const input = document.getElementById('modal-custom-crop-name');
            const key = addCustomCrop(input?.value);
            if (!key) { input?.focus(); return; }
            if (input) input.value = '';
            const sel = document.getElementById('modal-crop-select');
            if (sel) {
                const options = getAllCropOptions();
                sel.innerHTML = '<option value="">— Не задана —</option>' +
                    options.map(o => `<option value="${o.key}" ${o.key === key ? 'selected' : ''}>${formatCropOptionLabel(o.key, o.label, o.custom)}</option>`).join('');
                sel.value = key;
            }
            refreshModalCustomCropList();
            populateCreateCropSelect();
            showToast('Своя культура добавлена');
        };
    }
    refreshModalCustomCropList();
}

function manualFieldCrop() {
    if (!selectedFieldLayer || !layerSupportsCrop(selectedFieldLayerId)) {
        showToast('Для этого объекта культура не задаётся');
        return;
    }
    const meta = selectedFieldLayer._fieldMeta;
    const selected = meta.confirmedCrop || getTopCrop(meta).key || '';
    openAppModal({
        title: 'Культура объекта',
        bodyHtml: buildCropSelectHtml(selected),
        actions: [
            { label: 'Сохранить', className: 'mini-btn mini-btn-red', onClick: () => {
                const key = document.getElementById('modal-crop-select')?.value || '';
                meta.confirmedCrop = key || null;
                meta.confirmed = Boolean(key);
                if (isManualField(selectedFieldLayer) || meta.source === 'manual') {
                    meta.crops = [];
                    meta.source = 'manual';
                } else if (key) {
                    applyCropToMeta(meta, key);
                }
                closeAppModal();
                showFieldDetail(selectedFieldLayer, selectedFieldLayerId);
                renderFieldLabels();
                showToast(key ? `Культура: ${getCropLabel(key)}` : 'Культура сброшена');
            }},
            { label: 'Отмена', className: 'mini-btn', onClick: () => closeAppModal() },
        ],
    });
    setTimeout(wireCropModalExtras, 0);
}

function filterLayers(text) { renderLayersList(text); }

function selectLayerAsActive(id) {
    activeLayerId = id;
    const sel = document.getElementById('draw-layer-select');
    if (sel) {
        const has = [...sel.options].some(o => o.value === id);
        if (has) sel.value = id;
    }
    renderLayersList(document.getElementById('layer-search').value);
}

function toggleLayerVisibility(id) {
    const entry = findLayerEntry(id);
    if (!entry) return;
    entry.visible = !entry.visible;
    if (entry.visible) { entry.group.addTo(map); } else { map.removeLayer(entry.group); }
    logAction('tool', `Изменена видимость слоя «${entry.name}»`);
    renderLegend();
    renderFieldLabels();
}

function changeLayerColor(id, color) {
    const entry = findLayerEntry(id);
    if (!entry || !isCustomLayer(entry)) { showToast('Цвет стандартных слоёв нельзя менять'); return; }
    entry.color = color;
    entry.group.eachLayer(l => l.setStyle({ color, fillColor: color, weight: displaySettings.lineWidth }));
    logAction('tool', `Изменён цвет слоя «${entry.name}»`);
    renderLegend();
}

function toggleCreateLayerForm() {
    openAppModal({
        title: 'Новый слой',
        bodyHtml: `<label class="modal-label">Название</label>
            <input type="text" id="modal-layer-name" class="search-input modal-input" placeholder="Название слоя">
            <label class="modal-label">Цвет</label>
            <input type="color" id="modal-layer-color" value="#3388ff" class="color-input modal-input">`,
        actions: [
            { label: 'Создать', className: 'mini-btn mini-btn-red', onClick: () => {
                const name = document.getElementById('modal-layer-name')?.value.trim();
                const color = document.getElementById('modal-layer-color')?.value || '#3388ff';
                if (!name) return;
                const id = 'layer_' + Date.now();
                const group = L.featureGroup().addTo(map);
                layersRegistry.push({ id, name, color, group, visible: true, folderId: null, detected: false });
                activeLayerId = id;
                saveFoldersState();
                closeAppModal();
                renderLayersList(document.getElementById('layer-search')?.value);
                logAction('tool', `Создан новый слой «${name}»`);
                renderLegend();
                populateDrawLayerSelect();
                showToast(`Слой «${name}» создан`);
            }},
            { label: 'Отмена', className: 'mini-btn', onClick: () => closeAppModal() },
        ],
        focusId: 'modal-layer-name',
    });
}

function createLayer() { toggleCreateLayerForm(); }

function renameLayer(id) {
    const entry = findLayerEntry(id);
    if (!entry || !isCustomLayer(entry)) { showToast('Стандартные слои нельзя переименовывать'); return; }
    openAppModal({
        title: 'Переименовать слой',
        bodyHtml: `<label class="modal-label">Название</label>
            <input type="text" id="modal-layer-name" class="search-input modal-input" value="${String(entry.name).replace(/"/g, '&quot;')}">`,
        actions: [
            { label: 'Сохранить', className: 'mini-btn mini-btn-red', onClick: () => {
                const next = document.getElementById('modal-layer-name')?.value.trim();
                if (!next) return;
                entry.name = next;
                closeAppModal();
                renderLayersList(document.getElementById('layer-search')?.value);
                logAction('tool', `Переименован слой «${entry.name}»`);
                renderLegend();
                populateDrawLayerSelect();
            }},
            { label: 'Отмена', className: 'mini-btn', onClick: () => closeAppModal() },
        ],
        focusId: 'modal-layer-name',
    });
}

function deleteLayer(id) {
    const entry = findLayerEntry(id);
    if (!entry) return;
    if (!isCustomLayer(entry)) { showToast('Стандартные слои нельзя удалять'); return; }
    if (!confirm(`Удалить слой «${entry.name}» со всеми объектами?`)) return;
    if (entry.visible) map.removeLayer(entry.group);
    layersRegistry = layersRegistry.filter(l => l.id !== id);
    if (activeLayerId === id) activeLayerId = layersRegistry[0]?.id || null;
    selectedFeatures = selectedFeatures.filter(s => s.layerId !== id);
    if (selectedFieldLayerId === id) hideFieldDetail();
    clearVertexMarkers();
    renderLayersList(document.getElementById('layer-search').value);
    logAction('tool', `Удалён слой «${entry.name}»`);
    renderLegend();
}

/* --- Импорт GeoJSON / Shapefile (.zip) --- */
function importLayerFile(file) {
    if (!file) return;
    const isZip = file.name.toLowerCase().endsWith('.zip');

    const id = 'imported_' + Date.now();
    const color = '#3388ff';
    const group = L.featureGroup().addTo(map);
    layersRegistry.push({ id, name: 'Импорт: ' + file.name, color, group, visible: true, folderId: null, detected: true });
    activeLayerId = id;

    const addGeoJSONToGroup = (geojson) => {
        L.geoJSON(geojson, {
            style: { color, weight: 2, fillColor: color, fillOpacity: getFillOpacity(false) },
            onEachFeature: (feature, layer) => bindFeatureEvents(layer, id)
        }).eachLayer(l => l.addTo(group));
        const bounds = group.getBounds();
        if (bounds.isValid()) map.fitBounds(bounds, { maxZoom: 15 });
        renderLayersList(document.getElementById('layer-search').value);
        logAction('tool', `Импортирован слой из файла «${file.name}»`);
        renderLegend();
    };

    if (isZip) {
        if (!window.shp) { alert('Библиотека для чтения Shapefile не загрузилась (нет интернета).'); return; }
        file.arrayBuffer().then(buf => shp(buf).then(addGeoJSONToGroup).catch(err => alert('Не удалось прочитать Shapefile: ' + err)));
    } else {
        const reader = new FileReader();
        reader.onload = () => {
            try { addGeoJSONToGroup(JSON.parse(reader.result)); }
            catch (err) { alert('Не удалось прочитать GeoJSON: ' + err); }
        };
        reader.readAsText(file);
    }
}

/* --- Загрузка снимка --- */
function handleUploadFile(file) {
    if (!file) return;
    uploadedFile = file;
    const status = document.getElementById('upload-status');
    const btn = document.getElementById('upload-process-btn');
    status.innerText = `Файл «${file.name}» выбран`;
    if (btn) btn.disabled = false;
    setMapSegStatus(`Загружен файл «${file.name}» — можно сегментировать`);
    logAction('upload', `Загружен снимок «${file.name}»`);
    showToast('Снимок загружен');
}

function startUploadProcessing() {
    runSegmentation(getSelectedArchitecture(), { preferUpload: true });
}

function runSegmentation(architecture, opts = {}) {
    if (architecture === 'yolo' || architecture === 'segformer') {
        const radio = document.querySelector(`input[name="seg-architecture"][value="${architecture}"]`);
        if (radio) {
            radio.checked = true;
            onSegArchitectureChange();
        }
    }

    const status = document.getElementById('upload-status');
    const progress = document.getElementById('upload-progress');
    const bar = document.getElementById('upload-progress-bar');
    const arch = architecture || getSelectedArchitecture();
    const threshold = getSegmentationThreshold();

    setSegmentButtonsEnabled(false);
    setMapSegProgress(8);
    setMapSegStatus(`Сегментация ${arch}, порог ${Math.round(threshold * 100)}%…`);
    if (status) status.innerText = `Сегментация (${arch}, порог ${Math.round(threshold * 100)}%)...`;
    if (progress) progress.style.display = 'block';
    if (bar) bar.style.width = '8%';

    (async () => {
        try {
            const health = await fetchMlHealth();
            if (!health.model_loaded && !(health.available_models || []).length) {
                throw new Error(
                    health.hint || 'На ML-сервере нет весов моделей (best_iou.pth / yolo_best.pt)',
                );
            }
            const available = health.available_models || [];
            if (available.length && !available.includes(arch)) {
                throw new Error(
                    `Модель «${arch}» недоступна. Есть: ${available.join(', ') || 'нет'}`,
                );
            }

            setMapSegProgress(25);
            if (bar) bar.style.width = '25%';

            let sourceFile = null;
            let sourceLabel = 'карта';
            if (opts.preferUpload && uploadedFile) {
                sourceFile = uploadedFile;
                sourceLabel = uploadedFile.name;
                lastMapCapture = null;
            } else if (uploadedFile && opts.forceUpload) {
                sourceFile = uploadedFile;
                sourceLabel = uploadedFile.name;
                lastMapCapture = null;
            } else {
                setMapSegStatus('Снимаю выделенную область с карты…');
                sourceFile = await captureMapRegionAsFile();
                sourceLabel = sourceFile.name;
            }

            setMapSegProgress(45);
            if (bar) bar.style.width = '45%';

            const geoBounds = lastMapCapture?.geoBounds
                ? { ...lastMapCapture.geoBounds }
                : getMapGeoBounds();
            clearMapWorkspace({ keepFolders: true });
            if (aoiLayer && map && !map.hasLayer(aoiLayer)) aoiLayer.addTo(map);

            const result = await callSegmentationApi(sourceFile, arch, threshold);
            setMapSegProgress(85);
            if (bar) bar.style.width = '85%';

            const { count, allBounds } = applyApiSegmentationResult(result, arch, geoBounds);
            if (count === 0) {
                const msg = 'ML не нашёл объектов — понизьте порог или смените модель';
                if (status) status.innerText = msg;
                setMapSegStatus(msg, true);
                showToast('Объекты не найдены');
                return;
            }

            finalizeAnalysisOnMap(allBounds);

            const processId = 'proc_' + Date.now();
            setMapSegProgress(100);
            if (bar) bar.style.width = '100%';
            const done = `Готово: ${arch}, порог ${Math.round(threshold * 100)}%, объектов: ${count}`;
            if (status) status.innerText = done;
            setMapSegStatus(done);
            if (uploadedFile) {
                await storeProcessedUpload(uploadedFile, processId);
                await storeProcessedResult(processId, uploadedFile.name);
            }
            incStat('processed');
            logAction('process', `Сегментация «${sourceLabel}» (${arch})`, { processId });
            showToast('Сегментация завершена');
            updateMlNetworkStatus();
        } catch (err) {
            console.error(err);
            const msg = `Ошибка ML: ${err.message || err}`;
            if (status) status.innerText = msg;
            setMapSegStatus(msg, true);
            showToast('Ошибка обработки');
            logAction('process', `Ошибка обработки: ${err.message || err}`);
        } finally {
            setSegmentButtonsEnabled(true);
            setTimeout(() => {
                setMapSegProgress(null);
                if (progress) progress.style.display = 'none';
                if (bar) bar.style.width = '0%';
            }, 800);
        }
    })();
}

/* --- Настройки распознавания и подложки --- */
function setBasemapLayerVisible(layer, visible) {
    if (!map || !layer) return;
    const has = map.hasLayer(layer);
    if (visible && !has) layer.addTo(map);
    else if (!visible && has) map.removeLayer(layer);
}

function bringGroupToFront(group) {
    if (!map || !group) return;
    if (typeof group.bringToFront === 'function') {
        if (typeof map.hasLayer !== 'function' || map.hasLayer(group)) group.bringToFront();
        return;
    }
    if (typeof group.eachLayer === 'function') {
        group.eachLayer((layer) => {
            if (typeof layer.bringToFront === 'function') layer.bringToFront();
        });
    }
}

function raiseWorkingOverlays() {
    if (!map) return;
    layersRegistry.forEach((entry) => {
        if (entry?.group && map.hasLayer(entry.group)) bringGroupToFront(entry.group);
    });
    bringGroupToFront(overlaysLayerGroup);
    bringGroupToFront(textLayerGroup);
    bringGroupToFront(fieldLabelsLayerGroup);
    if (aoiLayer && map.hasLayer(aoiLayer)) bringGroupToFront(aoiLayer);
}

function dzzViewHasCoverage() {
    if (!map || !dzzSites.length) return false;
    const view = map.getBounds();
    return dzzSites.some((site) => view.intersects(site.bounds));
}

function restoreMapView(view) {
    if (!map || !view) return;
    map.setView(view.center, view.zoom, { animate: false });
}

function removeBasemapLayers() {
    setBasemapLayerVisible(tileSatellite, false);
    setBasemapLayerVisible(tileScheme, false);
    setBasemapLayerVisible(tileDzz, false);
    setBasemapLayerVisible(tileCustom, false);
}

function buildAuthLayer(urlTemplate, login, password, attribution) {
    const resolved = resolveXyzTileTemplate(urlTemplate);
    const url = (resolved?.url || '').trim();
    if (!url || (!url.includes('{z}') && !url.includes('{TileMatrix}'))) return null;
    return new AuthTileLayer(url, {
        attribution: attribution || '',
        maxZoom: 22,
        minZoom: 3,
        maxNativeZoom: resolved.maxNativeZoom,
        minNativeZoom: resolved.minNativeZoom,
        zoomOffset: resolved.zoomOffset,
        keepBuffer: 2,
        updateWhenZooming: false,
        updateWhenIdle: true,
        crossOrigin: true,
        authUser: login || '',
        authPass: password || '',
        errorTileUrl: '',
        zIndex: 1,
    });
}

function buildDzzLayer(urlTemplate) {
    const resolved = resolveDzzTileTemplate(urlTemplate);
    const url = (resolved.url || '').trim();
    if (!url || (!url.includes('{z}') && !url.includes('{TileMatrix}'))) return null;
    const layer = new DzzOrthoLayer(url, {
        attribution: 'dzz.by · БелПСХАГИ',
        maxZoom: 22,
        minZoom: 3,
        maxNativeZoom: resolved.maxNativeZoom,
        minNativeZoom: resolved.minNativeZoom,
        zoomOffset: resolved.zoomOffset,
        dzzSig: `proxy|${url}`,
        keepBuffer: 4,
        updateWhenIdle: true,
        updateWhenZooming: false,
        className: 'dzz-ortho-layer',
        errorTileUrl: '',
        zIndex: 2,
    });
    return layer;
}

function setBasemap(value, silent = false) {
    if (!map) return;
    readBasemapExtraFromForm();

    if (value === 'dzz' && !dzzSession.connected) {
        if (!silent) showToast('Укажите логин, пароль и адрес, затем «Проверить подключение»');
        const select = document.getElementById('opt-basemap');
        if (select) select.value = currentBasemap;
        updateBasemapExtraVisibility(currentBasemap);
        return;
    }
    if (value === 'custom' && !basemapExtra.customUrl) {
        if (!silent) showToast('Укажите URL дополнительной подложки');
        const select = document.getElementById('opt-basemap');
        if (select) select.value = currentBasemap;
        updateBasemapExtraVisibility(currentBasemap);
        return;
    }

    const view = { center: map.getCenter(), zoom: map.getZoom() };
    const wantedCrs = wantedCrsForBasemap(value);
    if (currentMapCrs() !== wantedCrs) {
        ensureMapCrs(wantedCrs);
    }

    if (value === 'dzz') {
        const nextUrl = basemapExtra.dzzUrl || DZZ_DEFAULT_TILE_URL;
        const sig = `proxy|${resolveDzzTileTemplate(nextUrl).url}`;
        const canReuse = tileDzz && tileDzz._dzzSig === sig;
        if (!canReuse) {
            const layer = buildDzzLayer(nextUrl);
            if (!layer) {
                if (!silent) showToast('Проверьте URL шаблон тайлов dzz.by');
                return;
            }
            setBasemapLayerVisible(tileDzz, false);
            tileDzz = layer;
        }
        setBasemapLayerVisible(tileScheme, false);
        setBasemapLayerVisible(tileCustom, false);
        setBasemapLayerVisible(tileSatellite, true);
        setBasemapLayerVisible(tileDzz, true);
        tileSatellite.setZIndex(1);
        tileDzz.setZIndex(2);
        loadDzzSites(nextUrl, { silent: true, focus: false }).then((ok) => {
            if (ok && dzzSites.length && !dzzViewHasCoverage()) {
                setDzzConnStatus(`Подключено: ${dzzSites.length} участок(ов). Выберите участок внизу, если ортофото не видно`);
            }
            raiseWorkingOverlays();
        });
    } else if (value === 'custom') {
        const sig = `${basemapExtra.customUrl}|${basemapExtra.customLogin}|${basemapExtra.customName}|${basemapExtra.customCrs}|${basemapExtra.customZoomOffset}`;
        if (!tileCustom || tileCustomSig !== sig) {
            const layer = buildAuthLayer(
                basemapExtra.customUrl,
                basemapExtra.customLogin,
                basemapExtra.customPassword,
                basemapExtra.customName || 'Дополнительная подложка'
            );
            if (!layer) {
                if (!silent) showToast('URL должен содержать {z}/{x}/{y} или ArcGIS {z}/{y}/{x}');
                return;
            }
            setBasemapLayerVisible(tileCustom, false);
            tileCustom = layer;
            tileCustomSig = sig;
        }
        setBasemapLayerVisible(tileSatellite, false);
        setBasemapLayerVisible(tileScheme, false);
        setBasemapLayerVisible(tileDzz, false);
        setBasemapLayerVisible(tileCustom, true);
    } else if (value === 'scheme') {
        setBasemapLayerVisible(tileSatellite, false);
        setBasemapLayerVisible(tileDzz, false);
        setBasemapLayerVisible(tileCustom, false);
        setBasemapLayerVisible(tileScheme, true);
    } else {
        value = 'satellite';
        setBasemapLayerVisible(tileScheme, false);
        setBasemapLayerVisible(tileDzz, false);
        setBasemapLayerVisible(tileCustom, false);
        setBasemapLayerVisible(tileSatellite, true);
    }

    restoreMapView(view);
    raiseWorkingOverlays();
    updateCrsDisplay();

    currentBasemap = value;
    displaySettings.basemap = value;
    const select = document.getElementById('opt-basemap');
    if (select) select.value = value;
    updateBasemapExtraVisibility(value);
    renderDzzSites();
    if (value === 'dzz') scheduleDzzPrefetch();
    else dzzClearPrefetchQueue();

    if (!silent) {
        const labels = {
            satellite: 'Спутник',
            scheme: 'Схема',
            dzz: 'dzz.by',
            custom: basemapExtra.customName || 'Дополнительная подложка',
        };
        logAction('tool', `Изменена подложка карты: ${labels[value] || value}`);
    }
}

function saveSettings() {
    displaySettings.pointSize = parseInt(document.getElementById('opt-point-size').value, 10) || 5;
    displaySettings.lineWidth = parseInt(document.getElementById('opt-line-width').value, 10) || 2;
    const fillPct = parseInt(document.getElementById('opt-fill-opacity')?.value, 10);
    displaySettings.fillOpacity = Number.isFinite(fillPct) ? Math.min(0.9, Math.max(0.05, fillPct / 100)) : 0.35;
    displaySettings.coordColor = document.getElementById('opt-coord-color').value;
    displaySettings.basemap = document.getElementById('opt-basemap')?.value || 'satellite';
    readBasemapExtraFromForm();
    localStorage.setItem(displaySettingsKey(), JSON.stringify(displaySettings));
    persistBasemapExtra();
    applyDisplaySettings();
    setBasemap(displaySettings.basemap);
    logAction('account', 'Обновлены настройки');
    showToast('Настройки сохранены');
}

/* =========================================================
   ИНСТРУМЕНТЫ КАРТЫ
   ========================================================= */
const TOOL_NAMES = {
    select: 'Выделение области',
    ruler: 'Линейка',
    compass: 'Циркуль',
    text: 'Текст',
    freehand: 'Редактирование области',
};

function deactivateCurrentTool() {
    document.getElementById('more-menu')?.classList.remove('active');
    stopFreehandEdit();
    document.getElementById('map-area')?.classList.remove('tool-eraser', 'tool-brush');
    clearRulerPreview();
    clearCompassPreview();
    if (activeDrawHandler) {
        activeDrawHandler.disable();
        activeDrawHandler = null;
    }
    if (selectedFeatures.length === 1 && selectedFeatures[0].layer?.editing?.enabled()) {
        selectedFeatures[0].layer.editing.disable();
    }
    if (mapMouseMoveHandler) {
        map.off('mousemove', mapMouseMoveHandler);
        mapMouseMoveHandler = null;
    }
    compassCenter = null;
}

function setTool(tool) {
    if (tool !== 'freehand' && createSessionActive) {
        discardCreateDraft();
        createSessionActive = false;
    }
    deactivateCurrentTool();
    activeTool = tool;
    editDrawMode = null;

    document.querySelectorAll('.tool-btn[data-tool]').forEach(btn => btn.classList.remove('active'));
    const btn = document.querySelector(`.tool-btn[data-tool="${tool}"]`);
    if (btn) btn.classList.add('active');

    const mapArea = document.getElementById('map-area');
    if (mapArea) {
        mapArea.classList.remove(
            'tool-select', 'tool-ruler', 'tool-compass', 'tool-text',
            'tool-freehand', 'tool-eraser', 'tool-brush'
        );
        mapArea.classList.add('tool-' + tool);
    }
    if (map) map.dragging.enable();
    raiseWorkingOverlays();
    if (tool !== 'freehand') {
        document.getElementById('edit-area-controls').style.display = 'none';
    }
    const toolLabel = TOOL_NAMES[tool] || tool;
    showToast(`Инструмент: ${toolLabel}`);
    logAction('tool', `Выбран инструмент: ${toolLabel}`);
}

function onMapClick(e) {
    if (currentBasemap === 'dzz' && e.originalEvent && (e.originalEvent.ctrlKey || e.originalEvent.metaKey)) {
        const t = getMapTileCoords(e.latlng, map.getZoom());
        goToDzzTile(t.z, t.x, t.y);
        return;
    }
    if (activeTool === 'freehand') return;
    if (activeTool === 'select') {
        if (suppressMapClick) return;
        const oe = e.originalEvent;
        // при зажатом Ctrl/⌘/Shift клик по карте не сбрасывает выбор
        if (oe && (oe.ctrlKey || oe.metaKey || oe.shiftKey)) return;
        clearSelection();
        hideFieldDetail();
        selectedOverlay = null;
        return;
    }
    if (activeTool === 'ruler') handleRulerClick(e);
    else if (activeTool === 'compass') handleCompassClick(e);
    else if (activeTool === 'text') handleTextClick(e);
}

function copyToClipboard(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).catch(() => {});
    }
}

function getRulerTickIntervalMeters() {
    const zoom = map?.getZoom() || 13;
    if (zoom >= 17) return 10;
    if (zoom >= 15) return 20;
    if (zoom >= 13) return 50;
    return 100;
}

function addRulerTicks(p1, p2) {
    const dist = p1.distanceTo(p2);
    const step = getRulerTickIntervalMeters();
    const count = Math.floor(dist / step);
    const bright = displaySettings.coordColor || '#ff3366';
    for (let i = 1; i <= count; i++) {
        const t = (i * step) / dist;
        const lat = p1.lat + (p2.lat - p1.lat) * t;
        const lng = p1.lng + (p2.lng - p1.lng) * t;
        const tick = L.circleMarker([lat, lng], {
            radius: displaySettings.pointSize,
            color: bright, fillColor: bright, fillOpacity: 1, weight: 2,
        });
        rulerTicks.push(tick);
    }
}

function bindOverlayClick(layer) {
    layer.on('click', (e) => {
        if (activeTool !== 'select') return;
        L.DomEvent.stopPropagation(e);
        selectedOverlay = layer;
        clearSelection();
        hideFieldDetail();
        showToast('Метка выбрана — Delete или Ctrl+Z');
    });
}

function registerMapOverlay(layers, parentGroup = overlaysLayerGroup) {
    const list = Array.isArray(layers) ? layers.filter(Boolean) : [layers];
    const groupKey = parentGroup === textLayerGroup ? 'text' : 'overlay';
    let stored;
    if (list.length > 1) {
        stored = L.layerGroup(list);
        bindOverlayClick(stored);
        parentGroup.addLayer(stored);
        pushUndo({ type: 'addOverlay', layers: [stored], groupKey });
    } else {
        list.forEach(l => {
            bindOverlayClick(l);
            parentGroup.addLayer(l);
        });
        pushUndo({ type: 'addOverlay', layers: list, groupKey });
        stored = list[0];
    }
    return stored;
}

function restoreOverlayLayers(layers, groupKey) {
    const parent = groupKey === 'text' ? textLayerGroup : overlaysLayerGroup;
    layers.forEach(l => parent?.addLayer(l));
}

function handleRulerClick(e) {
    const bright = displaySettings.coordColor || '#ff3366';
    const r = displaySettings.pointSize;

    if (rulerPoints.length === 0) {
        rulerPoints.push(e.latlng);
        if (!rulerPreviewGroup) rulerPreviewGroup = L.layerGroup().addTo(overlaysLayerGroup);
        rulerPreviewGroup.clearLayers();
        const marker = L.circleMarker(e.latlng, {
            radius: r, color: bright, fillColor: bright, fillOpacity: 1, weight: 2,
        });
        rulerMarkers = [marker];
        rulerPreviewGroup.addLayer(marker);
        mapMouseMoveHandler = (ev) => updateRulerPreview(ev.latlng);
        map.on('mousemove', mapMouseMoveHandler);
        return;
    }

    if (mapMouseMoveHandler) { map.off('mousemove', mapMouseMoveHandler); mapMouseMoveHandler = null; }
    rulerPoints.push(e.latlng);
    const distance = rulerPoints[0].distanceTo(rulerPoints[1]);
    const label = distance >= 1000 ? (distance / 1000).toFixed(2) + ' км' : Math.round(distance) + ' м';
    rulerLine = L.polyline(rulerPoints, { color: bright, weight: displaySettings.lineWidth, dashArray: '6 4' });
    addRulerTicks(rulerPoints[0], rulerPoints[1]);
    const mid = L.latLng((rulerPoints[0].lat + rulerPoints[1].lat) / 2, (rulerPoints[0].lng + rulerPoints[1].lng) / 2);
    rulerLabel = L.marker(mid, {
        icon: L.divIcon({ className: 'ruler-label', html: label, iconSize: null }),
    });
    const endMarker = L.circleMarker(e.latlng, {
        radius: r, color: bright, fillColor: bright, fillOpacity: 1, weight: 2,
    });
    const overlayLayers = [rulerMarkers[0], endMarker, rulerLine, rulerLabel, ...rulerTicks].filter(Boolean);
    clearRulerPreview();
    registerMapOverlay(overlayLayers);
    rulerPoints = [];
    rulerMarkers = [];
    rulerLine = null;
    rulerLabel = null;
    rulerTicks = [];
}

function updateRulerPreview(cursor) {
    if (!rulerPreviewGroup || rulerPoints.length !== 1) return;
    const bright = displaySettings.coordColor || '#ff3366';
    const r = displaySettings.pointSize;
    rulerPreviewGroup.clearLayers();
    rulerPreviewGroup.addLayer(rulerMarkers[0]);
    const line = L.polyline([rulerPoints[0], cursor], { color: bright, weight: displaySettings.lineWidth, dashArray: '6 4' });
    rulerPreviewGroup.addLayer(line);
    const distance = rulerPoints[0].distanceTo(cursor);
    const label = distance >= 1000 ? (distance / 1000).toFixed(2) + ' км' : Math.round(distance) + ' м';
    const mid = L.latLng((rulerPoints[0].lat + cursor.lat) / 2, (rulerPoints[0].lng + cursor.lng) / 2);
    rulerPreviewGroup.addLayer(L.marker(mid, {
        icon: L.divIcon({ className: 'ruler-label', html: label, iconSize: null }),
    }));
    rulerPreviewGroup.addLayer(L.circleMarker(cursor, {
        radius: r, color: bright, fillColor: bright, fillOpacity: 0.85, weight: 2,
    }));
}

function clearRulerPreview() {
    if (mapMouseMoveHandler) { map?.off('mousemove', mapMouseMoveHandler); mapMouseMoveHandler = null; }
    if (rulerPreviewGroup) { rulerPreviewGroup.clearLayers(); overlaysLayerGroup?.removeLayer(rulerPreviewGroup); rulerPreviewGroup = null; }
}

function clearRulerDrawing() {
    rulerPoints = [];
    rulerMarkers.forEach(m => overlaysLayerGroup?.removeLayer(m));
    rulerMarkers = [];
    rulerTicks.forEach(m => overlaysLayerGroup?.removeLayer(m));
    rulerTicks = [];
    if (rulerLine) { overlaysLayerGroup?.removeLayer(rulerLine); rulerLine = null; }
    if (rulerLabel) { overlaysLayerGroup?.removeLayer(rulerLabel); rulerLabel = null; }
}

function clearCompassPreview() {
    if (compassPreviewCircle && overlaysLayerGroup) overlaysLayerGroup.removeLayer(compassPreviewCircle);
    if (compassPreviewLabel && overlaysLayerGroup) overlaysLayerGroup.removeLayer(compassPreviewLabel);
    compassPreviewCircle = null;
    compassPreviewLabel = null;
}

function handleCompassClick(e) {
    const bright = displaySettings.coordColor || '#ff3366';
    if (!compassCenter) {
        compassCenter = e.latlng;
        const centerMarker = L.circleMarker(compassCenter, { radius: displaySettings.pointSize, color: bright, fillColor: bright, fillOpacity: 1, weight: 2 });
        compassLayer = L.layerGroup([centerMarker]);
        overlaysLayerGroup.addLayer(compassLayer);
        mapMouseMoveHandler = (ev) => {
            if (!compassCenter) return;
            const radius = compassCenter.distanceTo(ev.latlng);
            const label = radius >= 1000 ? (radius / 1000).toFixed(2) + ' км' : Math.round(radius) + ' м';
            clearCompassPreview();
            compassPreviewCircle = L.circle(compassCenter, { radius, color: bright, weight: displaySettings.lineWidth, fillOpacity: 0.08, dashArray: '4 4' });
            compassPreviewLabel = L.marker(ev.latlng, {
                icon: L.divIcon({ className: 'ruler-label', html: `R = ${label}`, iconSize: null }),
            });
            overlaysLayerGroup.addLayer(compassPreviewCircle);
            overlaysLayerGroup.addLayer(compassPreviewLabel);
        };
        map.on('mousemove', mapMouseMoveHandler);
        showToast('Укажите точку на окружности (радиус)');
        return;
    }
    const radius = compassCenter.distanceTo(e.latlng);
    const label = radius >= 1000 ? (radius / 1000).toFixed(2) + ' км' : Math.round(radius) + ' м';
    clearCompassPreview();
    if (mapMouseMoveHandler) { map.off('mousemove', mapMouseMoveHandler); mapMouseMoveHandler = null; }
    const circle = L.circle(compassCenter, { radius, color: bright, weight: displaySettings.lineWidth, fillOpacity: 0.08 });
    const edge = L.circleMarker(e.latlng, { radius: displaySettings.pointSize, color: bright, fillColor: bright, fillOpacity: 1, weight: 2 });
    const labelMarker = L.marker(e.latlng, {
        icon: L.divIcon({ className: 'ruler-label', html: `R = ${label}`, iconSize: null }),
    });
    if (compassLayer) overlaysLayerGroup.removeLayer(compassLayer);
    const layers = [circle, edge, labelMarker];
    if (compassLayer) layers.unshift(...compassLayer.getLayers());
    registerMapOverlay(layers);
    compassLayer = null;
    compassCenter = null;
    showToast(`Радиус: ${label}`);
}

function clearCompassDrawing() {
    compassCenter = null;
    clearCompassPreview();
    if (mapMouseMoveHandler) { map?.off('mousemove', mapMouseMoveHandler); mapMouseMoveHandler = null; }
    if (compassLayer && overlaysLayerGroup) { overlaysLayerGroup.removeLayer(compassLayer); compassLayer = null; }
}

function handleTextClick(e) {
    const latlng = e.latlng;
    openAppModal({
        title: 'Текстовая пометка',
        bodyHtml: `<label class="modal-label">Текст на карте</label>
            <input type="text" id="modal-map-text" class="search-input modal-input" placeholder="Введите текст…" maxlength="200">`,
        actions: [
            { label: 'Добавить', className: 'mini-btn mini-btn-red', onClick: () => {
                const text = document.getElementById('modal-map-text')?.value.trim();
                if (!text) return;
                closeAppModal();
                const marker = L.marker(latlng, {
                    icon: L.divIcon({ className: 'map-text-label', html: text, iconSize: null }),
                });
                registerMapOverlay([marker], textLayerGroup);
                showToast('Пометка добавлена');
            }},
            { label: 'Отмена', className: 'mini-btn', onClick: () => closeAppModal() },
        ],
        focusId: 'modal-map-text',
    });
}

function circleToPolygon(center, radiusMeters, sides) {
    const points = [];
    for (let i = 0; i < sides; i++) {
        const angle = (i / sides) * 2 * Math.PI;
        const dx = radiusMeters * Math.cos(angle);
        const dy = radiusMeters * Math.sin(angle);
        const lat = center.lat + (dy / 111320);
        const lng = center.lng + (dx / (111320 * Math.cos(center.lat * Math.PI / 180)));
        points.push([lat, lng]);
    }
    return points;
}


function getDrawLayerOptions() {
    const options = [];
    const seen = new Set();
    DEFAULT_LAYERS.forEach(def => {
        const entry = findLayerEntry(def.id);
        if (entry && !seen.has(entry.id)) {
            options.push(entry);
            seen.add(entry.id);
        }
    });
    layersRegistry.forEach(entry => {
        if (seen.has(entry.id)) return;
        if (isCustomLayer(entry) || entry.detected || String(entry.id).startsWith('imported_')) {
            options.push(entry);
            seen.add(entry.id);
        }
    });
    return options;
}

function updateCreateCropBlockVisibility() {
    const block = document.getElementById('create-crop-block');
    if (!block) return;
    const layerId = document.getElementById('draw-layer-select')?.value || draftCreateLayerId || activeLayerId;
    const show = createSessionActive && layerSupportsCrop(layerId);
    block.style.display = show ? 'block' : 'none';
    if (show) {
        populateCreateCropSelect();
        const sel = document.getElementById('create-crop-select');
        if (sel && !sel._manageBound) {
            sel._manageBound = true;
            sel.addEventListener('change', () => {
                if (sel.value === '__manage__') {
                    sel.value = '';
                    openManageCustomCropsModal();
                }
            });
        }
    }
}

function openEditAreaMode() {
    if (selectedFeatures.length !== 1) {
        showToast('Выделите одну область для редактирования (или создайте новую через «Создать область»).');
        return;
    }
    createSessionActive = false;
    discardCreateDraft();
    activeLayerId = selectedFeatures[0].layerId;
    document.getElementById('create-crop-block').style.display = 'none';
    populateDrawLayerSelect();
    const sel = document.getElementById('draw-layer-select');
    if (sel) sel.value = activeLayerId;
    document.getElementById('edit-area-controls').style.display = 'block';
    const title = document.getElementById('paint-hud-title');
    if (title) title.textContent = 'Редактирование';
    document.getElementById('more-menu')?.classList.add('active');
    setEditDrawMode('brush');
    showToast('Редактирование: кисть расширяет, ластик подрезает край. «Готово» — выход.');
}

function setEditDrawMode(mode) {
    if (createSessionActive) {
        editDrawMode = mode === 'eraser' ? 'eraser' : 'create';
    } else {
        editDrawMode = mode;
    }
    document.getElementById('edit-brush-btn')?.classList.toggle('active', mode === 'brush' || mode === 'create');
    document.getElementById('edit-eraser-btn')?.classList.toggle('active', mode === 'eraser');
    const mapArea = document.getElementById('map-area');
    mapArea?.classList.toggle('tool-eraser', mode === 'eraser');
    mapArea?.classList.toggle('tool-brush', mode !== 'eraser');
    startFreehandEdit(editDrawMode);
}

function finishEditAreaMode() {
    // старый механизм: объекты уже созданы/изменены по штрихам
    createSessionActive = false;
    discardCreateDraft();
    stopFreehandEdit();
    document.getElementById('edit-area-controls').style.display = 'none';
    document.getElementById('more-menu')?.classList.remove('active');
    document.getElementById('map-area')?.classList.remove('tool-eraser', 'tool-brush');
    setTool('select');
    renderFieldLabels();
}

function startCreateArea() {
    clearSelection();
    hideFieldDetail();
    createSessionActive = true;
    discardCreateDraft();
    populateDrawLayerSelect();
    const sel = document.getElementById('draw-layer-select');
    const preferred = (activeLayerId && [...(sel?.options || [])].some(o => o.value === activeLayerId))
        ? activeLayerId
        : (sel?.options?.[0]?.value || 'crops');
    if (sel && preferred) sel.value = preferred;
    draftCreateLayerId = preferred;
    activeLayerId = preferred;
    updateCreateCropBlockVisibility();
    document.getElementById('edit-area-controls').style.display = 'block';
    const title = document.getElementById('paint-hud-title');
    if (title) title.textContent = 'Создание области';
    editDrawMode = 'create';
    document.getElementById('edit-brush-btn')?.classList.add('active');
    document.getElementById('edit-eraser-btn')?.classList.remove('active');
    document.getElementById('more-menu')?.classList.add('active');
    startFreehandEdit('create');
    showToast('Создание: обведите область кистью. Каждый штрих — объект. «Готово» — выход.');
}

function discardCreateDraft() {
    if (draftCreatePolygon) {
        if (overlaysLayerGroup?.hasLayer(draftCreatePolygon)) overlaysLayerGroup.removeLayer(draftCreatePolygon);
        else if (map?.hasLayer(draftCreatePolygon)) map.removeLayer(draftCreatePolygon);
    }
    draftCreatePolygon = null;
}

function commitCreateDraft() {
    // no-op: старый freehand сразу сохраняет объекты на слой
    createSessionActive = false;
    discardCreateDraft();
}

function startFreehandEdit(mode) {
    if (!map) { showToast('Карта ещё не готова'); return; }
    activeTool = 'freehand';
    if (mode === 'eraser') editDrawMode = 'eraser';
    else if (createSessionActive) editDrawMode = 'create';
    else editDrawMode = mode === 'brush' ? 'brush' : (mode || 'brush');

    const mapArea = document.getElementById('map-area');
    mapArea?.classList.remove('tool-select', 'tool-ruler', 'tool-compass', 'tool-text');
    mapArea?.classList.add('tool-freehand');
    mapArea?.classList.toggle('tool-eraser', editDrawMode === 'eraser');
    mapArea?.classList.toggle('tool-brush', editDrawMode !== 'eraser');

    // меню «Ещё» с настройками кисти остаётся открытым — не пересекается с toolbar
    document.getElementById('more-menu')?.classList.add('active');

    map.dragging.disable();
    // старый механизм: mousedown на карте, move/up на document
    map.off('mousedown', onFreehandDown);
    document.removeEventListener('mousemove', onFreehandDocMove);
    document.removeEventListener('mouseup', onFreehandUp);
    map.on('mousedown', onFreehandDown);
    document.addEventListener('mousemove', onFreehandDocMove);
    document.addEventListener('mouseup', onFreehandUp);

    showToast(
        editDrawMode === 'eraser'
            ? 'Ластик: проведите по краю объекта'
            : createSessionActive
                ? 'Обведите область кистью, затем «Готово»'
                : 'Кисть: проведите рядом с объектом, чтобы расширить'
    );
}

function stopFreehandEdit() {
    freehandActive = false;
    freehandPath = [];
    if (freehandPreviewLayer && overlaysLayerGroup) {
        overlaysLayerGroup.removeLayer(freehandPreviewLayer);
        freehandPreviewLayer = null;
    }
    if (brushCursorLayer && overlaysLayerGroup) {
        overlaysLayerGroup.removeLayer(brushCursorLayer);
        brushCursorLayer = null;
    }
    if (map) {
        map.off('mousedown', onFreehandDown);
        map.dragging.enable();
    }
    document.removeEventListener('mousemove', onFreehandDocMove);
    document.removeEventListener('mouseup', onFreehandUp);
    // cleanup legacy map handlers if any
    map?.off('mousemove', onFreehandMapMove);
    map?.off('mouseup', onFreehandUp);
}

function updateBrushCursor(latlng) {
    if (activeTool !== 'freehand' || !overlaysLayerGroup || !latlng) return;
    const radiusM = Math.max(0.8, getBrushSizeMeters() / 2);
    if (brushCursorLayer) overlaysLayerGroup.removeLayer(brushCursorLayer);
    const isEraser = editDrawMode === 'eraser';
    brushCursorLayer = L.circle(latlng, {
        radius: radiusM,
        color: isEraser ? '#e14059' : '#3388ff',
        weight: 1.5,
        dashArray: isEraser ? '2 3' : null,
        fillColor: isEraser ? '#e14059' : '#3388ff',
        fillOpacity: isEraser ? 0.12 : 0.08,
        interactive: false,
    });
    overlaysLayerGroup.addLayer(brushCursorLayer);
}

function densifyPath(path, stepM) {
    if (!path || path.length < 2) return path ? path.slice() : [];
    const out = [path[0]];
    for (let i = 1; i < path.length; i++) {
        const a = path[i - 1], b = path[i];
        const dist = a.distanceTo(b);
        const n = Math.max(1, Math.floor(dist / stepM));
        for (let k = 1; k <= n; k++) {
            const t = k / n;
            out.push(L.latLng(a.lat + (b.lat - a.lat) * t, a.lng + (b.lng - a.lng) * t));
        }
    }
    return out;
}

function densifyClosedRing(ring, stepM) {
    if (!ring || ring.length < 3) return ring ? ring.slice() : [];
    const pts = ring.map(p => L.latLng(p.lat, p.lng));
    if (pts[0].distanceTo(pts[pts.length - 1]) > 1e-9) pts.push(pts[0]);
    return densifyPath(pts, stepM);
}

function pointNearPath(latlng, path, radiusM) {
    return path.some(p => p.distanceTo(latlng) <= radiusM);
}

function getPolygonRing(layer) {
    const latlngs = layer.getLatLngs();
    return Array.isArray(latlngs[0]) ? latlngs[0] : latlngs;
}

function pointInPolygonLatLng(point, polygonCoords) {
    const x = point.lng, y = point.lat;
    let inside = false;
    for (let i = 0, j = polygonCoords.length - 1; i < polygonCoords.length; j = i++) {
        const xi = polygonCoords[i][1], yi = polygonCoords[i][0];
        const xj = polygonCoords[j][1], yj = polygonCoords[j][0];
        const inter = ((yi > y) !== (yj > y)) && (x < (xj - xi) * (y - yi) / (yj - yi + 1e-12) + xi);
        if (inter) inside = !inside;
    }
    return inside;
}

function pointInPolygonRing(latlng, ring) {
    return pointInPolygonLatLng(latlng, ring.map(p => [p.lat, p.lng]));
}

function getBrushSizeMeters() {
    return parseInt(document.getElementById('brush-size')?.value || 20, 10);
}

function closeToolsMenu() {
    // не закрываем меню, пока активна кисть/создание — там панель настроек
    if (activeTool === 'freehand' || createSessionActive) return;
    document.getElementById('more-menu')?.classList.remove('active');
}

function setPaintingUi(_active) {
    // no-op: панели остаются на месте (в more-menu), toolbar не трогаем
}

function destroyPaintSession() {
    // no-op: PhotoRoom / mask-painter удалён
}

function eventToLatLng(e) {
    if (e && e.latlng) return e.latlng;
    const oe = e?.originalEvent || e;
    if (map && oe) {
        try { return map.mouseEventToLatLng(oe.touches ? oe.touches[0] : oe); }
        catch { /* ignore */ }
    }
    return null;
}

/** Ластик: убрать вершины контура рядом со штрихом */
function subtractStrokeFromPolygon(layer, path, sizeM) {
    const ring = getPolygonRing(layer);
    if (!ring || ring.length < 3) return null;
    const base = ring.map(p => L.latLng(p.lat, p.lng));
    if (base.length > 1 && base[0].distanceTo(base[base.length - 1]) < 1e-9) base.pop();

    const radius = Math.max(1.0, sizeM / 2);
    const dense = densifyClosedRing(base, Math.max(0.5, radius / 5));
    if (dense.length < 6) return null;
    const brush = densifyPath(path, Math.max(0.4, radius / 6));
    const erased = dense.map(pt => pointNearPath(pt, brush, radius));

    const keptCount = erased.filter(e => !e).length;
    if (keptCount < Math.max(4, Math.floor(dense.length * 0.3))) {
        let sLat = 0, sLng = 0;
        base.forEach(p => { sLat += p.lat; sLng += p.lng; });
        const c = L.latLng(sLat / base.length, sLng / base.length);
        return base.map(pt => {
            if (!pointNearPath(pt, brush, radius * 1.1)) return pt;
            return L.latLng(c.lat + (pt.lat - c.lat) * 0.9, c.lng + (pt.lng - c.lng) * 0.9);
        });
    }

    let best = [], cur = [];
    for (let i = 0; i < dense.length; i++) {
        if (!erased[i]) cur.push(dense[i]);
        else { if (cur.length > best.length) best = cur; cur = []; }
    }
    if (cur.length > best.length) best = cur;
    if (!erased[0] && !erased[dense.length - 1]) {
        let L0 = 0; while (L0 < dense.length && !erased[L0]) L0++;
        let R0 = 0; while (R0 < dense.length && !erased[dense.length - 1 - R0]) R0++;
        if (L0 + R0 < dense.length) {
            const wrap = dense.slice(dense.length - R0).concat(dense.slice(0, L0));
            if (wrap.length > best.length) best = wrap;
        }
    }
    if (best.length < 3) return null;
    const out = [best[0]];
    for (let i = 1; i < best.length; i++) {
        if (out[out.length - 1].distanceTo(best[i]) > 0.4) out.push(best[i]);
    }
    if (out.length < 3) return null;
    if (out[0].distanceTo(out[out.length - 1]) > 0.5) out.push(out[0]);
    return out;
}

function onFreehandDown(e) {
    if (activeTool !== 'freehand' || !map) return;
    const latlng = eventToLatLng(e);
    if (!latlng) return;
    if (e.originalEvent) {
        L.DomEvent.stopPropagation(e.originalEvent);
        L.DomEvent.preventDefault(e.originalEvent);
    } else {
        L.DomEvent.stopPropagation(e);
        L.DomEvent.preventDefault(e);
    }

    freehandActive = true;
    freehandPath = [latlng];
    eraserLastLatLng = latlng;
    eraserDidChange = false;
    eraserUndoBefore = null;
    eraserTargetLayer = null;
    updateBrushCursor(latlng);

    if (!createSessionActive && (editDrawMode === 'brush' || editDrawMode === 'eraser')) {
        if (selectedFeatures.length !== 1) {
            showToast('Выделите один объект для редактирования');
            freehandActive = false;
            return;
        }
        eraserTargetLayer = selectedFeatures[0].layer;
        eraserUndoBefore = JSON.parse(JSON.stringify(eraserTargetLayer.getLatLngs()));
    }
}

function onFreehandDocMove(e) {
    if (activeTool !== 'freehand' || !map) return;
    let latlng = null;
    try { latlng = map.mouseEventToLatLng(e); } catch { return; }
    if (!latlng) return;
    updateBrushCursor(latlng);
    if (!freehandActive) return;

    const last = freehandPath[freehandPath.length - 1];
    if (last && map.latLngToContainerPoint(last).distanceTo(map.latLngToContainerPoint(latlng)) < 3) return;
    freehandPath.push(latlng);
    updateFreehandPreview();
}

// legacy name kept for cleanup
function onFreehandMapMove(e) {
    onFreehandDocMove(e?.originalEvent || e);
}

function onFreehandUp() {
    if (!freehandActive) return;
    freehandActive = false;

    if (freehandPreviewLayer && overlaysLayerGroup) {
        overlaysLayerGroup.removeLayer(freehandPreviewLayer);
        freehandPreviewLayer = null;
    }

    if (freehandPath.length >= 2) {
        applyFreehandStroke();
    }

    freehandPath = [];
    eraserLastLatLng = null;
    eraserTargetLayer = null;
    eraserUndoBefore = null;
    eraserDidChange = false;
}

function updateFreehandPreview() {
    if (freehandPath.length < 2) return;
    const isEraser = editDrawMode === 'eraser';
    const color = isEraser ? '#e14059' : (displaySettings.coordColor || '#ff3366');
    const weight = isEraser
        ? Math.max(2, Math.min(16, getBrushSizeMeters() / 3))
        : Math.max(2, Math.min(6, (displaySettings.lineWidth || 2) + 1));
    if (freehandPreviewLayer && overlaysLayerGroup) overlaysLayerGroup.removeLayer(freehandPreviewLayer);
    freehandPreviewLayer = L.polyline(freehandPath, {
        color, weight, opacity: 0.9, lineCap: 'round', lineJoin: 'round',
        dashArray: isEraser ? '5 4' : '4 4',
    });
    overlaysLayerGroup.addLayer(freehandPreviewLayer);
}

/**
 * Старый freehand (не PhotoRoom):
 *  - create/brush: штрих → круги по толщине → convexHull → полигон
 *  - eraser: подрезка края
 */
function applyFreehandStroke() {
    if (freehandPath.length < 2) return;
    const sizeM = getBrushSizeMeters();
    const layerId = document.getElementById('draw-layer-select')?.value || draftCreateLayerId || activeLayerId;
    if (!layerId || layerId === '__new__') {
        showToast('Выберите слой');
        return;
    }
    activeLayerId = layerId;
    const entry = findLayerEntry(layerId);
    if (!entry) return;

    // ——— ЛАСТИК ———
    if (editDrawMode === 'eraser') {
        const layer = eraserTargetLayer || (selectedFeatures[0] && selectedFeatures[0].layer);
        if (!layer) {
            showToast('Выделите один объект — ластик работает только с ним');
            return;
        }
        const before = eraserUndoBefore || JSON.parse(JSON.stringify(layer.getLatLngs()));
        const trimmed = subtractStrokeFromPolygon(layer, freehandPath, sizeM);
        if (!trimmed || trimmed.length < 3) {
            showToast('Ластик не изменил контур — проведите по границе объекта');
            return;
        }
        layer.setLatLngs(trimmed);
        pushUndo({ type: 'modifyFeature', layer, before, after: layer.getLatLngs() });
        renderFieldLabels();
        showVertexMarkers(layer, selectedFeatures[0]?.layerId || layerId);
        showToast('Контур скорректирован');
        logAction('tool', 'Контур объекта скорректирован ластиком');
        return;
    }

    // ——— КИСТЬ / СОЗДАНИЕ: sausage hull (старый механизм) ———
    let allPts = [];
    freehandPath.forEach(pt => {
        circleToPolygon(pt, sizeM / 2, 10).forEach(c => allPts.push(c));
    });

    if (editDrawMode === 'brush' && selectedFeatures.length === 1) {
        const sel = selectedFeatures[0].layer;
        const ring = getPolygonRing(sel);
        ring.forEach(pt => allPts.push([pt.lat, pt.lng]));
        const hull = convexHull(allPts);
        if (hull.length < 3) return;
        const before = eraserUndoBefore || JSON.parse(JSON.stringify(sel.getLatLngs()));
        sel.setLatLngs(hull.map(c => L.latLng(c[0], c[1])));
        pushUndo({ type: 'modifyFeature', layer: sel, before, after: sel.getLatLngs() });
        renderFieldLabels();
        showVertexMarkers(sel, selectedFeatures[0].layerId);
        showToast('Область расширена');
        logAction('tool', 'Область объекта расширена кистью');
        return;
    }

    // create: новый объект сразу на слой
    const hull = convexHull(allPts);
    if (hull.length < 3) {
        showToast('Проведите дольше, чтобы создать область');
        return;
    }
    const poly = L.polygon(hull, {
        color: entry.color,
        weight: displaySettings.lineWidth || 2,
        fillColor: entry.color,
        fillOpacity: getFillOpacity(false),
    });
    ensureFieldMeta(poly, layerId);
    if (editDrawMode === 'create' || createSessionActive) {
        const cropKey = document.getElementById('create-crop-select')?.value;
        if (cropKey && cropKey !== '__manage__') applyCropToMeta(poly._fieldMeta, cropKey);
    }
    bindFeatureEvents(poly, layerId);
    entry.group.addLayer(poly);
    pushUndo({ type: 'addFeature', layer: poly, layerId });
    expandedLayers.add(layerId);
    clearVertexMarkers();
    renderLayersList(document.getElementById('layer-search')?.value);
    renderLegend();
    renderFieldLabels();
    showToast('Контур применён');
    logAction('tool', `Создан/изменён контур на слое «${entry.name}»`);
}

function convexHull(points) {
    if (points.length < 3) return points;
    const sorted = points.slice().sort((a, b) => a[0] - b[0] || a[1] - b[1]);
    const cross = (o, a, b) => (a[0] - o[0]) * (b[1] - o[1]) - (a[1] - o[1]) * (b[0] - o[0]);
    const lower = [];
    for (const p of sorted) {
        while (lower.length >= 2 && cross(lower[lower.length - 2], lower[lower.length - 1], p) <= 0) lower.pop();
        lower.push(p);
    }
    const upper = [];
    for (let i = sorted.length - 1; i >= 0; i--) {
        const p = sorted[i];
        while (upper.length >= 2 && cross(upper[upper.length - 2], upper[upper.length - 1], p) <= 0) upper.pop();
        upper.push(p);
    }
    upper.pop();
    lower.pop();
    return lower.concat(upper);
}

function mergeLayerPolygons() {
    document.getElementById('more-menu')?.classList.remove('active');
    if (selectedFeatures.length >= 2) {
        const layerIds = new Set(selectedFeatures.map(s => s.layerId));
        if (layerIds.size !== 1) {
            openAppModal({
                title: 'Объединение',
                bodyHtml: '<p class="modal-text">Мультивыбор возможен только в пределах <strong>одного слоя</strong>. Сбросьте выделение и выберите полигоны одного слоя (Ctrl/⌘ или Shift + клик).</p>',
                actions: [{ label: 'Понятно', className: 'mini-btn mini-btn-red', onClick: () => closeAppModal() }],
            });
            return;
        }
        mergeSelectedPolygons(selectedFeatures);
        return;
    }
    openAppModal({
        title: 'Объединение полигонов',
        bodyHtml: '<p class="modal-text">1. Инструмент «Выделение области».<br>2. Зажмите <strong>Ctrl</strong> / <strong>⌘</strong> или <strong>Shift</strong> и кликните по 2+ полигонам одного слоя.<br>3. Снова выберите «Объединить полигоны».</p>',
        actions: [{ label: 'Понятно', className: 'mini-btn mini-btn-red', onClick: () => closeAppModal() }],
    });
}

function mergeSelectedPolygons(features) {
    const layerId = features[0].layerId;
    const entry = findLayerEntry(layerId);
    if (!entry) return;
    let allPoints = [];
    const toRemove = features.map(f => f.layer);
    toRemove.forEach(l => {
        if (!l.getLatLngs) return;
        const latlngs = l.getLatLngs();
        const ring = Array.isArray(latlngs[0]) ? latlngs[0] : latlngs;
        ring.forEach(pt => allPoints.push([pt.lat, pt.lng]));
    });
    const hull = convexHull(allPoints);
    if (hull.length < 3) return;
    const removedMeta = toRemove.map(layer => ({ layer, meta: layer._fieldMeta ? { ...layer._fieldMeta } : null }));
    toRemove.forEach(l => entry.group.removeLayer(l));
    const merged = L.polygon(hull, { color: entry.color, weight: displaySettings.lineWidth, fillColor: entry.color, fillOpacity: getFillOpacity(false) });
    ensureFieldMeta(merged, layerId);
    bindFeatureEvents(merged, layerId);
    entry.group.addLayer(merged);
    pushUndo({ type: 'mergePolygons', layerId, removed: removedMeta, merged });
    clearSelection();
    hideFieldDetail();
    selectFeature(merged, layerId, false);
    showFieldDetail(merged, layerId);
    renderLayersList(document.getElementById('layer-search')?.value);
    renderLegend();
    renderFieldLabels();
    showToast('Выделенные полигоны объединены');
    logAction('tool', 'Объединены выделенные полигоны');
}

/* --- Меню "Ещё" --- */
function toggleMoreMenu(event) {
    if (event) event.stopPropagation();
    document.getElementById('more-menu').classList.toggle('active');
}

function clearVertexMarkers() {
    if (!map) return;
    vertexMarkers.forEach(m => map.removeLayer(m));
    vertexMarkers = [];
}

function getMainCornerPoints(ring) {
    if (!ring || !ring.length) return [];
    const pts = ring.map(p => L.latLng(p.lat ?? p[0], p.lng ?? p[1]));
    let n = pts[0], s = pts[0], e = pts[0], w = pts[0];
    pts.forEach(pt => {
        if (pt.lat > n.lat) n = pt;
        if (pt.lat < s.lat) s = pt;
        if (pt.lng > e.lng) e = pt;
        if (pt.lng < w.lng) w = pt;
    });
    const uniq = [];
    for (const p of [n, e, s, w]) {
        if (!uniq.some(u => Math.abs(u.lat - p.lat) < 1e-10 && Math.abs(u.lng - p.lng) < 1e-10)) {
            uniq.push(p);
        }
    }
    return uniq;
}

function showVertexMarkers(layer, layerId) {
    if (!mapDisplay.coords) { clearVertexMarkers(); return; }
    if (!map || !layer || !layer.getLatLngs) return;
    clearVertexMarkers();
    let ring;
    try {
        ring = getPolygonRing(layer);
    } catch {
        return;
    }
    if (!Array.isArray(ring) || ring.length === 0) return;
    // normalize LatLng
    ring = ring.map(p => (p && typeof p.lat === 'number') ? p : L.latLng(p[0], p[1]));
    const c = displaySettings.coordColor || '#ff3366';
    const r = Math.max(4, displaySettings.pointSize || 5);

    let keyPoints = [];
    if (layerId === 'points' || layer._isPointObject) {
        let sumLat = 0, sumLng = 0;
        ring.forEach(pt => { sumLat += pt.lat; sumLng += pt.lng; });
        keyPoints = [L.latLng(sumLat / ring.length, sumLng / ring.length)];
    } else {
        // основные угловые точки (N/E/S/W) — стабильно для ручных и авто-полей
        keyPoints = getMainCornerPoints(ring);
        if (keyPoints.length < 2 && ring.length >= 2) {
            keyPoints = [ring[0], ring[Math.floor(ring.length / 2)]];
        }
    }

    vertexMarkers = keyPoints.map((pt) => {
        const label = `${pt.lat.toFixed(6)}, ${pt.lng.toFixed(6)}`;
        return L.circleMarker(pt, {
            radius: r, color: c, fillColor: c, fillOpacity: 1, weight: 2,
            interactive: false,
        })
            .addTo(map)
            .bindTooltip(label, {
                permanent: true, direction: 'top', offset: [0, -8], opacity: 0.95,
                className: 'coord-tooltip',
            });
    });
}

function layerHasMapFeatures(entry) {
    return entry.group.getLayers().length > 0;
}

function renderLegend() {
    const el = document.getElementById('legend');
    if (!el) return;
    const items = [];
    foldersRegistry.forEach(f => {
        const children = layersRegistry.filter(l => l.folderId === f.id && l.detected && layerHasMapFeatures(l));
        if (children.length > 0) items.push({ name: f.name, color: children[0].color });
    });
    layersRegistry.filter(l => !l.folderId && l.detected && layerHasMapFeatures(l)).forEach(l => items.push({ name: l.name, color: l.color }));
    if (items.length === 0) { el.innerHTML = ''; return; }
    el.innerHTML = items.map(l => `
        <span class="legend-item">
            <span class="legend-swatch" style="background:${l.color}"></span>
            <span class="legend-text">${l.name}</span>
        </span>
    `).join('');
}

function renderFieldLabels() {
    if (!fieldLabelsLayerGroup) return;
    fieldLabelsLayerGroup.clearLayers();
    if (!mapDisplay.labels) return;
    layersRegistry.forEach(entry => {
        if (!entry.visible) return;
        entry.group.eachLayer(layer => {
            if (!layer.getBounds) return;
            if (layer.options && layer.options.opacity === 0) return;
            const meta = ensureFieldMeta(layer, entry.id);
            const center = layer.getBounds().getCenter();
            let html = `<strong>${meta.name}</strong>`;
            if (layerSupportsCrop(entry.id)) {
                if (meta.source === 'manual' || isManualField(layer)) {
                    if (meta.confirmedCrop) html += `<span>${formatCropDisplay(meta.confirmedCrop)}</span>`;
                } else {
                    const top = getTopCrop(meta);
                    if (top.key) {
                        const cropLine = meta.confirmed
                            ? formatCropDisplay(meta.confirmedCrop)
                            : `${formatCropDisplay(top.key)} ${top.pct.toFixed(0)}%`;
                        html += `<span>${cropLine}</span>`;
                    }
                }
            }
            fieldLabelsLayerGroup.addLayer(L.marker(center, {
                icon: L.divIcon({ className: 'field-map-label', html, iconSize: null }),
                interactive: false,
            }));
        });
    });
}

function populateDrawLayerSelect() {
    const sel = document.getElementById('draw-layer-select');
    if (!sel) return;
    const options = getDrawLayerOptions();
    const prev = sel.value;
    sel.innerHTML = options
        .map(l => `<option value="${l.id}">${l.name}</option>`)
        .join('') + '<option value="__new__">+ Новый слой…</option>';
    const preferred = (prev && options.some(l => l.id === prev))
        ? prev
        : (activeLayerId && options.some(l => l.id === activeLayerId))
            ? activeLayerId
            : (options[0]?.id || '');
    if (preferred) sel.value = preferred;
}

function populateCreateCropSelect() {
    const sel = document.getElementById('create-crop-select');
    if (!sel) return;
    const prev = sel.value;
    const options = getAllCropOptions();
    sel.innerHTML = '<option value="">— Выберите культуру —</option>' +
        options.map(o => `<option value="${o.key}">${formatCropOptionLabel(o.key, o.label, o.custom)}</option>`).join('') +
        '<option value="__manage__">⚙ Свои культуры…</option>';
    if (prev && prev !== '__manage__' && [...sel.options].some(o => o.value === prev)) sel.value = prev;
}

function openManageCustomCropsModal() {
    openAppModal({
        title: 'Свои культуры',
        bodyHtml: buildCropSelectHtml(''),
        actions: [
            { label: 'Готово', className: 'mini-btn mini-btn-red', onClick: () => {
                closeAppModal();
                populateCreateCropSelect();
            }},
        ],
    });
    setTimeout(wireCropModalExtras, 0);
}

function onDrawLayerSelect(val) {
    if (val === '__new__') {
        const name = prompt('Название нового слоя', 'Новый слой');
        if (!name || !name.trim()) { populateDrawLayerSelect(); return; }
        const id = 'layer_' + Date.now();
        const color = document.getElementById('new-layer-color')?.value || '#3388ff';
        const group = L.featureGroup().addTo(map);
        layersRegistry.push({ id, name: name.trim(), color, group, visible: true, folderId: null, detected: true });
        activeLayerId = id;
        saveFoldersState();
        renderLayersList(document.getElementById('layer-search')?.value);
        populateDrawLayerSelect();
        onDrawLayerSelect(id);
        showToast(`Слой «${name.trim()}» создан`);
        return;
    }

    if (createSessionActive) {
        draftCreateLayerId = val;
        activeLayerId = val;
        const entry = findLayerEntry(val);
        if (entry && draftCreatePolygon) {
            draftCreatePolygon.setStyle({ color: entry.color, fillColor: entry.color });
        }
        updateCreateCropBlockVisibility();
        selectLayerAsActive(val);
        return;
    }

    if (selectedFeatures.length === 1 && selectedFeatures[0].layerId !== val) {
        moveFeatureToLayer(selectedFeatures[0].layer, selectedFeatures[0].layerId, val);
        populateDrawLayerSelect();
        const sel = document.getElementById('draw-layer-select');
        if (sel) sel.value = val;
        return;
    }

    activeLayerId = val;
    selectLayerAsActive(val);
    updateCreateCropBlockVisibility();
}

function setMapDisplayOption(key, value) {
    mapDisplay[key] = value;
    const labelsEl = document.getElementById('opt-field-labels');
    const coordsEl = document.getElementById('opt-field-coords');
    if (labelsEl) labelsEl.checked = mapDisplay.labels;
    if (coordsEl) coordsEl.checked = mapDisplay.coords;
    renderFieldLabels();
    if (selectedFeatures.length === 1) showVertexMarkers(selectedFeatures[0].layer, selectedFeatures[0].layerId);
    else clearVertexMarkers();
    const label = key === 'labels' ? 'подписи объектов' : 'координаты вершин';
    logAction('map', value ? `Включены ${label} на карте` : `Скрыты ${label} на карте`);
}

let sidebarCollapsed = false;
function toggleSidebarPanel(forceExpand) {
    const wrap = document.getElementById('sidebar-panel-wrap');
    const panel = document.getElementById('sidebar-panel');
    const toggle = document.getElementById('sidebar-edge-toggle');
    if (!panel || !wrap) return;
    sidebarCollapsed = forceExpand === true ? false : !sidebarCollapsed;
    panel.classList.toggle('collapsed', sidebarCollapsed);
    wrap.classList.toggle('collapsed', sidebarCollapsed);
    if (toggle) {
        toggle.title = sidebarCollapsed ? 'Развернуть панель' : 'Свернуть панель';
        toggle.setAttribute('aria-expanded', sidebarCollapsed ? 'false' : 'true');
    }
    setTimeout(() => { if (map) map.invalidateSize(); }, 220);
}

function toggleFieldDetailPanel() {
    fieldDetailCollapsed = !fieldDetailCollapsed;
    const body = document.getElementById('field-detail-body');
    const icon = document.getElementById('field-detail-icon');
    if (body) body.style.display = fieldDetailCollapsed ? 'none' : 'block';
    if (icon) icon.textContent = fieldDetailCollapsed ? '▸' : '▾';
}

function toggleLayerGroup(id) {
    const el = document.getElementById(id);
    const icon = document.getElementById(id + '-icon');
    if (!el) return;
    if (collapsedGroups.has(id)) {
        collapsedGroups.delete(id);
        el.style.display = 'block';
        if (icon) icon.textContent = '▾';
    } else {
        collapsedGroups.add(id);
        el.style.display = 'none';
        if (icon) icon.textContent = '▸';
    }
}

function initNetworkStatus() {
    const refresh = () => {
        updateDzzNetworkStatus();
        updateMlNetworkStatus();
    };
    refresh();
    window.addEventListener('online', refresh);
    window.addEventListener('offline', refresh);
    document.addEventListener('visibilitychange', () => {
        if (document.visibilityState === 'visible') refresh();
    });
    setInterval(() => {
        if (navigator.onLine) updateMlNetworkStatus();
    }, 30000);
}

function setDzzHeaderStatus(available, title) {
    const el = document.getElementById('status-dzz');
    if (!el) return;
    el.textContent = available ? 'dzz.by · Онлайн' : 'dzz.by · Сервис недоступен';
    el.className = available ? 'status-online' : 'status-offline';
    el.title = title || '';
}

function scheduleDzzHealth() {
    if (dzzHealthTimer) clearTimeout(dzzHealthTimer);
    const ms = (!navigator.onLine || dzzHealthAvailable) ? 30000 : 5000;
    dzzHealthTimer = setTimeout(() => {
        if (navigator.onLine) updateDzzNetworkStatus();
        else scheduleDzzHealth();
    }, ms);
}

async function updateDzzNetworkStatus() {
    const el = document.getElementById('status-dzz');
    if (!el) {
        scheduleDzzHealth();
        return;
    }
    if (!navigator.onLine) {
        dzzHealthAvailable = false;
        setDzzHeaderStatus(false, 'Нет сетевого соединения');
        scheduleDzzHealth();
        return;
    }
    if (dzzStatusInflight) return;
    dzzStatusInflight = true;
    try {
        const res = await fetch('/api/dzz/health', { credentials: 'include' });
        const data = await res.json().catch(() => ({}));
        const available = Boolean(data.available);
        const connected = Boolean(data.connected);
        const recovered = !dzzHealthAvailable && available;
        dzzHealthAvailable = available;
        setDzzHeaderStatus(available, data.message || '');
        const settings = document.getElementById('dzz-conn-status');
        const probing = settings && settings.textContent === 'Проверка подключения…';

        if (connected && !dzzSession.connected) {
            await restoreDzzSession({ skipHealth: true });
            if (dzzSession.connected && map && (displaySettings.basemap === 'dzz' || currentBasemap === 'dzz')) {
                setBasemap('dzz', true);
                if (!probing) setDzzConnStatus('Сессия dzz.by восстановлена после перезапуска сервера');
                showToast('Сессия dzz.by восстановлена');
            }
        } else if (dzzSession.connected && available && !connected) {
            await restoreDzzSession({ skipHealth: true });
            if (!dzzSession.connected && !probing) {
                setDzzConnStatus('Сессия dzz.by сброшена. Нажмите «Проверить подключение».');
            }
        } else if (!probing && dzzSession.connected && !available) {
            setDzzConnStatus('Сервис dzz.by недоступен. Повторная проверка каждые 5 с.');
        }

        if (recovered && dzzSession.connected && tileDzz && map?.hasLayer(tileDzz)) {
            tileDzz.redraw();
            scheduleDzzPrefetch();
            if (!probing) {
                setDzzConnStatus('Связь с dzz.by восстановлена');
                showToast('Связь с dzz.by восстановлена');
            }
        }
    } catch {
        dzzHealthAvailable = false;
        setDzzHeaderStatus(false, 'Не удалось проверить dzz.by');
    } finally {
        dzzStatusInflight = false;
        scheduleDzzHealth();
    }
}

async function updateMlNetworkStatus() {
    const el = document.getElementById('status-ml');
    if (!el) return;
    if (!navigator.onLine) {
        el.textContent = 'ML оффлайн';
        el.className = 'status-ml status-offline';
        el.title = 'Нет сетевого соединения';
        return;
    }
    try {
        const health = await fetchMlHealth();
        if (health.model_loaded) {
            const models = (health.available_models || []).join(', ') || 'ok';
            el.textContent = `ML · ${models}`;
            el.className = 'status-ml status-online';
            el.title = '';
        } else {
            el.textContent = 'ML · нет весов';
            el.className = 'status-ml status-offline';
            el.title = health.hint || 'Положите веса на ML-сервер';
        }
    } catch {
        el.textContent = 'ML недоступен';
        el.className = 'status-ml';
        el.title = 'Запустите ML backend на :8000 или docker compose';
    }
}

function initSidebarResize() {
    const panel = document.getElementById('sidebar-panel');
    const resizer = document.getElementById('sidebar-resizer');
    if (!panel || !resizer) return;
    const saved = localStorage.getItem('ttz_sidebar_width');
    if (saved) panel.style.width = saved + 'px';
    let startX = 0;
    let startW = 0;
    const onMove = (e) => {
        const w = Math.min(520, Math.max(300, startW + (e.clientX - startX)));
        panel.style.width = w + 'px';
    };
    const onUp = () => {
        document.removeEventListener('mousemove', onMove);
        document.removeEventListener('mouseup', onUp);
        localStorage.setItem('ttz_sidebar_width', String(panel.offsetWidth));
        if (map) map.invalidateSize();
    };
    resizer.addEventListener('mousedown', (e) => {
        e.preventDefault();
        startX = e.clientX;
        startW = panel.offsetWidth;
        document.addEventListener('mousemove', onMove);
        document.addEventListener('mouseup', onUp);
    });
}

function updateScaleDisplay() {
    const el = document.getElementById('scale-display');
    if (!el || !map) return;
    const midY = map.getSize().y / 2;
    const ll1 = map.containerPointToLatLng(L.point(0, midY));
    const ll2 = map.containerPointToLatLng(L.point(256, midY));
    const mpp = map.distance(ll1, ll2) / 256;
    const dpi = 96;
    const inchesPerMeter = 39.37;
    const denom = Math.max(1, Math.round(mpp * dpi * inchesPerMeter));
    const pretty = denom >= 10000 ? denom.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ' ') : denom.toString();
    el.innerText = `1:${pretty}`;
}

/* =========================================================
   ЭКСПОРТ: GeoJSON / KML / SHP (полностью в браузере)
   ========================================================= */
function collectAllFeaturesAsGeoJSON() {
    const features = [];
    layersRegistry.forEach(entry => {
        entry.group.eachLayer(layer => {
            const gj = layer.toGeoJSON();
            const meta = layer._fieldMeta || {};
            gj.properties = {
                layer: entry.name,
                layerId: entry.id,
                color: entry.color,
                folderId: entry.folderId || null,
                name: meta.name || null,
                objectNumber: meta.objectNumber ?? null,
                crops: layerSupportsCrop(entry.id) ? (meta.crops || []) : [],
                confirmedCrop: layerSupportsCrop(entry.id) ? (meta.confirmedCrop || null) : null,
                confirmed: !!meta.confirmed,
                source: meta.source || 'detected',
                objectFolderId: meta.objectFolderId || null,
                isPointObject: !!(layer._isPointObject || entry.id === 'points'),
            };
            features.push(gj);
        });
    });
    return {
        type: 'FeatureCollection',
        features,
        folders: foldersRegistry.map(f => ({
            id: f.id, name: f.name, visible: f.visible !== false, collapsed: !!f.collapsed,
        })),
    };
}

function downloadBlob(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = filename;
    document.body.appendChild(a); a.click(); a.remove();
    URL.revokeObjectURL(url);
}

/* Минимальный конвертер GeoJSON -> KML (Point / LineString / Polygon) */
function geojsonToKML(geojson) {
    const coordsToKML = (coords) => coords.map(c => `${c[0]},${c[1]},0`).join(' ');

    const geometryToKML = (geom) => {
        if (geom.type === 'Point') {
            return `<Point><coordinates>${coordsToKML([geom.coordinates])}</coordinates></Point>`;
        }
        if (geom.type === 'LineString') {
            return `<LineString><coordinates>${coordsToKML(geom.coordinates)}</coordinates></LineString>`;
        }
        if (geom.type === 'Polygon') {
            const outer = geom.coordinates[0];
            return `<Polygon><outerBoundaryIs><LinearRing><coordinates>${coordsToKML(outer)}</coordinates></LinearRing></outerBoundaryIs></Polygon>`;
        }
        return '';
    };

    const placemarks = geojson.features.map(f => `
        <Placemark>
            <name>${(f.properties && f.properties.layer) || 'Объект'}</name>
            ${geometryToKML(f.geometry)}
        </Placemark>`).join('');

    return `<?xml version="1.0" encoding="UTF-8"?>
<kml xmlns="http://www.opengis.net/kml/2.2"><Document>${placemarks}</Document></kml>`;
}

function geojsonToSVG(geojson) {
    let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
    const rings = [];
    geojson.features.forEach(f => {
        if (f.geometry?.type !== 'Polygon') return;
        const outer = f.geometry.coordinates[0].map(c => ({ x: c[0], y: c[1] }));
        outer.forEach(p => {
            minX = Math.min(minX, p.x); maxX = Math.max(maxX, p.x);
            minY = Math.min(minY, p.y); maxY = Math.max(maxY, p.y);
        });
        rings.push({ pts: outer, color: '#e14059' });
    });
    if (rings.length === 0) return '<svg xmlns="http://www.w3.org/2000/svg"></svg>';
    const pad = 0.001;
    const w = maxX - minX + pad * 2;
    const h = maxY - minY + pad * 2;
    const paths = rings.map(r => {
        const d = r.pts.map((p, i) => {
            const x = ((p.x - minX + pad) / w) * 1000;
            const y = ((maxY - p.y + pad) / h) * 1000;
            return `${i === 0 ? 'M' : 'L'}${x.toFixed(2)},${y.toFixed(2)}`;
        }).join(' ') + ' Z';
        return `<path d="${d}" fill="${r.color}" fill-opacity="0.35" stroke="${r.color}" stroke-width="2"/>`;
    }).join('');
    return `<?xml version="1.0" encoding="UTF-8"?><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1000 1000">${paths}</svg>`;
}

function exportLayers() {
    const format = document.getElementById('export-format').value;
    const status = document.getElementById('export-status');
    const geojson = collectAllFeaturesAsGeoJSON();

    if (geojson.features.length === 0) {
        status.innerText = 'Нет объектов для экспорта.';
        return;
    }

    if (format === 'geojson') {
        downloadBlob(new Blob([JSON.stringify(geojson, null, 2)], { type: 'application/geo+json' }), 'export.geojson');
    } else if (format === 'kml') {
        downloadBlob(new Blob([geojsonToKML(geojson)], { type: 'application/vnd.google-earth.kml+xml' }), 'export.kml');
    } else if (format === 'shp') {
        if (!window.shpwrite) { status.innerText = 'Библиотека экспорта SHP не загрузилась (нет интернета).'; return; }
        try {
            const blob = window.shpwrite.zip(geojson);
            Promise.resolve(blob).then(b => downloadBlob(b instanceof Blob ? b : new Blob([b]), 'export_shp.zip'));
        } catch (err) {
            status.innerText = 'Ошибка экспорта SHP: ' + err;
            return;
        }
    } else if (format === 'svg') {
        downloadBlob(new Blob([geojsonToSVG(geojson)], { type: 'image/svg+xml' }), 'export.svg');
    }

    status.innerText = `Экспортировано ${geojson.features.length} объект(ов) в формате ${format.toUpperCase()}.`;
    incStat('exports');
    logAction('export', `Экспорт ${format.toUpperCase()}: ${geojson.features.length} объект(ов)`, { exportFormat: format.toUpperCase() });
}

/* =========================================================
   МОДАЛЬНЫЕ ОК (единый стиль с выбором папки)
   ========================================================= */
function openAppModal({ title, bodyHtml, actions = [], focusId }) {
    const root = document.getElementById('app-modal');
    const titleEl = document.getElementById('app-modal-title');
    const bodyEl = document.getElementById('app-modal-body');
    const actionsEl = document.getElementById('app-modal-actions');
    if (!root || !bodyEl || !actionsEl) {
        console.warn('app-modal missing');
        return;
    }
    if (titleEl) titleEl.textContent = title || '';
    bodyEl.innerHTML = bodyHtml || '';
    actionsEl.innerHTML = '';
    _modalActionHandlers = [];
    actions.forEach((a, i) => {
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = a.className || 'mini-btn';
        btn.textContent = a.label;
        btn.addEventListener('click', () => a.onClick && a.onClick());
        actionsEl.appendChild(btn);
        _modalActionHandlers.push(btn);
    });
    root.style.display = 'flex';
    if (focusId) setTimeout(() => document.getElementById(focusId)?.focus(), 30);
}

function closeAppModal() {
    const root = document.getElementById('app-modal');
    if (root) root.style.display = 'none';
    const bodyEl = document.getElementById('app-modal-body');
    const actionsEl = document.getElementById('app-modal-actions');
    if (bodyEl) bodyEl.innerHTML = '';
    if (actionsEl) actionsEl.innerHTML = '';
    _modalActionHandlers = [];
}

/* =========================================================
   ВСПОМОГАТЕЛЬНОЕ
   ========================================================= */
let toastTimer = null;
function showToast(text) {
    const el = document.getElementById('toast');
    if (!el) return;
    el.innerText = text;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { el.innerText = ''; }, 2500);
}

/* =========================================================
   СТАРТ
   ========================================================= */
document.addEventListener('DOMContentLoaded', async () => {
    initPasswordToggles();

    const useApi = await ensureAuthBackend();
    if (useApi) {
        try {
            const data = await apiFetch('/api/me');
            currentUser = data.user;
            authMode = 'server';
            enterApp();
        } catch {
            const localUser = localRestoreSession();
            if (localUser) {
                currentUser = localUser;
                enterApp();
            }
        }
    } else {
        const localUser = localRestoreSession();
        if (localUser) {
            currentUser = localUser;
            enterApp();
        }
    }

    const cardAvatar = document.getElementById('card-avatar');
    if (cardAvatar) {
        cardAvatar.title = 'Нажмите: загрузить или удалить аватарку';
        cardAvatar.addEventListener('click', onAvatarClick);
    }
    const sidebarAvatar = document.getElementById('sidebar-avatar');
    if (sidebarAvatar) {
        sidebarAvatar.title = 'Аккаунт';
        sidebarAvatar.style.cursor = 'pointer';
    }
});
