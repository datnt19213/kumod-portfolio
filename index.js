/**
 * Template Engine & Portfolio Logic
 * Full support for: {{#each}}, {{#if}}, {{variable}}, {{#array}}
 */

const IS_LOCAL = location.hostname === "localhost" || location.hostname === "127.0.0.1";
const BASE_PATH = IS_LOCAL ? "./" : "/kumod-portfolio/";
const TEMPLATE_URL = BASE_PATH + "list.template.html";
const DETAIL_TEMPLATE_URL = BASE_PATH + "detail.template.html";
const ADMIN_TEMPLATE_URL = BASE_PATH + "admin.template.html";
const HEADER_TEMPLATE_URL = BASE_PATH + "header.template.html";
const FOOTER_TEMPLATE_URL = BASE_PATH + "footer.template.html";
const NOTFOUND_URL = BASE_PATH + "notfound.html";

const DATA_URL = "https://gist.githubusercontent.com/datnt19213/17726f1fb5188f180f20b3f5e862bb98/raw/portfolio-mydev.json";

/* =========================
   FETCH & UTILS
========================= */
async function fetchText(url) {
    try {
        const res = await fetch(url);
        if (!res.ok) throw new Error("Fetch failed: " + url);
        return await res.text();
    } catch (err) { return ""; }
}

async function fetchJSON(url) {
    try {
        const res = await fetch(url);
        if (!res.ok) throw new Error("Fetch failed");
        return await res.json();
    } catch (err) { return {}; }
}

function getQueryParam(name) {
    return new URLSearchParams(location.search).get(name);
}

function getSlugFromPath() {
    const match = location.pathname.match(/project\/([^\/]+)/);
    return match ? match[1] : null;
}

/* =========================
   TEMPLATE ENGINE
========================= */
function renderArrays(template, item) {
    return template.replace(/{{#array (.*?)}}([\s\S]*?){{\/array}}/g, (_, key, content) => {
        const arr = item[key.trim()];
        if (!Array.isArray(arr)) return "";
        return arr.map(v => content.replace(/{{value}}/g, v)).join("");
    });
}

function renderIf(template, item) {
    return template.replace(/{{#if (.*?)}}([\s\S]*?){{\/if}}/g, (_, key, content) => {
        key = key.trim();
        const isNot = key.startsWith("!");
        const actualKey = isNot ? key.slice(1).trim() : key;
        const value = item[actualKey];
        return (isNot ? !value : !!value) ? content : "";
    });
}

function renderVariables(template, item) {
    return template.replace(/{{(.*?)}}/g, (_, key) => {
        key = key.trim();
        if (key.startsWith("#") || key.startsWith("/")) return "";
        return item[key] ?? "";
    });
}

function renderEach(template, data) {
    return template.replace(/{{#each (.*?)}}([\s\S]*?){{\/each}}/g, (_, arrayName, content) => {
        const arr = data[arrayName.trim()];
        if (!Array.isArray(arr)) return "";
        return arr.map(item => {
            let block = content;
            block = renderArrays(block, item);
            block = renderIf(block, item);
            block = renderVariables(block, item);
            return block;
        }).join("");
    });
}

function render(template, data) {
    let res = renderEach(template, data);
    res = renderArrays(res, data);
    res = renderIf(res, data);
    res = renderVariables(res, data);
    return res;
}

/* =========================
   CRYPTO (FanHash)
========================= */
function _sha256Internal(ascii) {
    const rightRotate = (v, a) => (v >>> a) | (v << (32 - a));
    const mathPow = Math.pow;
    const maxWord = mathPow(2, 32);
    let i, j, result = '';
    const words = [];
    const asciiBitLength = ascii.length * 8;
    let hash = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    const k = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc600bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];
    let str = ascii + '\x80';
    while (str.length % 64 - 56) str += '\x00';
    for (i = 0; i < str.length; i++) words[i >> 2] |= str.charCodeAt(i) << ((3 - i) % 4) * 8;
    words[words.length] = ((asciiBitLength / maxWord) | 0);
    words[words.length] = (asciiBitLength | 0);
    for (j = 0; j < words.length;) {
        const w = words.slice(j, j += 16);
        const oldHash = [...hash];
        for (i = 0; i < 64; i++) {
            if (i >= 16) {
                const s0 = rightRotate(w[i - 15], 7) ^ rightRotate(w[i - 15], 18) ^ (w[i - 15] >>> 3);
                const s1 = rightRotate(w[i - 2], 17) ^ rightRotate(w[i - 2], 19) ^ (w[i - 2] >>> 10);
                w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
            }
            const t1 = (hash[7] + (rightRotate(hash[4], 6) ^ rightRotate(hash[4], 11) ^ rightRotate(hash[4], 25)) + ((hash[4] & hash[5]) ^ (~hash[4] & hash[6])) + k[i] + (w[i] | 0)) | 0;
            const t2 = ((rightRotate(hash[0], 2) ^ rightRotate(hash[0], 13) ^ rightRotate(hash[0], 22)) + ((hash[0] & hash[1]) ^ (hash[0] & hash[2]) ^ (hash[1] & hash[2]))) | 0;
            hash = [(t1 + t2) | 0, ...hash.slice(0, 7)];
            hash[4] = (hash[4] + t1) | 0;
        }
        for (i = 0; i < 8; i++) hash[i] = (hash[i] + oldHash[i]) | 0;
    }
    for (i = 0; i < 8; i++) {
        for (j = 3; j + 1; j--) {
            const b = (hash[i] >> (j * 8)) & 255;
            result += (b < 16 ? '0' : '') + b.toString(16);
        }
    }
    return result;
}

class FanHashEngine {
    static encode(text, password) {
        const data = new TextEncoder().encode(text);
        const passHash = _sha256Internal(password);
        const passBytes = new Uint8Array(passHash.match(/.{1,2}/g).map(b => parseInt(b, 16)));
        const n = 61 + (password.length % 11);
        for (let k = 0; k < n; k++) {
            const offset = k % data.length;
            for (let i = offset; i < data.length - 1; i += 2) {
                [data[i], data[i + 1]] = [data[i + 1], data[i]];
                data[i] ^= (passBytes[i % passBytes.length] + k) % 256;
            }
        }
        return Array.from(data).map(b => b.toString(16).padStart(2, '0')).join('');
    }
    static decode(hex, password) {
        try {
            const data = new Uint8Array(hex.match(/.{1,2}/g).map(b => parseInt(b, 16)));
            const passHash = _sha256Internal(password);
            const passBytes = new Uint8Array(passHash.match(/.{1,2}/g).map(b => parseInt(b, 16)));
            const n = 61 + (password.length % 11);
            for (let k = n - 1; k >= 0; k--) {
                const offset = k % data.length;
                for (let i = offset; i < data.length - 1; i += 2) {
                    data[i] ^= (passBytes[i % passBytes.length] + k) % 256;
                    [data[i], data[i + 1]] = [data[i + 1], data[i]];
                }
            }
            return new TextDecoder().decode(data);
        } catch (e) { return null; }
    }
}

/* =========================
   CORE STATE & GIST
========================= */
let projects = [];
let session = { isLoggedIn: false, token: "", password: "", hashedToken: "" };

async function updateGist(token, content) {
    const gistIdMatch = DATA_URL.match(/\/([a-f0-9]+)\/raw\//);
    const gistId = gistIdMatch[1];
    const getRes = await fetch(`https://api.github.com/gists/${gistId}`, { headers: { 'Authorization': `token ${token}` } });
    const gistData = await getRes.json();
    const filename = Object.keys(gistData.files)[0];
    const updateRes = await fetch(`https://api.github.com/gists/${gistId}`, {
        method: 'PATCH',
        headers: { 'Authorization': `token ${token}`, 'Content-Type': 'application/json', 'Accept': 'application/vnd.github.v3+json' },
        body: JSON.stringify({ files: { [filename]: { content } } })
    });
    if (!updateRes.ok) throw new Error("Update failed");
    return true;
}

/* =========================
   RENDER LOGIC
========================= */
async function init() {
    // Header & Footer
    const [hT, fT] = await Promise.all([fetchText(HEADER_TEMPLATE_URL), fetchText(FOOTER_TEMPLATE_URL)]);
    const headerEl = document.getElementById("header");
    const footerEl = document.getElementById("footer");
    if (headerEl) headerEl.innerHTML = render(hT, { BASE_PATH });
    if (footerEl) footerEl.innerHTML = render(fT, { BASE_PATH });

    const app = document.getElementById("app");
    const data = await fetchJSON(DATA_URL + "?t=" + Date.now());
    projects = Array.isArray(data) ? data : (data.projects || []);

    // Sort newest first
    projects.sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0));

    const page = getQueryParam("page");
    const slug = getSlugFromPath() || getQueryParam("slug");

    if (page === "admin") {
        await initAdmin();
    } else if (slug) {
        const p = projects.find(x => x.slug === slug);
        if (!p) app.innerHTML = (await fetchText(NOTFOUND_URL)) || "Project not found";
        else app.innerHTML = render(await fetchText(DETAIL_TEMPLATE_URL), p);
    } else {
        const template = await fetchText(TEMPLATE_URL);
        app.innerHTML = render(template, { projects, featuredProjects: projects.filter(p => p.featured), projectCount: projects.length });
    }
}

async function initAdmin() {
    session.password = localStorage.getItem("admin_pass") || "";
    session.hashedToken = localStorage.getItem("admin_token") || "";

    if (session.password && session.hashedToken) {
        const tk = FanHashEngine.decode(session.hashedToken, session.password);
        if (tk?.startsWith("ghp_")) {
            session.token = tk;
            session.isLoggedIn = true;
        }
    }
    renderAdminPage();
}

async function renderAdminPage() {
    const app = document.getElementById("app");
    const template = await fetchText(ADMIN_TEMPLATE_URL);
    app.innerHTML = render(template, session);

    attachAdminEvents();
    if (session.isLoggedIn) renderList();
}

function renderList() {
    const listEl = document.getElementById("projectAdminList");
    if (!listEl) return;
    if (projects.length === 0) {
        listEl.innerHTML = `<div class="p-8 text-center text-slate-500 uppercase tracking-widest text-[10px]">No projects found</div>`;
        return;
    }
    listEl.innerHTML = projects.map((p, idx) => `
        <div class="group flex justify-between items-center p-4! bg-white/[0.02] rounded-xl border border-white/5 transition-all duration-300 hover:bg-white/[0.04] hover:border-white/10 gap-4">
            <div class="flex-1 min-w-0">
                <div class="text-[11px] font-bold text-white uppercase tracking-wider truncate">${p.title}</div>
                <div class="text-[9px] text-slate-600 uppercase tracking-widest mt-0.5! truncate">${p.slug}</div>
            </div>
            <div class="flex gap-2">
                <button class="w-8 h-8 flex items-center justify-center bg-white/5 rounded-lg border border-white/5 text-slate-600 hover:bg-white hover:text-black transition-all edit" data-idx="${idx}">✎</button>
                <button class="w-8 h-8 flex items-center justify-center bg-white/5 rounded-lg border border-white/5 text-slate-600 hover:bg-red-500/20 hover:text-red-400 transition-all delete" data-idx="${idx}">🗑</button>
            </div>
        </div>
    `).join("");

    listEl.querySelectorAll(".edit").forEach(b => b.onclick = () => openEditor(b.dataset.idx));
    listEl.querySelectorAll(".delete").forEach(b => b.onclick = () => {
        if (confirm("Delete?")) { projects.splice(b.dataset.idx, 1); saveAndRefresh(); }
    });
}

function attachAdminEvents() {
    const showStatus = (msg, isErr) => {
        const el = document.getElementById("statusMessage");
        if (!el) return;
        el.innerText = msg;
        el.style.display = "block";
        el.className = `fixed bottom-10! left-1/2 -translate-x-1/2 z-[2000] py-3! px-8! rounded-full border text-[10px] font-bold uppercase tracking-widest ${isErr ? "bg-black border-red-500 text-red-500" : "bg-black border-white/20 text-white"}`;
        setTimeout(() => el.style.display = "none", 3000);
    };

    // Form Login
    const loginForm = document.getElementById("loginForm");
    if (loginForm) {
        loginForm.onsubmit = (e) => {
            e.preventDefault();
            const tk = loginForm.githubToken.value;
            const pw = loginForm.password.value;
            if (tk.startsWith("ghp_")) {
                session.token = tk; session.password = pw; session.isLoggedIn = true;
                session.hashedToken = FanHashEngine.encode(tk, pw);
                localStorage.setItem("admin_pass", pw);
                localStorage.setItem("admin_token", session.hashedToken);
                renderAdminPage();
            }
        };
    }

    // Buttons
    const logoutBtn = document.getElementById("logoutBtn");
    if (logoutBtn) logoutBtn.onclick = () => { session.isLoggedIn = false; renderAdminPage(); };

    const clearBtn = document.getElementById("clearSessionBtn");
    if (clearBtn) clearBtn.onclick = () => { localStorage.clear(); location.reload(); };

    const addNewBtn = document.getElementById("addNewBtn");
    if (addNewBtn) addNewBtn.onclick = () => openEditor();

    const closeBtn = document.getElementById("closeEditorBtn");
    if (closeBtn) closeBtn.onclick = () => document.getElementById("editorCard").style.display = "none";

    // Project Form (SAVE) - FULL FIELDS
    const projectForm = document.getElementById("projectForm");
    if (projectForm) {
        projectForm.onsubmit = async (e) => {
            e.preventDefault();
            const idx = document.getElementById("editId").value;
            const comma = (s) => s.split(",").map(x => x.trim()).filter(Boolean);
            const nl = (s) => s.split("\n").map(x => x.trim()).filter(Boolean);

            const p = {
                title: document.getElementById("pTitle").value,
                slug: document.getElementById("pSlug").value,
                thumbnail: document.getElementById("pThumbnail").value,
                category: document.getElementById("pCategory").value,
                status: document.getElementById("pStatus").value,
                featured: document.getElementById("pFeatured").checked ? true : false,
                startDate: document.getElementById("pStartDate").value,
                endDate: document.getElementById("pEndDate").value,
                liveUrl: document.getElementById("pLiveUrl").value,
                repoUrl: document.getElementById("pRepoUrl").value,
                shortDescription: document.getElementById("pShortDesc").value,
                description: document.getElementById("pDesc").value,
                video: document.getElementById("pVideo").value,
                metaTitle: document.getElementById("pMetaTitle").value,
                metaDescription: document.getElementById("pMetaDescription").value,
                ogImage: document.getElementById("pOgImage").value,
                technologies: comma(document.getElementById("pTechnologies").value),
                frameworks: comma(document.getElementById("pFrameworks").value),
                tools: comma(document.getElementById("pTools").value),
                tags: comma(document.getElementById("pTags").value),
                images: nl(document.getElementById("pImages").value),
                updatedAt: new Date().toISOString().split("T")[0]
            };

            if (idx !== "") projects[idx] = { ...projects[idx], ...p };
            else { p.createdAt = p.updatedAt; p.id = Date.now().toString(); projects.unshift(p); }

            document.getElementById("editorCard").style.display = "none";
            try {
                await updateGist(session.token, JSON.stringify(projects, null, 2));
                showStatus("Saved successfully!");
                renderList();
            } catch (err) { showStatus("Error: " + err.message, true); }
        };
    }
}

function openEditor(idx = null) {
    const editor = document.getElementById("editorCard");
    const form = document.getElementById("projectForm");
    editor.style.display = "block";
    form.reset();
    document.getElementById("editId").value = "";
    document.getElementById("editorTitle").innerText = idx !== null ? "Edit Project" : "Add New Project";

    if (idx !== null) {
        const p = projects[idx];
        document.getElementById("editId").value = idx;
        document.getElementById("pTitle").value = p.title || "";
        document.getElementById("pSlug").value = p.slug || "";
        document.getElementById("pThumbnail").value = p.thumbnail || "";
        document.getElementById("pCategory").value = p.category || "";
        document.getElementById("pStatus").value = p.status || "completed";
        document.getElementById("pFeatured").checked = !!p.featured;
        document.getElementById("pStartDate").value = p.startDate || "";
        document.getElementById("pEndDate").value = p.endDate || "";
        document.getElementById("pLiveUrl").value = p.liveUrl || "";
        document.getElementById("pRepoUrl").value = p.repoUrl || "";
        document.getElementById("pShortDesc").value = p.shortDescription || "";
        document.getElementById("pDesc").value = p.description || "";
        document.getElementById("pVideo").value = p.video || "";
        document.getElementById("pMetaTitle").value = p.metaTitle || "";
        document.getElementById("pMetaDescription").value = p.metaDescription || "";
        document.getElementById("pOgImage").value = p.ogImage || "";
        document.getElementById("pTechnologies").value = (p.technologies || []).join(", ");
        document.getElementById("pFrameworks").value = (p.frameworks || []).join(", ");
        document.getElementById("pTools").value = (p.tools || []).join(", ");
        document.getElementById("pTags").value = (p.tags || []).join(", ");
        document.getElementById("pImages").value = (p.images || []).join("\n");
    }
}

async function saveAndRefresh() {
    try {
        await updateGist(session.token, JSON.stringify(projects, null, 2));
        renderList();
    } catch (err) { alert("Failed to save"); }
}

init();


// event listener interaction

// hamburger menu

function toggleMenu() {
    document.getElementById("nav-menu").style.display = "flex";
    document.getElementById("nav-menu-2").style.display = "flex";
    document.getElementById("hamburger-menu").style.display = "none";
    document.getElementById("close-menu").style.display = "block";
    console.log("hamburger-menu clicked");
}

function closeMenu() {
    document.getElementById("nav-menu").style.display = "none";
    document.getElementById("nav-menu-2").style.display = "none";
    document.getElementById("hamburger-menu").style.display = "block";
    document.getElementById("close-menu").style.display = "none";
    console.log("close-menu clicked");
}