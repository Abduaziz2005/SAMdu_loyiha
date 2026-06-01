// ============================================================
// S_TATU PLATFORM — main.js  v2.0
// Xavfsizlik + Admin funksiyalari
// ============================================================

// ── UTILS ────────────────────────────────────────────────────
const $ = id => document.getElementById(id);

// ── CSRF HELPER ───────────────────────────────────────────────
function getCsrf() {
  const el = document.querySelector('[name="_csrf_token"]');
  return el ? el.value : '';
}

// ── NAVBAR ────────────────────────────────────────────────────
const navbar    = $('navbar');
const mobToggle = $('mobToggle');
const navLinks  = $('navLinks');

if (navbar) {
  window.addEventListener('scroll', () => {
    navbar.style.borderBottomColor = window.scrollY > 10
      ? 'rgba(255,255,255,0.08)' : '';
  });
}
if (mobToggle && navLinks) {
  mobToggle.addEventListener('click', () => {
    navLinks.classList.toggle('open');
    mobToggle.classList.toggle('active');
  });
  document.addEventListener('click', e => {
    if (!navbar.contains(e.target)) {
      navLinks.classList.remove('open');
      mobToggle.classList.remove('active');
    }
  });
}

// ── FLASH AUTO-CLOSE ──────────────────────────────────────────
setTimeout(() => {
  document.querySelectorAll('.flash').forEach(el => {
    el.style.transition = 'opacity .4s, transform .4s';
    el.style.opacity = '0';
    el.style.transform = 'translateX(20px)';
    setTimeout(() => el.remove(), 400);
  });
}, 5000);

// ── TOAST ────────────────────────────────────────────────────
function showToast(msg, type = 'info', dur = 3000) {
  const t = document.createElement('div');
  t.className = `flash flash-${type}`;
  t.style.cssText = 'position:fixed;bottom:20px;right:20px;z-index:9999;padding:12px 18px;border-radius:8px;font-size:13px;animation:slideIn .3s ease;border:1px solid';
  t.innerHTML = `<span>${msg}</span><button onclick="this.parentElement.remove()" style="background:none;border:none;color:inherit;cursor:pointer;margin-left:10px;font-size:14px">✕</button>`;
  document.body.appendChild(t);
  setTimeout(() => { t.style.opacity='0'; setTimeout(()=>t.remove(),400); }, dur);
}

// ── CONFIRM DELETE ────────────────────────────────────────────
function confirmDelete(name) {
  return confirm(`"${name}" ni o'chirishni tasdiqlaysizmi?\n\nBu amalni qaytarib bo'lmaydi!`);
}

// ── ADMIN FORM TOGGLE ─────────────────────────────────────────
function toggleForm(id) {
  const el = $(id);
  if (!el) return;
  const isHidden = el.classList.contains('hidden');
  el.classList.toggle('hidden');
  if (!isHidden) return;
  // Scroll into view
  setTimeout(() => el.scrollIntoView({ behavior: 'smooth', block: 'nearest' }), 100);
}

// ── DATE DISPLAY ──────────────────────────────────────────────
const dateEl = $('currentDate');
if (dateEl) {
  const DAYS   = ['Yakshanba','Dushanba','Seshanba','Chorshanba','Payshanba','Juma','Shanba'];
  const MONTHS = ['Yanvar','Fevral','Mart','Aprel','May','Iyun','Iyul','Avgust','Sentabr','Oktabr','Noyabr','Dekabr'];
  const now    = new Date();
  dateEl.textContent = `${DAYS[now.getDay()]}, ${now.getDate()} ${MONTHS[now.getMonth()]} ${now.getFullYear()}`;
}

// ── ADMIN SIDEBAR TOGGLE ──────────────────────────────────────
function toggleAdminSidebar() {
  const sb = $('adminSidebar'), mn = $('adminMain');
  if (!sb) return;
  const col = sb.classList.toggle('collapsed');
  if (mn) mn.classList.toggle('sidebar-collapsed', col);
  localStorage.setItem('adminSidebarCollapsed', col ? '1' : '0');
}
// Restore on load
(function() {
  if (localStorage.getItem('adminSidebarCollapsed') === '1') {
    const sb = $('adminSidebar'), mn = $('adminMain');
    if (sb) sb.classList.add('collapsed');
    if (mn) mn.classList.add('sidebar-collapsed');
  }
})();

// ── COPY TEXT ─────────────────────────────────────────────────
function copyText(text) {
  navigator.clipboard.writeText(text)
    .then(() => showToast('📋 Nusxalandi!', 'success'))
    .catch(() => { showToast('Nusxalash muvaffaqiyatsiz', 'danger'); });
}

// ── SESSION MODAL ─────────────────────────────────────────────
function openSessionModal(id, status, note) {
  const form  = $('sessionUpdateForm');
  const ssel  = $('sess_status_sel');
  const sinp  = $('sess_note_inp');
  const ovl   = $('sessionModalOverlay');
  const modal = $('sessionModal');
  if (!form) return;
  form.action = '/admin/sessions/update/' + id;
  if (ssel) ssel.value = status;
  if (sinp) sinp.value = note;
  if (modal) modal.classList.add('open');
  if (ovl)   ovl.classList.add('open');
}
function closeSessionModal() {
  const modal = $('sessionModal'), ovl = $('sessionModalOverlay');
  if (modal) modal.classList.remove('open');
  if (ovl)   ovl.classList.remove('open');
}

// ── MEDIA PREVIEW ─────────────────────────────────────────────
function previewMedia(inp) {
  if (!inp.files || !inp.files[0]) return;
  const wrap = $('mediaPreview'), img = $('previewImg'), nm = $('previewName');
  if (!wrap || !img) return;
  img.src = URL.createObjectURL(inp.files[0]);
  if (nm) nm.textContent = `${inp.files[0].name} (${(inp.files[0].size/1024).toFixed(1)} KB)`;
  wrap.classList.remove('hidden');
}

// ── DRAG & DROP UPLOAD ────────────────────────────────────────
const dropZone = $('dropZone');
if (dropZone) {
  ['dragenter','dragover'].forEach(ev =>
    dropZone.addEventListener(ev, e => { e.preventDefault(); dropZone.style.borderColor = 'var(--accent)'; }));
  ['dragleave','drop'].forEach(ev =>
    dropZone.addEventListener(ev, e => { e.preventDefault(); dropZone.style.borderColor = ''; }));
  dropZone.addEventListener('drop', e => {
    const file = e.dataTransfer.files[0];
    const inp  = $('mediaFile');
    if (file && inp) {
      const dt = new DataTransfer(); dt.items.add(file); inp.files = dt.files;
      previewMedia(inp);
    }
  });
}

// ── PASSWORD TOGGLE ───────────────────────────────────────────
function togglePass(id) {
  const inp = $(id);
  if (inp) inp.type = inp.type === 'password' ? 'text' : 'password';
}

// ── DASHBOARD PANELS ──────────────────────────────────────────
function showPanel(name) {
  document.querySelectorAll('.dpanel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.dash-nav-item').forEach(i => i.classList.remove('active'));
  const panel = $('panel-' + name);
  if (panel) panel.classList.add('active');
  const titleEl = $('panelTitle');
  if (titleEl) {
    const titles = {
      overview: 'Umumiy ko\'rinish', profile: 'Profilim',
      sessions: 'Sessiyalarim', notifications: 'Bildirishnomalar'
    };
    titleEl.textContent = titles[name] || name;
  }
  if (event && event.target) event.target.classList.add('active');
}

// ── MARK NOTIFICATIONS READ ───────────────────────────────────
function markAllRead() {
  fetch('/api/notifications/mark-read', {
    method: 'POST',
    headers: { 'X-CSRF-Token': getCsrf() }
  })
  .then(() => {
    document.querySelectorAll('.notif-item.unread').forEach(el => el.classList.remove('unread'));
    document.querySelectorAll('.notif-badge').forEach(el => { el.textContent = '0'; el.style.display = 'none'; });
    showToast('Barcha bildirishnomalar o\'qildi ✓', 'success');
  })
  .catch(() => {});
}

// ── REALTIME STATS (admin) ────────────────────────────────────
function loadAdminStats() {
  fetch('/api/admin/stats', { headers: { 'X-Requested-With': 'XMLHttpRequest' } })
    .then(r => r.ok ? r.json() : null)
    .then(d => {
      if (!d) return;
      const ms = $('ms_students'); if (ms) ms.textContent = d.students;
      const mp = $('ms_pending'); if (mp) mp.textContent = d.pending_sessions;
      const mf = $('ms_failed'); if (mf) mf.textContent = d.failed_logins_24h;
      const pb = $('pendingBadge');
      if (pb) { pb.textContent = d.pending_sessions; pb.style.display = d.pending_sessions > 0 ? 'inline-flex' : 'none'; }
    })
    .catch(() => {});
}
// Only on admin pages
if (document.querySelector('.admin-layout')) {
  loadAdminStats();
  setInterval(loadAdminStats, 30000);
}

// ── TOPBAR CLOCK ──────────────────────────────────────────────
function updateClock() {
  const el = $('adminClock');
  if (!el) return;
  el.textContent = new Date().toLocaleTimeString('uz-UZ', {
    hour: '2-digit', minute: '2-digit', second: '2-digit'
  });
}
setInterval(updateClock, 1000);
updateClock();

// ── CSV EXPORT ────────────────────────────────────────────────
function exportTableCSV(tableId, filename) {
  const table = document.querySelector(tableId || 'table');
  if (!table) return;
  const rows = [...table.querySelectorAll('tr')];
  const csv  = rows.map(row => {
    return [...row.querySelectorAll('th,td')]
      .map(cell => `"${cell.textContent.replace(/"/g,'""').trim()}"`)
      .join(',');
  }).join('\n');
  const blob = new Blob(['\uFEFF' + csv], { type: 'text/csv;charset=utf-8' });
  const a    = document.createElement('a');
  a.href     = URL.createObjectURL(blob);
  a.download = filename || 'export.csv';
  a.click();
  showToast('📥 CSV yuklab olindi!', 'success');
}

// ── FORM VALIDATION ───────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('form').forEach(form => {
    form.addEventListener('submit', function(e) {
      const required = this.querySelectorAll('[required]');
      let valid = true;
      required.forEach(inp => {
        inp.style.borderColor = '';
        if (!inp.value.trim()) {
          inp.style.borderColor = 'var(--danger)';
          valid = false;
        }
      });
      if (!valid) {
        e.preventDefault();
        showToast('Barcha majburiy maydonlarni to\'ldiring!', 'danger');
        const firstBad = this.querySelector('[required]');
        if (firstBad) firstBad.focus();
      }
    });
  });

  // Auto-dismiss flash messages
  setTimeout(() => {
    document.querySelectorAll('.flash').forEach(el => {
      el.style.opacity = '0';
      el.style.transform = 'translateX(20px)';
      el.style.transition = 'all .4s';
      setTimeout(() => el.remove(), 400);
    });
  }, 5000);
});

// ── PROGRESS BARS (animate) ───────────────────────────────────
window.addEventListener('load', () => {
  document.querySelectorAll('[data-width]').forEach(el => {
    const w = el.dataset.width;
    setTimeout(() => { el.style.transition = 'width .6s ease'; el.style.width = w; }, 120);
  });
  document.querySelectorAll('.lb-bar-fill, .lb-bar-fill-full, .rating-bar-fill').forEach(el => {
    const w = el.style.width; el.style.width = '0';
    setTimeout(() => { el.style.transition = 'width .8s cubic-bezier(.4,0,.2,1)'; el.style.width = w; }, 200);
  });
});

// ── CONFIRM FORMS ─────────────────────────────────────────────
document.querySelectorAll('[data-confirm]').forEach(el => {
  el.addEventListener('click', e => {
    if (!confirm(el.dataset.confirm || 'O\'chirilsinmi?')) e.preventDefault();
  });
});

// ── SEARCH DEBOUNCE ───────────────────────────────────────────
let _searchTimer;
const clientSearch = $('clientSearch');
if (clientSearch) {
  clientSearch.addEventListener('input', function() {
    clearTimeout(_searchTimer);
    const q = this.value.toLowerCase();
    _searchTimer = setTimeout(() => {
      document.querySelectorAll('[data-searchable]').forEach(el => {
        el.style.display = el.textContent.toLowerCase().includes(q) ? '' : 'none';
      });
    }, 200);
  });
}

// ── COUNTER ANIMATION ─────────────────────────────────────────
function animateCounters() {
  document.querySelectorAll('.hstat-num, .stat-num').forEach(el => {
    const m = el.textContent.match(/\d+/);
    if (!m) return;
    const target = parseInt(m[0]);
    const suffix = el.textContent.replace(/\d+/, '').trim();
    let cur = 0;
    const step = Math.max(1, Math.floor(target / 50));
    const timer = setInterval(() => {
      cur = Math.min(cur + step, target);
      el.textContent = cur + suffix;
      if (cur >= target) clearInterval(timer);
    }, 20);
  });
}
const ctrSection = document.querySelector('.hero-stats-wrap, .stats-section');
if (ctrSection) {
  new IntersectionObserver(entries => {
    if (entries[0].isIntersecting) { animateCounters(); entries[0].target._obs?.disconnect(); }
  }, { threshold: .3 }).observe(ctrSection);
}

// ── INTERSECT REVEAL ──────────────────────────────────────────
new IntersectionObserver((entries) => {
  entries.forEach(e => { if (e.isIntersecting) e.target.classList.add('visible'); });
}, { threshold: .1, rootMargin: '0px 0px -40px 0px' })
  .observe(...(document.querySelectorAll('.reveal').length ? document.querySelectorAll('.reveal') : [document.body]));

// ── SMOOTH SCROLL ─────────────────────────────────────────────
document.querySelectorAll('a[href^="#"]').forEach(link => {
  link.addEventListener('click', e => {
    const target = document.querySelector(link.getAttribute('href'));
    if (target) { e.preventDefault(); target.scrollIntoView({ behavior: 'smooth', block: 'start' }); }
  });
});

console.log('%c🎓 S_TATU Platform v2.0', 'font-size:16px;font-weight:800;color:#fff;background:#0d1117;padding:8px 16px;border-radius:8px');
