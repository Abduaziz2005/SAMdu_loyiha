// ============================================================
// S_TATU PLATFORM — Main JavaScript
// ============================================================

// ── NAVBAR ──────────────────────────────────────────────────
const navbar = document.getElementById('navbar');
const mobToggle = document.getElementById('mobToggle');
const navLinks  = document.getElementById('navLinks');

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
  // Close on outside click
  document.addEventListener('click', (e) => {
    if (!navbar.contains(e.target)) {
      navLinks.classList.remove('open');
      mobToggle.classList.remove('active');
    }
  });
}

// ── FLASH AUTO-CLOSE ─────────────────────────────────────────
setTimeout(() => {
  document.querySelectorAll('.flash').forEach(el => {
    el.style.opacity = '0';
    el.style.transform = 'translateX(20px)';
    el.style.transition = 'all 0.4s';
    setTimeout(() => el.remove(), 400);
  });
}, 4000);

// ── PROGRESS BARS (animate on load) ─────────────────────────
function animateBars() {
  document.querySelectorAll('[data-width]').forEach(el => {
    const w = el.dataset.width;
    setTimeout(() => { el.style.width = w; }, 100);
  });
}
window.addEventListener('load', animateBars);

// ── REVEAL ANIMATIONS ─────────────────────────────────────────
const observer = new IntersectionObserver((entries) => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      entry.target.classList.add('visible');
    }
  });
}, { threshold: 0.1, rootMargin: '0px 0px -40px 0px' });

document.querySelectorAll('.reveal').forEach(el => observer.observe(el));

// ── SMOOTH SCROLL ─────────────────────────────────────────────
document.querySelectorAll('a[href^="#"]').forEach(link => {
  link.addEventListener('click', (e) => {
    const target = document.querySelector(link.getAttribute('href'));
    if (target) {
      e.preventDefault();
      target.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  });
});

// ── LEADERBOARD BAR ANIMATION ─────────────────────────────────
setTimeout(() => {
  document.querySelectorAll('.lb-bar-fill, .lb-bar-fill-full, .rating-bar-fill').forEach(el => {
    const w = el.style.width;
    el.style.width = '0';
    setTimeout(() => { el.style.transition = 'width 0.8s cubic-bezier(0.4,0,0.2,1)'; el.style.width = w; }, 200);
  });
}, 300);

// ── ADMIN TOGGLE FORM ─────────────────────────────────────────
function toggleForm(id) {
  const el = document.getElementById(id);
  if (el) el.classList.toggle('hidden');
}

// ── DATE DISPLAY ──────────────────────────────────────────────
const dateEl = document.getElementById('currentDate');
if (dateEl) {
  const days   = ['Yakshanba','Dushanba','Seshanba','Chorshanba','Payshanba','Juma','Shanba'];
  const months = ['Yanvar','Fevral','Mart','Aprel','May','Iyun','Iyul','Avgust','Sentabr','Oktabr','Noyabr','Dekabr'];
  const now    = new Date();
  dateEl.textContent = `${days[now.getDay()]}, ${now.getDate()} ${months[now.getMonth()]} ${now.getFullYear()}`;
}

// ── SEARCH FILTER (client-side fast) ─────────────────────────
const clientSearch = document.getElementById('clientSearch');
if (clientSearch) {
  clientSearch.addEventListener('input', function () {
    const q = this.value.toLowerCase();
    document.querySelectorAll('[data-searchable]').forEach(el => {
      el.style.display = el.textContent.toLowerCase().includes(q) ? '' : 'none';
    });
  });
}

// ── COUNTER ANIMATION ─────────────────────────────────────────
function animateCounters() {
  document.querySelectorAll('.hstat-num, .stat-num').forEach(el => {
    const match = el.textContent.match(/\d+/);
    if (!match) return;
    const target = parseInt(match[0]);
    const suffix = el.textContent.replace(/\d+/, '').trim();
    let current = 0;
    const step = Math.max(1, Math.floor(target / 50));
    const timer = setInterval(() => {
      current = Math.min(current + step, target);
      el.textContent = current + suffix;
      if (current >= target) clearInterval(timer);
    }, 20);
  });
}

// Run counter when visible
const countersSection = document.querySelector('.hero-stats-wrap, .stats-section');
if (countersSection) {
  const counterObs = new IntersectionObserver((entries) => {
    if (entries[0].isIntersecting) { animateCounters(); counterObs.disconnect(); }
  }, { threshold: 0.3 });
  counterObs.observe(countersSection);
}

// ── NOTIFICATIONS ─────────────────────────────────────────────
function markAllRead() {
  fetch('/api/notifications/mark-read', { method: 'POST' })
    .then(() => {
      document.querySelectorAll('.notif-item.unread').forEach(el => el.classList.remove('unread'));
      document.querySelectorAll('.notif-badge').forEach(el => el.textContent = '0');
    })
    .catch(() => {});
}

// ── DASHBOARD PANELS ──────────────────────────────────────────
function showPanel(name) {
  document.querySelectorAll('.dpanel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.dash-nav-item').forEach(i => i.classList.remove('active'));
  const panel = document.getElementById('panel-' + name);
  if (panel) panel.classList.add('active');
  const panelTitle = document.getElementById('panelTitle');
  if (panelTitle) {
    const titles = {
      overview:      'Umumiy ko\'rinish',
      profile:       'Mening profilim',
      sessions:      'Sessiyalar',
      notifications: 'Bildirishnomalar'
    };
    panelTitle.textContent = titles[name] || name;
  }
  if (event && event.target) event.target.classList.add('active');
}

// ── PASSWORD TOGGLE ───────────────────────────────────────────
function togglePass(id) {
  const input = document.getElementById(id);
  if (input) input.type = input.type === 'password' ? 'text' : 'password';
}

// ── CONFIRM DELETE ────────────────────────────────────────────
document.querySelectorAll('[data-confirm]').forEach(el => {
  el.addEventListener('click', (e) => {
    if (!confirm(el.dataset.confirm || 'O\'chirilsinmi?')) e.preventDefault();
  });
});

// ── COPY TEXT ─────────────────────────────────────────────────
function copyText(text) {
  navigator.clipboard.writeText(text).then(() => showToast('Nusxalandi!')).catch(() => {});
}

function showToast(msg, type = 'success') {
  const t = document.createElement('div');
  t.className = `flash flash-${type}`;
  t.style.cssText = 'position:fixed;bottom:20px;right:20px;z-index:9999;padding:12px 18px;border-radius:8px;font-size:14px;animation:slideIn 0.3s ease';
  t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(() => { t.style.opacity='0'; setTimeout(()=>t.remove(),400); }, 2500);
}

// ── FORM VALIDATION ───────────────────────────────────────────
document.querySelectorAll('form').forEach(form => {
  form.addEventListener('submit', function (e) {
    const required = this.querySelectorAll('[required]');
    let valid = true;
    required.forEach(inp => {
      inp.style.borderColor = '';
      if (!inp.value.trim()) {
        inp.style.borderColor = '#ff4444';
        valid = false;
      }
    });
    if (!valid) {
      e.preventDefault();
      showToast('Barcha majburiy maydonlarni to\'ldiring!', 'danger');
    }
  });
});

console.log('%cS_TATU Platform', 'font-size:20px;font-weight:800;color:#fff;background:#111;padding:8px 16px;border-radius:8px');
console.log('Admin: /admin | Login: admin / admin123');
