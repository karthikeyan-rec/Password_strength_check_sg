/* ============================================================
   SecureGuard — Password Strength Analyzer
   app.js — Core Logic
   ============================================================ */

'use strict';

// ===== COMMON PASSWORDS LIST =====
const COMMON_PASSWORDS = new Set([
  'password', '123456', '12345678', '1234567890', 'password1', 'qwerty',
  'abc123', 'iloveyou', 'monkey', '123456789', 'dragon', 'master',
  'letmein', 'login', 'admin', 'welcome', 'sunshine', 'shadow',
  'michael', 'superman', 'batman', 'football', 'baseball', 'soccer',
  '1234567', 'trustno1', 'passw0rd', 'hello', 'charlie', 'donald',
  'princess', 'startrek', 'starwars', '111111', '000000', 'zxcvbn',
  'asdfgh', 'qazwsx', 'password123', 'changeme', 'secret', 'test',
  'guest', 'root', 'toor', 'pass', 'qwerty123', 'abc1234', '1q2w3e',
  'letmein1', 'password!', 'test123', 'admin123', 'user123'
]);

// ===== APP STATE =====
let currentPassword = '';
let currentScore = 0;
let passwordHistory = JSON.parse(localStorage.getItem('sg-history') || '[]');
let isVisible = false;

// ===== NAVIGATION =====
function showSection(name) {
  ['analyzer', 'history', 'about'].forEach(s => {
    const sec = document.getElementById(`section-${s}`);
    const btn = document.getElementById(`nav-${s}`);
    const isActive = s === name;
    sec.style.display = isActive ? 'block' : 'none';
    btn.classList.toggle('active', isActive);
    btn.setAttribute('aria-pressed', isActive);
  });

  if (name === 'history') renderHistory();
}

// ===== TOGGLE PASSWORD VISIBILITY =====
function toggleVisibility() {
  isVisible = !isVisible;
  const input = document.getElementById('password-input');
  const icon = document.getElementById('eye-icon');
  input.type = isVisible ? 'text' : 'password';
  icon.innerHTML = isVisible
    ? '<path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19m-6.72-1.07a3 3 0 11-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/>'
    : '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>';
}

// ===== PASSWORD ANALYSIS ENGINE =====
function analyzePassword() {
  const input = document.getElementById('password-input');
  const pwd = input.value;
  currentPassword = pwd;

  if (!pwd) {
    resetUI();
    return;
  }

  const result = evaluatePassword(pwd);
  currentScore = result.score;
  updateUI(pwd, result);
}

function evaluatePassword(pwd) {
  const len = pwd.length;
  const upperCount = (pwd.match(/[A-Z]/g) || []).length;
  const lowerCount = (pwd.match(/[a-z]/g) || []).length;
  const numberCount = (pwd.match(/[0-9]/g) || []).length;
  const specialCount = (pwd.match(/[^A-Za-z0-9]/g) || []).length;
  const uniqueChars = new Set(pwd).size;

  // Charset pool calculation
  let charsetSize = 0;
  if (upperCount > 0) charsetSize += 26;
  if (lowerCount > 0) charsetSize += 26;
  if (numberCount > 0) charsetSize += 10;
  if (specialCount > 0) charsetSize += 32;
  if (charsetSize === 0) charsetSize = 26;

  // Entropy = log2(charsetSize^len)
  const entropy = len * Math.log2(charsetSize);

  // Score calculation (0–100)
  let score = 0;

  // Length scoring
  if (len >= 6) score += 10;
  if (len >= 8) score += 10;
  if (len >= 12) score += 10;
  if (len >= 16) score += 15;
  if (len >= 20) score += 10;

  // Complexity scoring
  if (upperCount > 0) score += 10;
  if (lowerCount > 0) score += 10;
  if (numberCount > 0) score += 10;
  if (specialCount > 0) score += 15;
  if (specialCount >= 2) score += 5;

  // Uniqueness bonus
  const uniqueRatio = uniqueChars / len;
  if (uniqueRatio > 0.8) score += 5;

  // Penalties
  const isCommon = COMMON_PASSWORDS.has(pwd.toLowerCase());
  if (isCommon) score = Math.min(score, 20);

  const hasRepeat = /(.)\1{2,}/.test(pwd); // 3+ same chars
  const hasSeq = /(012|123|234|345|456|567|678|789|abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz|qwerty|asdf|zxcv)/i.test(pwd);
  if (hasRepeat) score -= 15;
  if (hasSeq) score -= 10;

  score = Math.max(0, Math.min(100, score));

  // Strength level 1–5
  let level, label, color;
  if (score <= 20) { level = 1; label = 'Very Weak'; color = '#ef4444'; }
  else if (score <= 40) { level = 2; label = 'Weak'; color = '#f97316'; }
  else if (score <= 60) { level = 3; label = 'Fair'; color = '#f59e0b'; }
  else if (score <= 80) { level = 4; label = 'Strong'; color = '#10b981'; }
  else { level = 5; label = 'Very Strong'; color = '#06b6d4'; }

  // Checks
  const checks = {
    length: len >= 8,
    lengthGreat: len >= 16,
    upper: upperCount > 0,
    lower: lowerCount > 0,
    number: numberCount > 0,
    special: specialCount > 0,
    noCommon: !isCommon,
    noRepeat: !hasRepeat && !hasSeq
  };

  // Suggestions
  const suggestions = [];
  if (len < 8) suggestions.push({ icon: '📏', text: 'Use at least 8 characters.' });
  if (len < 16) suggestions.push({ icon: '📐', text: 'Aim for 16+ characters for maximum security.' });
  if (upperCount === 0) suggestions.push({ icon: '🔠', text: 'Add uppercase letters (A-Z).' });
  if (lowerCount === 0) suggestions.push({ icon: '🔡', text: 'Add lowercase letters (a-z).' });
  if (numberCount === 0) suggestions.push({ icon: '🔢', text: 'Include numbers (0-9).' });
  if (specialCount === 0) suggestions.push({ icon: '💥', text: 'Add special characters (!@#$%^&*).' });
  if (isCommon) suggestions.push({ icon: '🚨', text: 'This is a commonly breached password! Choose something unique.' });
  if (hasRepeat) suggestions.push({ icon: '♻️', text: 'Avoid repeating characters (e.g. "aaa").' });
  if (hasSeq) suggestions.push({ icon: '🔢', text: 'Avoid sequential patterns (e.g. "123", "abc").' });
  if (uniqueRatio < 0.6) suggestions.push({ icon: '✨', text: 'Use more unique characters to increase entropy.' });

  if (suggestions.length === 0) {
    suggestions.push({ icon: '🏆', text: 'Excellent! Your password meets all security criteria.' });
  }

  return {
    score, level, label, color, entropy, charsetSize,
    uniqueChars, len, upperCount, lowerCount, numberCount, specialCount,
    checks, suggestions, isCommon, hasRepeat, hasSeq
  };
}

// ===== UI UPDATE =====
function updateUI(pwd, result) {
  // Strength bars
  const bars = document.querySelectorAll('.strength-bar');
  bars.forEach((bar, i) => {
    bar.classList.toggle('active', i < result.level);
    bar.style.background = i < result.level ? '' : '';
  });

  // Strength label
  const labelEl = document.getElementById('strength-label');
  const scoreEl = document.getElementById('strength-score');
  labelEl.textContent = result.label;
  labelEl.style.color = result.color;
  scoreEl.textContent = `${result.score}/100`;
  scoreEl.style.color = result.color;

  // ARIA
  document.getElementById('strength-bars').setAttribute('aria-valuenow', result.score);

  // Crack time
  const crackBox = document.getElementById('crack-time-box');
  const crackValue = document.getElementById('crack-time-value');
  crackBox.style.display = 'flex';
  crackValue.textContent = estimateCrackTime(result.entropy);

  // Checklist
  setCheck('check-length', result.checks.length);
  setCheck('check-length-great', result.checks.lengthGreat);
  setCheck('check-upper', result.checks.upper);
  setCheck('check-lower', result.checks.lower);
  setCheck('check-number', result.checks.number);
  setCheck('check-special', result.checks.special);
  setCheck('check-no-common', result.checks.noCommon);
  setCheck('check-no-repeat', result.checks.noRepeat);

  // Stats
  document.getElementById('stat-length-val').textContent = result.len;
  document.getElementById('stat-entropy-val').textContent = result.entropy.toFixed(1);
  document.getElementById('stat-charset-val').textContent = result.charsetSize;
  document.getElementById('stat-unique-val').textContent = result.uniqueChars;

  // Breakdown bars
  const total = result.len || 1;
  updateBreakdownBar('bar-upper', 'cnt-upper', result.upperCount, total);
  updateBreakdownBar('bar-lower', 'cnt-lower', result.lowerCount, total);
  updateBreakdownBar('bar-number', 'cnt-number', result.numberCount, total);
  updateBreakdownBar('bar-special', 'cnt-special', result.specialCount, total);

  // Suggestions
  const suggList = document.getElementById('suggestions-list');
  suggList.innerHTML = result.suggestions.map(s =>
    `<li class="suggestion-item"><span class="suggestion-icon">${s.icon}</span><span>${s.text}</span></li>`
  ).join('');

  // Alternatives
  const altSection = document.getElementById('alternatives-section');
  if (result.score < 80) {
    altSection.style.display = 'block';
    generateAlternatives();
  } else {
    altSection.style.display = 'none';
  }
}

function updateBreakdownBar(barId, cntId, count, total) {
  const pct = Math.min(100, (count / total) * 100);
  document.getElementById(barId).style.width = pct + '%';
  document.getElementById(cntId).textContent = count;
}

function setCheck(id, pass) {
  const el = document.getElementById(id);
  el.classList.toggle('pass', pass);
  el.classList.toggle('fail', !pass);
  const indicator = el.querySelector('.check-indicator');
  if (pass) {
    indicator.innerHTML = `<svg viewBox="0 0 16 16" fill="none"><circle cx="8" cy="8" r="7" fill="rgba(16,185,129,0.15)" stroke="#10b981" stroke-width="1.5"/><path d="M5 8l2 2 4-4" stroke="#10b981" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>`;
  } else {
    indicator.innerHTML = `<svg viewBox="0 0 16 16" fill="none"><circle cx="8" cy="8" r="7" fill="rgba(239,68,68,0.1)" stroke="#ef4444" stroke-width="1.5"/><path d="M5.5 10.5l5-5M10.5 10.5l-5-5" stroke="#ef4444" stroke-width="1.5" stroke-linecap="round"/></svg>`;
  }
}

function resetUI() {
  currentScore = 0;
  document.querySelectorAll('.strength-bar').forEach(b => b.classList.remove('active'));
  document.getElementById('strength-label').textContent = 'Enter a password to begin';
  document.getElementById('strength-label').style.color = '';
  document.getElementById('strength-score').textContent = '';
  document.getElementById('crack-time-box').style.display = 'none';

  ['check-length','check-length-great','check-upper','check-lower','check-number','check-special','check-no-common','check-no-repeat'].forEach(id => {
    const el = document.getElementById(id);
    el.classList.remove('pass', 'fail');
    el.querySelector('.check-indicator').innerHTML = `<svg viewBox="0 0 16 16" fill="none"><circle cx="8" cy="8" r="7" stroke="currentColor" stroke-width="1.5"/></svg>`;
  });

  ['stat-length-val','stat-entropy-val','stat-charset-val','stat-unique-val'].forEach(id => {
    document.getElementById(id).textContent = '—';
  });

  ['bar-upper','bar-lower','bar-number','bar-special'].forEach(id => {
    document.getElementById(id).style.width = '0%';
  });
  ['cnt-upper','cnt-lower','cnt-number','cnt-special'].forEach(id => {
    document.getElementById(id).textContent = '0';
  });

  document.getElementById('suggestions-list').innerHTML = `
    <li class="suggestion-item empty-state">
      <span class="suggestion-icon">🛡️</span>
      <span>Enter a password to get personalized suggestions</span>
    </li>`;

  document.getElementById('alternatives-section').style.display = 'none';
  document.getElementById('strength-bars').setAttribute('aria-valuenow', 0);
}

// ===== CRACK TIME ESTIMATION =====
function estimateCrackTime(entropy) {
  // Assume 10 billion guesses/second (GPU cluster)
  const guessesPerSec = 1e10;
  const combinations = Math.pow(2, entropy);
  const secondsToHalfCrack = combinations / (2 * guessesPerSec);

  if (secondsToHalfCrack < 1) return 'Instantly';
  if (secondsToHalfCrack < 60) return `${secondsToHalfCrack.toFixed(1)} seconds`;
  if (secondsToHalfCrack < 3600) return `${(secondsToHalfCrack / 60).toFixed(1)} minutes`;
  if (secondsToHalfCrack < 86400) return `${(secondsToHalfCrack / 3600).toFixed(1)} hours`;
  if (secondsToHalfCrack < 31536000) return `${(secondsToHalfCrack / 86400).toFixed(0)} days`;
  if (secondsToHalfCrack < 3.154e9) return `${(secondsToHalfCrack / 31536000).toFixed(0)} years`;
  if (secondsToHalfCrack < 3.154e12) return `${(secondsToHalfCrack / 3.154e9).toFixed(0)}K years`;
  if (secondsToHalfCrack < 3.154e15) return `${(secondsToHalfCrack / 3.154e12).toFixed(0)}M years`;
  return 'Practically uncrackable';
}

// ===== PASSWORD GENERATION =====
const CHARS = {
  upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  lower: 'abcdefghijklmnopqrstuvwxyz',
  number: '0123456789',
  special: '!@#$%^&*()-_=+[]{}|;:,.<>?'
};

function generatePassword() {
  const length = 20;
  const allChars = CHARS.upper + CHARS.lower + CHARS.number + CHARS.special;
  let pwd = '';

  // Ensure at least one of each type
  pwd += pickRandom(CHARS.upper);
  pwd += pickRandom(CHARS.lower);
  pwd += pickRandom(CHARS.number);
  pwd += pickRandom(CHARS.special);

  for (let i = pwd.length; i < length; i++) {
    pwd += allChars[Math.floor(Math.random() * allChars.length)];
  }

  // Shuffle
  pwd = shuffleString(pwd);

  const input = document.getElementById('password-input');
  input.value = pwd;
  currentPassword = pwd;
  analyzePassword();
  showToast('🔐 Strong password generated!');
}

function pickRandom(str) {
  return str[Math.floor(Math.random() * str.length)];
}

function shuffleString(str) {
  const arr = str.split('');
  for (let i = arr.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr.join('');
}

function generateAlternatives() {
  const altList = document.getElementById('alt-list');
  const alternatives = [];
  for (let i = 0; i < 3; i++) {
    const length = 16 + Math.floor(Math.random() * 6);
    alternatives.push(generateStrongPassword(length));
  }

  altList.innerHTML = alternatives.map((pwd, i) => `
    <div class="alt-item" id="alt-item-${i}">
      <span class="alt-password">${escapeHtml(pwd)}</span>
      <button class="alt-copy-btn" onclick="copyAlt(${i})" aria-label="Copy alternative password ${i+1}" title="Copy this password">Copy</button>
    </div>
  `).join('');
  altList._passwords = alternatives;
}

function generateStrongPassword(length) {
  const allChars = CHARS.upper + CHARS.lower + CHARS.number + CHARS.special;
  let pwd = pickRandom(CHARS.upper) + pickRandom(CHARS.lower) + pickRandom(CHARS.number) + pickRandom(CHARS.special);
  for (let i = pwd.length; i < length; i++) {
    pwd += allChars[Math.floor(Math.random() * allChars.length)];
  }
  return shuffleString(pwd);
}

function copyAlt(i) {
  const altList = document.getElementById('alt-list');
  const pwd = altList._passwords && altList._passwords[i];
  if (pwd) {
    navigator.clipboard.writeText(pwd).then(() => {
      showToast('✅ Alternative password copied!');
    }).catch(() => fallbackCopy(pwd));
  }
}

// ===== COPY PASSWORD =====
function copyPassword() {
  if (!currentPassword) {
    showToast('⚠️ No password to copy!');
    return;
  }
  navigator.clipboard.writeText(currentPassword)
    .then(() => showToast('✅ Password copied to clipboard!'))
    .catch(() => fallbackCopy(currentPassword));
}

function fallbackCopy(text) {
  const ta = document.createElement('textarea');
  ta.value = text;
  ta.style.position = 'fixed';
  ta.style.opacity = '0';
  document.body.appendChild(ta);
  ta.select();
  document.execCommand('copy');
  document.body.removeChild(ta);
  showToast('✅ Copied!');
}

// ===== HISTORY =====
function saveToHistory() {
  if (!currentPassword) {
    showToast('⚠️ Enter a password first!');
    return;
  }

  const result = evaluatePassword(currentPassword);
  const masked = maskPassword(currentPassword);

  // Check for reuse
  const existing = passwordHistory.find(h => h.masked === masked);
  if (existing) {
    showToast('⚠️ This password was already saved!');
    return;
  }

  const entry = {
    id: Date.now(),
    masked,
    score: result.score,
    label: result.label,
    color: result.color,
    level: result.level,
    length: result.len,
    entropy: result.entropy.toFixed(1),
    savedAt: new Date().toLocaleString()
  };

  passwordHistory.unshift(entry);
  if (passwordHistory.length > 20) passwordHistory.pop();
  localStorage.setItem('sg-history', JSON.stringify(passwordHistory));
  showToast('💾 Password saved to history!');
}

function maskPassword(pwd) {
  if (pwd.length <= 4) return '*'.repeat(pwd.length);
  return pwd[0] + '*'.repeat(pwd.length - 2) + pwd[pwd.length - 1];
}

function renderHistory() {
  const list = document.getElementById('history-list');
  const empty = document.getElementById('empty-history');

  if (passwordHistory.length === 0) {
    empty.style.display = 'block';
    // Remove any previous history items
    list.querySelectorAll('.history-item').forEach(el => el.remove());
    return;
  }

  empty.style.display = 'none';
  list.querySelectorAll('.history-item').forEach(el => el.remove());

  const levelEmojis = ['', '🔴', '🟠', '🟡', '🟢', '🔵'];
  const levelBg = ['', 'rgba(239,68,68,0.1)', 'rgba(249,115,22,0.1)', 'rgba(245,158,11,0.1)', 'rgba(16,185,129,0.1)', 'rgba(6,182,212,0.1)'];

  passwordHistory.forEach(entry => {
    const div = document.createElement('div');
    div.className = 'history-item';
    div.setAttribute('role', 'listitem');
    div.innerHTML = `
      <div class="history-badge" style="background:${levelBg[entry.level] || levelBg[1]}">
        ${levelEmojis[entry.level] || '🔴'}
      </div>
      <div class="history-info">
        <div class="history-masked">${escapeHtml(entry.masked)}</div>
        <div class="history-meta">
          <span class="history-strength-tag" style="background:${entry.color}22;color:${entry.color};border:1px solid ${entry.color}44">${entry.label}</span>
          <span>Score: ${entry.score}/100</span>
          <span>Entropy: ${entry.entropy} bits</span>
          <span>${entry.savedAt}</span>
        </div>
      </div>
      <button class="history-delete-btn" onclick="deleteHistoryItem(${entry.id})" aria-label="Delete this history entry" title="Remove">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 01-2 2H8a2 2 0 01-2-2L5 6"/></svg>
      </button>
    `;
    list.appendChild(div);
  });
}

function deleteHistoryItem(id) {
  const entry = passwordHistory.find(h => h.id === id);
  if (!entry) return;
  openConfirmModal({
    icon: '🗑️',
    title: 'Delete This Entry?',
    message: `Remove the saved password <strong>${escapeHtml(entry.masked)}</strong> (${entry.label} — ${entry.score}/100)? This cannot be undone.`,
    okLabel: 'Yes, Delete',
    onConfirm: () => {
      // Animate out the item before removal
      const items = document.querySelectorAll('.history-item');
      items.forEach(el => {
        if (el.querySelector('.history-masked') &&
            el.querySelector('.history-masked').textContent === entry.masked) {
          el.style.transition = 'all 0.35s ease';
          el.style.opacity = '0';
          el.style.transform = 'translateX(40px) scale(0.95)';
          setTimeout(() => {
            passwordHistory = passwordHistory.filter(h => h.id !== id);
            localStorage.setItem('sg-history', JSON.stringify(passwordHistory));
            renderHistory();
            showToast('🗑️ Entry removed');
          }, 340);
        }
      });
    }
  });
}

function clearHistory() {
  if (passwordHistory.length === 0) {
    showToast('History is already empty');
    return;
  }
  openConfirmModal({
    icon: '🗑️',
    title: 'Clear All History?',
    message: `This will permanently delete all <strong>${passwordHistory.length}</strong> saved password entries. This action cannot be undone.`,
    okLabel: 'Yes, Clear All',
    onConfirm: confirmClearHistory
  });
}

// ===== UNIFIED CONFIRM MODAL =====
let _confirmCallback = null;

function openConfirmModal({ icon = '🗑️', title = 'Are you sure?', message = '', okLabel = 'Yes, Delete', onConfirm }) {
  _confirmCallback = onConfirm;
  document.getElementById('confirm-icon').textContent = icon;
  document.getElementById('confirm-title').textContent = title;
  document.getElementById('confirm-message').innerHTML = message;
  document.getElementById('confirm-ok-label').textContent = okLabel;
  const modal = document.getElementById('confirm-modal');
  modal.style.display = 'flex';
  // Keyboard focus to cancel for safety
  setTimeout(() => document.getElementById('confirm-cancel-btn').focus(), 50);
}

function closeConfirmModal() {
  document.getElementById('confirm-modal').style.display = 'none';
  _confirmCallback = null;
}

function confirmClearHistory() {
  closeConfirmModal();
  passwordHistory = [];
  localStorage.removeItem('sg-history');
  renderHistory();
  showToast('🗑️ History cleared');
}

// The OK button always delegates to the active callback
document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('confirm-ok-btn').addEventListener('click', () => {
    if (_confirmCallback) {
      closeConfirmModal();
      _confirmCallback();
    }
  });
});

// ===== TOAST =====
let toastTimeout;
function showToast(message) {
  const toast = document.getElementById('toast');
  toast.textContent = message;
  toast.classList.add('show');
  clearTimeout(toastTimeout);
  toastTimeout = setTimeout(() => toast.classList.remove('show'), 3000);
}

// ===== HELPERS =====
function escapeHtml(str) {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// ===== KEYBOARD SHORTCUTS =====
document.addEventListener('keydown', (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key === 'g') {
    e.preventDefault();
    generatePassword();
  }
  if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
    e.preventDefault();
    document.getElementById('password-input').focus();
  }
  if (e.key === 'Escape') {
    closeConfirmModal();
  }
});

// Close modal when clicking the dark backdrop
document.addEventListener('click', (e) => {
  const modal = document.getElementById('confirm-modal');
  if (e.target === modal) closeConfirmModal();
});

// ===== SPLASH SCREEN =====
(function initSplash() {
  const splash = document.getElementById('splash-screen');
  if (!splash) return;

  // Lock scroll while splash is active
  document.body.classList.add('splash-active');

  // Dismiss after 2.7s (bar animation is 2.2s + 0.4s delay = 2.6s)
  const SPLASH_DURATION = 2700;

  function dismissSplash() {
    splash.classList.add('splash-hide');
    // After fade-out, remove from DOM and restore scroll
    setTimeout(() => {
      splash.style.display = 'none';
      document.body.classList.remove('splash-active');
      // Focus the password input after page reveals
      const input = document.getElementById('password-input');
      if (input) input.focus();
    }, 700); // matches CSS transition duration
  }

  // Auto-dismiss
  setTimeout(dismissSplash, SPLASH_DURATION);

  // Allow clicking anywhere on splash to skip early
  splash.addEventListener('click', () => {
    dismissSplash();
  }, { once: true });
})();
