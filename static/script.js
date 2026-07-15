const fileInput = document.getElementById('fileInput');
const fileDrop = document.getElementById('fileDrop');
const fileDropText = document.getElementById('fileDropText');
const analyzeBtn = document.getElementById('analyzeBtn');
const sampleChips = document.querySelectorAll('.sample-chip');

const reportPanel = document.getElementById('reportPanel');
const errorPanel = document.getElementById('errorPanel');
const errorText = document.getElementById('errorText');

let selectedFile = null;
let selectedSample = null;

fileInput.addEventListener('change', () => {
  if (fileInput.files.length) {
    selectedFile = fileInput.files[0];
    selectedSample = null;
    fileDropText.textContent = selectedFile.name;
  }
});

['dragover', 'dragleave', 'drop'].forEach((evt) => {
  fileDrop.addEventListener(evt, (e) => {
    e.preventDefault();
    fileDrop.classList.toggle('drag-over', evt === 'dragover');
  });
});

fileDrop.addEventListener('drop', (e) => {
  const file = e.dataTransfer.files[0];
  if (file) {
    selectedFile = file;
    selectedSample = null;
    fileDropText.textContent = file.name;
  }
});

sampleChips.forEach((chip) => {
  chip.addEventListener('click', () => {
    selectedSample = chip.dataset.sample;
    selectedFile = null;
    fileDropText.textContent = `Sample selected: ${chip.textContent}`;
    runAnalysis();
  });
});

analyzeBtn.addEventListener('click', runAnalysis);

async function runAnalysis() {
  errorPanel.hidden = true;
  reportPanel.hidden = true;

  if (!selectedFile && !selectedSample) {
    showError('Choose a .eml file or pick a sample case first.');
    return;
  }

  analyzeBtn.disabled = true;
  analyzeBtn.textContent = 'Analyzing…';

  try {
    const formData = new FormData();
    if (selectedFile) {
      formData.append('file', selectedFile);
    } else {
      formData.append('sample', selectedSample);
    }

    const res = await fetch('/api/analyze', { method: 'POST', body: formData });
    const data = await res.json();

    if (!res.ok) {
      showError(data.error || 'Analysis failed.');
      return;
    }

    renderReport(data);
  } catch (err) {
    showError('Could not reach the server. Is app.py running?');
  } finally {
    analyzeBtn.disabled = false;
    analyzeBtn.textContent = 'Analyze →';
  }
}

function showError(msg) {
  errorText.textContent = msg;
  errorPanel.hidden = false;
}

function riskColor(score) {
  if (score >= 70) return 'var(--red)';
  if (score >= 40) return '#ffb000';
  if (score >= 15) return '#e8c547';
  return 'var(--green)';
}

function renderReport(data) {
  reportPanel.hidden = false;

  // Risk banner
  const score = data.risk.score;
  const color = riskColor(score);
  document.getElementById('riskScore').textContent = score;
  document.getElementById('riskScore').style.color = color;
  document.getElementById('riskVerdict').textContent = data.risk.verdict;
  document.getElementById('riskVerdict').style.color = color;
  const fill = document.getElementById('riskBarFill');
  fill.style.width = score + '%';
  fill.style.background = color;

  // Header table
  const h = data.headers;
  const headerRows = [
    ['From', h.from], ['To', h.to], ['Reply-To', h.reply_to || '—'],
    ['Subject', h.subject], ['Date', h.date],
  ];
  document.getElementById('headerTable').innerHTML = headerRows.map(
    ([k, v]) => `<tr><td>${k}</td><td>${escapeHtml(v || '—')}</td></tr>`
  ).join('');

  // Auth chips
  const auth = data.auth_results;
  const authHtml = ['spf', 'dkim', 'dmarc'].map((mech) => {
    const val = auth[mech];
    const cls = val.replace(' ', '');
    return `<span class="auth-chip ${cls}">${mech.toUpperCase()}: ${val}</span>`;
  }).join('');
  document.getElementById('authChips').innerHTML = authHtml;

  // Reasons
  const reasonsList = document.getElementById('reasonsList');
  if (data.risk.reasons.length) {
    reasonsList.className = 'reasons-list';
    reasonsList.innerHTML = data.risk.reasons.map((r) => `<li>${escapeHtml(r)}</li>`).join('');
  } else {
    reasonsList.className = 'reasons-list empty';
    reasonsList.innerHTML = '<li>No risk indicators detected.</li>';
  }

  // Sender analysis
  const dn = data.display_name_check;
  const rt = data.reply_to_check;
  let senderHtml = `Display name: <strong>${escapeHtml(dn.display_name || '—')}</strong><br>`;
  senderHtml += `Sending domain: <strong>${escapeHtml(dn.domain || '—')}</strong><br>`;
  senderHtml += dn.mismatch
    ? `<span class="flag">⚠ Impersonates ${escapeHtml(dn.implied_brand)}</span><br>`
    : `<span class="ok">✓ No brand impersonation detected</span><br>`;
  senderHtml += rt.mismatch
    ? `<span class="flag">⚠ Reply-To domain (${escapeHtml(rt.reply_domain)}) differs from sender</span>`
    : `<span class="ok">✓ Reply-To matches sender domain</span>`;
  document.getElementById('senderAnalysis').innerHTML = senderHtml;

  // URLs / domains
  const urlListEl = document.getElementById('urlList');
  if (data.urls.length) {
    urlListEl.innerHTML = data.urls.map((url) => {
      const isIp = data.ip_urls.includes(url);
      return `<div class="ioc-row ${isIp ? 'flagged' : ''}">
        <span>${escapeHtml(url)}</span>
        ${isIp ? '<span class="ioc-flag-tag">IP-BASED URL</span>' : ''}
      </div>`;
    }).join('');
  } else {
    urlListEl.innerHTML = '<div class="ioc-empty">No URLs found in the message body.</div>';
  }

  // Attachments
  const attEl = document.getElementById('attachmentList');
  if (data.attachments.length) {
    attEl.innerHTML = data.attachments.map((a) => `
      <div class="ioc-row ${a.risky ? 'flagged' : ''}">
        <span>${escapeHtml(a.filename)} <span style="color:var(--muted)">(${escapeHtml(a.content_type)})</span></span>
        ${a.risky ? '<span class="ioc-flag-tag">HIGH RISK TYPE</span>' : ''}
      </div>
    `).join('');
  } else {
    attEl.innerHTML = '<div class="ioc-empty">No attachments found.</div>';
  }

  reportPanel.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str ?? '';
  return div.innerHTML;
}
