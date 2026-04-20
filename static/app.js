// ═══════════════════════════════════════════
// LLM Remediation Platform — Frontend Logic
// ═══════════════════════════════════════════

const API_BASE = "http://127.0.0.1:8765/api";
let currentAlert = null;
let currentScenarioId = null;
let currentPlan = null;
let currentMode = "llm"; // "rule-based" | "llm" | "compare"

// UI Elements
const els = {
    scenarioList: document.getElementById('scenarioList'),
    agentMode: document.getElementById('agentMode'),
    alertDisplay: document.getElementById('alertDisplay'),
    alertHeader: document.getElementById('alertHeader'),
    alertMetrics: document.getElementById('alertMetrics'),
    reactContainer: document.getElementById('reactContainer'),
    actionBar: document.getElementById('actionBar'),
    executeBtn: document.getElementById('executeBtn'),
    resultsContent: document.getElementById('resultsContent')
};

const delay = ms => new Promise(res => setTimeout(res, ms));

const ICONS = {
    critical: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
    high: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="12 2 2 22 22 22 12 2"/><line x1="12" y1="8" x2="12" y2="16"/><line x1="12" y1="20" x2="12.01" y2="20"/></svg>',
    medium: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>',
    low: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>'
};

const MODE_LABELS = {
    "rule-based": { icon: "📋", label: "Rule-Based", color: "var(--accent-orange)" },
    "llm": { icon: "🧠", label: "LLM-Based (Llama 3.3 70B)", color: "var(--accent-purple)" },
    "compare": { icon: "⚖️", label: "Karşılaştırma", color: "var(--accent-cyan)" }
};

// ─── Mode Selection ───

async function setMode(mode) {
    currentMode = mode;
    document.querySelectorAll('.mode-btn').forEach(b => b.classList.remove('active'));
    document.querySelector(`.mode-btn[data-mode="${mode}"]`).classList.add('active');

    const ml = MODE_LABELS[mode];

    if (currentAlert) {
        els.agentMode.innerHTML = `<span style="color:${ml.color}">${ml.icon}</span> ${ml.label} — Yeniden analiz ediliyor...`;
        els.reactContainer.innerHTML = '<div class="spinner"></div>';
        els.actionBar.classList.add('hidden');
        els.resultsContent.innerHTML = '<div class="empty-state-small">Analiz bekleniyor...</div>';

        try {
            if (mode === "compare") {
                await triggerCompareMode();
            } else {
                await triggerRemediationAgent();
            }
        } catch (e) {
            console.error(e);
            els.reactContainer.innerHTML = `<div class="empty-state-small" style="color:var(--accent-red)">Hata: ${e.message}</div>`;
        }
    } else {
        els.agentMode.innerHTML = `<span style="color:${ml.color}">${ml.icon} ${ml.label}</span> — Bekleniyor...`;
    }
}

// ─── Init ───

async function init() {
    try {
        const res = await fetch(`${API_BASE}/scenarios`);
        const scenarios = await res.json();
        renderScenarioList(scenarios);
    } catch (e) {
        console.error("Failed to load scenarios:", e);
        els.scenarioList.innerHTML = `<div class="empty-state-small">Backend bağlantısı kurulamadı.</div>`;
    }
}

// ─── Scenarios ───

const CATEGORY_ICONS = {
    "Pod Yaşam Döngüsü": "🔄",
    "Ağ & Bağlantı": "🌐",
    "Depolama": "💾",
    "Güvenlik": "🔒",
    "Konfigürasyon": "⚙️",
    "Cluster & Orkestrasyon": "🏗️"
};

function renderScenarioList(scenarios) {
    const grouped = {};
    scenarios.forEach(s => {
        const cat = s.category || "Diğer";
        if (!grouped[cat]) grouped[cat] = [];
        grouped[cat].push(s);
    });

    let html = "";
    for (const [category, items] of Object.entries(grouped)) {
        const icon = CATEGORY_ICONS[category] || "📁";
        html += `<div class="scenario-category-header">${icon} ${category} <span class="category-count">${items.length}</span></div>`;
        html += items.map(s => `
            <div class="scenario-card" onclick="selectScenario('${s.id}')" id="card-${s.id}">
                <div class="scenario-title">${s.title}</div>
                <div class="scenario-meta">
                    <span class="severity-tag ${s.severity}">${ICONS[s.severity]} ${s.severity}</span>
                    <span>${s.service}</span>
                </div>
            </div>
        `).join("");
    }
    els.scenarioList.innerHTML = html;
}

async function selectScenario(id) {
    document.querySelectorAll('.scenario-card').forEach(c => c.classList.remove('active'));
    document.getElementById(`card-${id}`).classList.add('active');

    currentScenarioId = id;
    const ml = MODE_LABELS[currentMode];
    els.agentMode.innerHTML = `<span style="color:${ml.color}">${ml.icon}</span> Anomali Tespiti ve Alert Üretimi...`;

    els.reactContainer.innerHTML = '<div class="spinner"></div>';
    els.alertDisplay.classList.add('hidden');
    els.actionBar.classList.add('hidden');
    els.resultsContent.innerHTML = '<div class="empty-state-small">Analiz bekleniyor...</div>';

    try {
        const res = await fetch(`${API_BASE}/simulate/${id}`, { method: 'POST' });
        currentAlert = await res.json();
        await displayAlert(currentAlert);

        if (currentMode === "compare") {
            els.agentMode.innerHTML = `<span style="color:var(--accent-cyan)">⚖️</span> Her iki mod ile analiz yapılıyor...`;
            await triggerCompareMode();
        } else {
            els.agentMode.innerHTML = `<span style="color:${ml.color}">${ml.icon}</span> ${ml.label} — ReAct Analizi Yapılıyor...`;
            await triggerRemediationAgent();
        }
    } catch (e) {
        console.error(e);
        els.reactContainer.innerHTML = `<div class="empty-state-small" style="color:var(--accent-red)">Hata: ${e.message}</div>`;
    }
}

async function triggerRandom() {
    document.querySelectorAll('.scenario-card').forEach(c => c.classList.remove('active'));
    currentScenarioId = null;
    const ml = MODE_LABELS[currentMode];
    els.agentMode.innerHTML = `<span style="color:${ml.color}">${ml.icon}</span> Rastgele Anomali Tetikleniyor...`;
    els.reactContainer.innerHTML = '<div class="spinner"></div>';
    els.resultsContent.innerHTML = '<div class="empty-state-small">Analiz bekleniyor...</div>';

    try {
        const res = await fetch(`${API_BASE}/simulate/random/trigger`, { method: 'POST' });
        currentAlert = await res.json();
        await displayAlert(currentAlert);

        if (currentMode === "compare") {
            els.agentMode.innerHTML = `<span style="color:var(--accent-cyan)">⚖️</span> Her iki mod ile analiz yapılıyor...`;
            await triggerCompareMode();
        } else {
            els.agentMode.innerHTML = `<span style="color:${ml.color}">${ml.icon}</span> ${ml.label} — ReAct Analizi Yapılıyor...`;
            await triggerRemediationAgent();
        }
    } catch (e) {
        console.error(e);
    }
}

// ─── Alert Display ───

async function displayAlert(alert) {
    els.alertDisplay.classList.remove('hidden');

    els.alertHeader.innerHTML = `
        <div class="alert-title-row">
            <span class="severity-tag ${alert.severity}">${ICONS[alert.severity]} ${alert.severity}</span>
            <span class="alert-id">${alert.id}</span>
            <span style="font-size: 13px; font-weight: 600; color: var(--text-primary)">${alert.title}</span>
        </div>
        <div style="font-size: 11px; color: var(--text-muted); font-family: 'JetBrains Mono'">Service: ${alert.source_service} | Namespace: ${alert.namespace} | Timestamp: ${new Date(alert.timestamp).toLocaleTimeString()}</div>
        <div class="alert-desc">${alert.description}</div>
    `;

    let metricsHtml = "";
    for (const [key, val] of Object.entries(alert.metrics)) {
        let displayVal = val;
        let pClass = "normal";

        if (typeof val === 'number') {
            displayVal = val % 1 !== 0 ? val.toFixed(1) : val;
            if (key.includes('usage') || key.includes('percent')) { displayVal += '%'; }
            if (key.includes('ms')) { displayVal += 'ms'; }
            if (val > 85) pClass = "danger";
            else if (val > 60) pClass = "warning";
        } else if (typeof val === 'boolean') {
            displayVal = val ? "True" : "False";
            pClass = val ? "danger" : "normal";
        }

        const label = key.replace(/_/g, ' ').replace('percent', '%').replace('ms', '');
        metricsHtml += `
            <div class="metric-chip">
                <span class="metric-label">${label}</span>
                <span class="metric-value ${pClass}">${displayVal}</span>
            </div>
        `;
    }
    els.alertMetrics.innerHTML = metricsHtml;
    await delay(800);
}

// ─── Single Mode Agent ───

async function triggerRemediationAgent() {
    try {
        const res = await fetch(`${API_BASE}/remediate`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ alert: currentAlert, scenario_id: currentScenarioId, mode: currentMode })
        });

        currentPlan = await res.json();
        const planMode = currentPlan._mode || currentMode;
        const ml = MODE_LABELS[planMode] || MODE_LABELS["llm"];

        els.reactContainer.innerHTML = "";

        // Mode indicator at top
        const modeTag = document.createElement('div');
        modeTag.style.cssText = "padding:8px 14px; margin-bottom:8px; display:flex; align-items:center; gap:8px;";
        modeTag.innerHTML = `<span class="mode-indicator ${planMode}">${ml.icon} ${ml.label}</span>` +
            (currentPlan._fallback ? `<span style="font-size:10px; color:var(--accent-orange)">⚠️ LLM hata verdi, fallback kullanıldı</span>` : "");
        els.reactContainer.appendChild(modeTag);

        for (const step of currentPlan.react_trace) {
            renderReactStep(step);
            await delay(planMode === "llm" ? 600 + Math.random() * 400 : 400 + Math.random() * 300);
        }

        els.agentMode.innerHTML = `<span style="color:var(--accent-green)">✓ Analiz Tamamlandı</span> <span class="mode-indicator ${planMode}" style="margin-left:8px">${ml.icon} ${ml.label}</span>`;
        renderRemediationPlan(currentPlan);
        els.actionBar.classList.remove('hidden');
    } catch (e) {
        console.error(e);
        els.reactContainer.innerHTML = `<div class="empty-state-small" style="color:var(--accent-red)">Agent Error: ${e.message}</div>`;
    }
}

// ─── Compare Mode ───

async function triggerCompareMode() {
    try {
        els.reactContainer.innerHTML = `
            <div style="text-align:center; padding:20px;">
                <div class="spinner"></div>
                <div style="margin-top:12px; font-size:12px; color:var(--text-muted);">
                    Her iki mod çalıştırılıyor...<br>
                    <span style="color:var(--accent-orange)">📋 Rule-Based</span> + <span style="color:var(--accent-purple)">🧠 LLM-Based</span>
                </div>
            </div>
        `;

        const res = await fetch(`${API_BASE}/remediate/compare`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ alert: currentAlert, scenario_id: currentScenarioId })
        });

        const data = await res.json();
        const { rule_based, llm_based, comparison } = data;

        els.reactContainer.innerHTML = "";

        // ── Rule-Based Trace ──
        const ruleHeader = document.createElement('div');
        ruleHeader.style.cssText = "padding:10px 14px; margin-bottom:4px; display:flex; align-items:center; gap:8px; border-bottom:2px solid var(--accent-orange); background:var(--accent-orange-glow); border-radius:6px 6px 0 0;";
        ruleHeader.innerHTML = `<span class="mode-indicator rule-based">📋 Rule-Based ReAct Trace</span>
            <span style="font-size:10px; color:var(--text-muted); margin-left:auto;">Güven: %${(comparison.rule_based_confidence * 100).toFixed(0)} · ${comparison.rule_based_time_ms}ms</span>`;
        els.reactContainer.appendChild(ruleHeader);

        const ruleTrace = rule_based.react_trace || [];
        for (const step of ruleTrace) {
            renderReactStep(step);
            await delay(300 + Math.random() * 200);
        }

        // ── Divider ──
        const divider = document.createElement('div');
        divider.style.cssText = "margin:16px 0; border-top:2px dashed var(--border-primary); position:relative;";
        divider.innerHTML = `<span style="position:absolute; top:-10px; left:50%; transform:translateX(-50%); background:var(--bg-primary); padding:0 12px; font-size:11px; font-weight:700; color:var(--accent-cyan);">⚖️ VS</span>`;
        els.reactContainer.appendChild(divider);

        // ── LLM-Based Trace ──
        const llmHeader = document.createElement('div');
        llmHeader.style.cssText = "padding:10px 14px; margin-bottom:4px; display:flex; align-items:center; gap:8px; border-bottom:2px solid var(--accent-purple); background:var(--accent-purple-glow); border-radius:6px 6px 0 0;";
        llmHeader.innerHTML = `<span class="mode-indicator llm">🧠 LLM-Based ReAct Trace</span>
            <span style="font-size:10px; color:var(--text-muted); margin-left:auto;">Güven: %${(comparison.llm_confidence * 100).toFixed(0)} · ${comparison.llm_time_ms}ms</span>`;
        els.reactContainer.appendChild(llmHeader);

        const llmTrace = llm_based.react_trace || [];
        for (const step of llmTrace) {
            renderReactStep(step);
            await delay(400 + Math.random() * 300);
        }

        els.agentMode.innerHTML = `<span style="color:var(--accent-green)">✓ Karşılaştırma Tamamlandı</span>`;

        renderComparisonResults(rule_based, llm_based, comparison);
        els.actionBar.classList.remove('hidden');
        currentPlan = llm_based;
    } catch (e) {
        console.error(e);
        els.reactContainer.innerHTML = `<div class="empty-state-small" style="color:var(--accent-red)">Karşılaştırma hatası: ${e.message}</div>`;
    }
}

function renderComparisonResults(rule, llm, comp) {
    const rConf = (comp.rule_based_confidence * 100).toFixed(0);
    const lConf = (comp.llm_confidence * 100).toFixed(0);
    const confWinner = comp.llm_confidence >= comp.rule_based_confidence ? "llm" : "rule";
    const timeWinner = comp.rule_based_time_ms <= comp.llm_time_ms ? "rule" : "llm";

    let html = `
        <div class="compare-section">
            <div class="compare-section-header" style="color:var(--accent-cyan)">⚖️ PERFORMANS KARŞILAŞTIRMASI</div>
            <div class="compare-metric-row">
                <span class="compare-metric-label">Metrik</span>
                <span class="compare-metric-label" style="color:var(--accent-orange)">📋 Rule</span>
                <span class="compare-metric-label" style="color:var(--accent-purple)">🧠 LLM</span>
            </div>
            <div class="compare-metric-row">
                <span class="compare-metric-label">Yanıt Süresi</span>
                <span class="compare-metric-val ${timeWinner === 'rule' ? 'winner' : 'loser'}">${comp.rule_based_time_ms}ms</span>
                <span class="compare-metric-val ${timeWinner === 'llm' ? 'winner' : 'loser'}">${comp.llm_time_ms}ms</span>
            </div>
            <div class="compare-metric-row">
                <span class="compare-metric-label">Güven Skoru</span>
                <span class="compare-metric-val ${confWinner === 'rule' ? 'winner' : 'loser'}">%${rConf}</span>
                <span class="compare-metric-val ${confWinner === 'llm' ? 'winner' : 'loser'}">%${lConf}</span>
            </div>
            <div class="compare-metric-row">
                <span class="compare-metric-label">ReAct Adımları</span>
                <span class="compare-metric-val">${comp.rule_based_steps}</span>
                <span class="compare-metric-val">${comp.llm_steps}</span>
            </div>
            <div class="compare-metric-row">
                <span class="compare-metric-label">Aynı Kök Neden?</span>
                <span class="compare-metric-val" style="grid-column: span 2; color: ${comp.same_root_cause ? 'var(--accent-green)' : 'var(--accent-orange)'}">${comp.same_root_cause ? '✓ Evet' : '✗ Farklı'}</span>
            </div>
            ${comp.llm_error ? `<div style="font-size:10px; color:var(--accent-red); margin-top:6px;">⚠️ LLM Hata: ${comp.llm_error.substring(0, 100)}</div>` : ''}
        </div>

        <div class="compare-section">
            <div class="compare-section-header" style="color:var(--accent-orange)">📋 RULE-BASED KÖK NEDEN</div>
            <div style="font-size:12px; color:var(--text-secondary); line-height:1.5;">${rule.root_cause_analysis}</div>
            <div class="result-command" style="margin-top:8px">${rule.selected_action?.command || 'N/A'}</div>
        </div>

        <div class="compare-section">
            <div class="compare-section-header" style="color:var(--accent-purple)">🧠 LLM-BASED KÖK NEDEN</div>
            <div style="font-size:12px; color:var(--text-secondary); line-height:1.5;">${llm.root_cause_analysis}</div>
            <div class="result-command" style="margin-top:8px">${llm.selected_action?.command || 'N/A'}</div>
        </div>

        <div class="compare-section">
            <div class="compare-section-header">🏆 DEĞERLENDİRME</div>
            <div style="font-size:12px; color:var(--text-primary); line-height:1.6;">
                ${generateEvaluation(rule, llm, comp)}
            </div>
        </div>
    `;

    els.resultsContent.innerHTML = html;
}

function generateEvaluation(rule, llm, comp) {
    const advantages = [];
    const disadvantages = [];

    if (comp.llm_confidence > comp.rule_based_confidence) {
        advantages.push(`LLM daha yüksek güven skoru üretti (%${(comp.llm_confidence*100).toFixed(0)} vs %${(comp.rule_based_confidence*100).toFixed(0)})`);
    }
    if (comp.llm_steps > comp.rule_based_steps) {
        advantages.push(`LLM daha detaylı analiz yaptı (${comp.llm_steps} vs ${comp.rule_based_steps} adım)`);
    }
    if (llm.selected_action?.command !== rule.selected_action?.command) {
        advantages.push("LLM bağlama özel komut üretti (hardcoded değil)");
    }
    if (comp.rule_based_time_ms < comp.llm_time_ms) {
        disadvantages.push(`Rule-based daha hızlı (${comp.rule_based_time_ms}ms vs ${comp.llm_time_ms}ms)`);
    }
    if (comp.llm_error) {
        disadvantages.push("LLM API hatası oluştu, güvenilirlik riski");
    }

    let html = "<strong style='color:var(--accent-green)'>LLM Avantajları:</strong><ul style='margin:4px 0 8px 16px'>";
    advantages.forEach(a => html += `<li>${a}</li>`);
    if (advantages.length === 0) html += "<li>Bu senaryoda belirgin avantaj yok</li>";
    html += "</ul>";

    html += "<strong style='color:var(--accent-orange)'>Rule-Based Avantajları:</strong><ul style='margin:4px 0 0 16px'>";
    disadvantages.forEach(d => html += `<li>${d}</li>`);
    html += "<li>İnternet bağlantısı gerektirmez, her zaman çalışır</li>";
    html += "</ul>";

    return html;
}

// ─── Confidence Breakdown ───

const FACTOR_LABELS = {
    symptom_match: { label: "Semptom Eşleşme", icon: "🔍", desc: "Alert'teki semptomların runbook ile eşleşme oranı" },
    metric_anomaly: { label: "Metrik Anomali", icon: "📊", desc: "Metriklerdeki anormallik şiddeti" },
    runbook_coverage: { label: "Runbook Kapsamı", icon: "📋", desc: "Runbook'un tanı adımları ve çözüm zenginliği" },
    evidence_richness: { label: "Kanıt Zenginliği", icon: "🔬", desc: "Alert'teki metrik, pod ve servis bilgisi miktarı" },
    action_specificity: { label: "Aksiyon Spesifikliği", icon: "🎯", desc: "Seçilen aksiyonun ne kadar spesifik ve uygulanabilir olduğu" },
    llm_self_assessment: { label: "LLM Öz-Değerlendirme", icon: "🧠", desc: "LLM'in kendi analizine verdiği güven skoru" }
};

function renderConfidenceBreakdown(factors, mode) {
    if (!factors || Object.keys(factors).length === 0) return "";

    let rows = "";
    for (const [key, val] of Object.entries(factors)) {
        if (key.startsWith("_")) continue;
        const f = FACTOR_LABELS[key] || { label: key, icon: "•", desc: "" };
        const pct = (val * 100).toFixed(0);
        const barColor = val >= 0.7 ? "var(--accent-green)" : val >= 0.4 ? "var(--accent-orange)" : "var(--accent-red)";
        rows += `
            <div class="conf-factor-row" title="${f.desc}">
                <span class="conf-factor-label">${f.icon} ${f.label}</span>
                <div class="conf-factor-bar-bg">
                    <div class="conf-factor-bar-fill" style="width:${pct}%; background:${barColor}"></div>
                </div>
                <span class="conf-factor-val">%${pct}</span>
            </div>`;
    }

    const blending = factors._blending || "";
    const blendingHtml = blending ? `<div style="font-size:9px; color:var(--text-muted); margin-top:6px; font-family:'JetBrains Mono',monospace;">${blending}</div>` : "";

    return `
        <div class="conf-breakdown" style="margin-top:10px;">
            <div style="font-size:10px; font-weight:700; text-transform:uppercase; letter-spacing:0.5px; color:var(--text-muted); margin-bottom:6px;">
                Güven Skoru Faktörleri
            </div>
            ${rows}
            ${blendingHtml}
        </div>`;
}

// ─── Single Plan Render ───

function renderRemediationPlan(plan) {
    const confWidth = Math.max(10, plan.confidence_score * 100);
    const planMode = plan._mode || currentMode;
    const ml = MODE_LABELS[planMode] || MODE_LABELS["llm"];

    const factors = plan.confidence_factors || {};
    const factorBreakdown = renderConfidenceBreakdown(factors, planMode);

    let html = `
        <div class="result-section">
            <div class="result-section-title">
                <span class="mode-indicator ${planMode}">${ml.icon} ${ml.label}</span>
            </div>
        </div>

        <div class="result-section">
            <div class="result-section-title">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>
                Tespit Edilen Kök Neden
            </div>
            <div style="font-size: 13px; color: var(--text-primary); line-height: 1.5; margin-bottom: 8px;">
                ${plan.root_cause_analysis}
            </div>
            <div style="display:flex; justify-content:space-between; align-items:flex-end; margin-top:12px;">
                <span style="font-size:11px; color:var(--text-muted);">Güven Skoru: <strong>%${(plan.confidence_score * 100).toFixed(0)}</strong></span>
                <span class="risk-tag ${plan.selected_action.risk}">Risk: ${plan.selected_action.risk}</span>
            </div>
            <div class="confidence-bar"><div class="confidence-fill" style="width: ${confWidth}%"></div></div>
            ${factorBreakdown}
        </div>

        <div class="result-section">
            <div class="result-section-title">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
                Önerilen Aksiyon
            </div>
            <div class="result-card selected">
                <div class="result-action-name">${plan.selected_action.action}</div>
                <div style="font-size: 11px; color: var(--text-secondary);">${plan.selected_action.description || ''}</div>
                <div class="result-command">${plan.selected_action.command}</div>
            </div>
        </div>
    `;

    if (plan.alternative_actions && plan.alternative_actions.length > 0) {
        html += `
            <div class="result-section">
                <div class="result-section-title">Alternatif Çözümler</div>
                <div class="result-card alternative">
                    <div style="display:flex; justify-content:space-between;">
                        <span class="result-action-name" style="font-size:12px">${plan.alternative_actions[0].action}</span>
                        <span class="risk-tag ${plan.alternative_actions[0].risk}" style="font-size:8px; padding:2px 4px">${plan.alternative_actions[0].risk}</span>
                    </div>
                </div>
            </div>
        `;
    }

    html += `
        <div class="result-section">
            <div class="result-section-title">🛡️ Rollback & Doğrulama</div>
            <div class="rollback-box">${plan.rollback_plan}</div>
        </div>
    `;

    els.resultsContent.innerHTML = html;
}

// ─── ReAct Step Render ───

function renderReactStep(step) {
    const el = document.createElement('div');
    el.className = 'react-step';

    let badgeHtml = "";
    const a = step.action || "";
    if (a === "root_cause_analysis" || a === "select_remediation" || a.includes("plan") || a.includes("validation")) {
        badgeHtml = `<span class="step-type thought">Reasoning</span>`;
    } else if (a.includes("investigate") || a.includes("analyze") || a.includes("query") || a.includes("log")) {
        badgeHtml = `<span class="step-type action">Action</span><span class="step-type observation">Observation</span>`;
    } else if (a.includes("triage") || a.includes("alert")) {
        badgeHtml = `<span class="step-type thought">Thought</span>`;
    } else {
        badgeHtml = `<span class="step-type action">Action</span>`;
    }

    let bodyHtml = `
        <div class="step-section">
            <span class="step-label thought-label">THOUGHT</span>
            <div class="step-content">${step.thought}</div>
        </div>
    `;

    if (step.action && step.action_input) {
        bodyHtml += `
            <div class="step-section">
                <span class="step-label action-label">ACTION</span>
                <div class="step-content"><strong>${step.action}</strong> <code>${step.action_input}</code></div>
            </div>
        `;
    }

    if (step.observation) {
        bodyHtml += `
            <div class="step-section">
                <span class="step-label observation-label">OBSERVE</span>
                <div class="step-content" style="color: var(--text-primary)">${formatObservation(step.observation)}</div>
            </div>
        `;
    }

    el.innerHTML = `
        <div class="react-step-header">
            <div class="step-number">${step.step_number}</div>
            ${badgeHtml}
            <div style="flex:1"></div>
            <div style="font-size:10px; color:var(--text-muted); font-family:'JetBrains Mono'">${new Date().toLocaleTimeString()}</div>
        </div>
        <div class="react-step-body">
            ${bodyHtml}
        </div>
    `;

    els.reactContainer.appendChild(el);
    els.reactContainer.parentElement.scrollTop = els.reactContainer.parentElement.scrollHeight;
}

function formatObservation(obs) {
    if (obs.includes('\n')) {
        return `<pre style="font-family:'JetBrains Mono'; font-size:10px; background:var(--bg-elevated); padding:8px; border-radius:4px; margin-top:4px; overflow-x:auto; border-left:2px solid var(--accent-green)">${obs}</pre>`;
    }
    return obs;
}

// ─── Execution ───

async function executeRemediation() {
    els.executeBtn.disabled = true;
    els.executeBtn.innerHTML = '<div class="spinner" style="width:16px;height:16px;margin:0;border-width:2px;"></div> Uygulanıyor...';

    try {
        const res = await fetch(`${API_BASE}/execute`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ alert: currentAlert, scenario_id: currentScenarioId })
        });

        const data = await res.json();
        const exec = data.execution;
        const sim = data.simulation_result;

        await delay(1500);

        let validationsHtml = '<ul class="validation-list">';
        exec.validation_results.forEach(v => {
            validationsHtml += `<li class="passed">${v.step}</li>`;
        });
        validationsHtml += '</ul>';

        const resultEl = document.createElement('div');
        resultEl.className = 'execution-result';
        resultEl.innerHTML = `
            <div class="execution-header">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
                Remediation Başarıyla Uygulandı
            </div>
            <div class="execution-detail">> ${exec.command_executed}</div>
            <div class="execution-detail" style="color:var(--text-muted)">Exec Time: ${exec.execution_time_ms}ms · MTTR: ${sim ? sim.mttr_seconds : 45}s</div>
            <hr style="border:0; border-top:1px solid rgba(16,185,129,0.3); margin:12px 0;">
            <div style="font-size: 11px; font-weight: 600; color: var(--accent-green); margin-bottom: 6px;">DOĞRULAMA KONTROLLERİ:</div>
            ${validationsHtml}
        `;

        els.reactContainer.appendChild(resultEl);
        els.reactContainer.parentElement.scrollTop = els.reactContainer.parentElement.scrollHeight;
        els.executeBtn.innerHTML = '✅ Sistem Stabil';
    } catch (e) {
        console.error(e);
        els.executeBtn.disabled = false;
        els.executeBtn.innerHTML = 'Tekrar Dene';
    }
}

function resetDashboard() {
    currentAlert = null;
    currentScenarioId = null;
    currentPlan = null;

    document.querySelectorAll('.scenario-card').forEach(c => c.classList.remove('active'));
    const ml = MODE_LABELS[currentMode];
    els.agentMode.innerHTML = `<span style="color:${ml.color}">${ml.icon} ${ml.label}</span> — Bekleniyor...`;
    els.alertDisplay.classList.add('hidden');
    els.actionBar.classList.add('hidden');
    els.executeBtn.disabled = false;
    els.executeBtn.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg> Remediation Uygula';

    els.reactContainer.innerHTML = `
        <div class="empty-state">
            <div class="empty-icon">🤖</div>
            <h3>Remediation Agent Hazır</h3>
            <p>Soldaki panelden bir incident senaryosu seçin veya rastgele incident tetikleyin.</p>
            <p class="empty-sub">Üstteki mod seçici ile Rule-Based, LLM-Based veya Karşılaştırma modunu seçebilirsiniz.</p>
        </div>
    `;

    els.resultsContent.innerHTML = `
        <div class="empty-state-small">Agent analizi tamamladığında remediation planı burada görünecek.</div>
    `;
}

// Start
init();
