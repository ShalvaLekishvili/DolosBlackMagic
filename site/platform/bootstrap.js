(function (global) {
  'use strict';

  const P = global.DBMPlatform = global.DBMPlatform || {};
  const bus = P.bus;
  const $ = (selector) => document.querySelector(selector);
  const esc = (value) => String(value ?? '').replace(/[&<>'"]/g, (char) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;'
  }[char]));

  let controller = null;

  function status(message, error = false) {
    const element = $('#logStatus');
    if (!element) return;
    element.textContent = message;
    element.classList.toggle('error', error);
  }

  function renderStream(input) {
    const result = P.detectionPipeline?.apply ? P.detectionPipeline.apply(input) : input;
    global.DBMState = global.DBMState || {};
    global.DBMState.logResult = result;

    const summary = result.summary || {};
    const parse = summary.parse || {};
    const events = Array.isArray(result.events) ? result.events : [];
    const findings = Array.isArray(result.findings) ? result.findings : [];

    if ($('#logFormat')) $('#logFormat').textContent = String(summary.format || 'stream').toUpperCase();
    if ($('#logEvents')) $('#logEvents').textContent = summary.total || events.length;
    if ($('#logFindings')) $('#logFindings').textContent = findings.length;
    if ($('#logCritical')) $('#logCritical').textContent = findings.filter((finding) => ['critical', 'high'].includes(finding.severity)).length;
    if ($('#logParsed')) $('#logParsed').textContent = parse.parsed || 0;
    if ($('#logPartial')) $('#logPartial').textContent = parse.partial || 0;
    if ($('#logMalformed')) $('#logMalformed').textContent = parse.malformed || 0;
    if ($('#logDropped')) $('#logDropped').textContent = parse.dropped || 0;

    const findingList = $('#findingList');
    if (findingList) {
      findingList.innerHTML = findings.length
        ? findings.slice(0, 120).map((finding, index) => `
          <button class="log-finding sev-${esc(finding.severity)}" data-stream-finding="${index}">
            <div>
              <span class="severity-pill ${esc(finding.severity)}">${esc(finding.severity)}</span>
              <b>${esc(finding.name)}</b>
            </div>
            <small>${esc(finding.ruleId)} · ${esc(finding.confidence || 'unknown')} confidence · ${esc(finding.kind || 'finding')} · ${(finding.eventIds || []).length} evidence event(s)</small>
          </button>`).join('')
        : '<div class="empty"><h3>No detections fired</h3><p>Telemetry remains available for investigation.</p></div>';
    }

    const body = $('#logBody');
    if (body) {
      body.innerHTML = events.slice(0, 750).map((event) => `
        <tr>
          <td>${esc((event.timestamp || '—').replace('T', ' ').replace('Z', ''))}</td>
          <td><span class="severity-pill ${esc(event.severity)}">${esc(event.severity)}</span></td>
          <td>${esc(event.source)}</td>
          <td>${esc(event.stableId || event.eventId || event.id)}</td>
          <td>${esc(event.host || '—')}<small>${esc(event.user || '')}</small></td>
          <td><code>${esc(event.srcIp || '—')} → ${esc(event.dstIp || '—')}</code></td>
          <td class="message-cell">${esc(String(event.message || '').slice(0, 600))}</td>
        </tr>`).join('');
    }

    if ($('#logShown')) $('#logShown').textContent = `${events.length} events · first ${Math.min(750, events.length)} rendered`;
    $('#logWorkspace')?.classList.remove('hidden');

    window.dispatchEvent(new CustomEvent('dbm:log-analysis', {
      detail: {
        result,
        mode: summary.streaming ? 'stream' : summary.persisted ? 'vault' : 'compatibility',
        sourceName: summary.sourceName || ''
      }
    }));

    bus?.emit('telemetry:loaded', result, { remember: true });

    const investigation = P.investigations?.active?.();
    if (investigation && summary.sourceName) {
      P.investigations.addSource(investigation.id, {
        name: summary.sourceName,
        kind: 'telemetry',
        format: summary.format || 'stream',
        retention: summary.persisted ? 'indexeddb' : 'ephemeral'
      });
    }

    return result;
  }

  async function compatibilityAnalyze(file, reason) {
    status(`Reading ${file.name} with the ${reason} parser…`);
    if (file.size > 35 * 1024 * 1024) {
      throw new Error(`${reason} files above 35 MB are not streamed yet; convert large datasets to NDJSON/JSONL or line-oriented telemetry.`);
    }

    const text = await file.text();
    const result = global.DBMLogEngine.analyzeLogs(text);
    result.summary = { ...(result.summary || {}), sourceName: file.name, streaming: false, parserMode: 'full-file' };

    (result.events || []).forEach((event, index) => {
      event.stableId = event.stableId || `EVT-${String(index + 1).padStart(7, '0')}`;
      event.provenance = event.provenance || {
        sourceFile: file.name,
        recordIndex: index + 1,
        lineNumber: null,
        byteStart: null,
        byteEnd: null,
        parser: event.format || result.summary.format || '',
        rawPreview: typeof event.raw === 'string'
          ? event.raw.slice(0, 1600)
          : JSON.stringify(event.raw ?? {}).slice(0, 1600)
      };
    });

    const merged = renderStream(result);
    status(`${reason} analysis complete · ${merged.events.length.toLocaleString()} events · ${merged.findings.length.toLocaleString()} findings · full-file compatibility parser`);
  }

  async function chooseMode(file) {
    const name = (file.name || '').toLowerCase();
    if (name.endsWith('.csv')) return 'csv';
    if (name.endsWith('.json') && !name.endsWith('.jsonl')) return 'json';

    const head = await file.slice(0, 65536).text();
    const trimmed = head.trimStart();
    if ((trimmed.startsWith('[') || trimmed.startsWith('{')) && (!head.includes('\n') || trimmed.startsWith('['))) return 'json';
    if (/^[^\n]+,[^\n]+\n/.test(head) && /(time|date|timestamp|event|message|source|host|user|process)/i.test(head.split(/\r?\n/, 1)[0])) return 'csv';
    return 'stream';
  }

  async function analyzeFile(file) {
    if (!P.streaming || !file) return;

    controller?.abort();
    controller = new AbortController();
    const cancel = $('#cancelLogs');
    const analyze = $('#analyzeLogs');

    if (cancel) {
      cancel.classList.remove('hidden');
      cancel.onclick = () => controller.abort();
    }
    if (analyze) analyze.disabled = true;

    try {
      const mode = await chooseMode(file);
      if (mode !== 'stream') {
        await compatibilityAnalyze(file, mode.toUpperCase());
        return;
      }

      status(`Streaming ${file.name} locally…`);
      const { result, summary } = await P.streaming.analyzeFile(file, {
        signal: controller.signal,
        onProgress: (message) => {
          if (!message.totalBytes) return;
          const percent = Math.min(100, Math.round((message.bytesProcessed / message.totalBytes) * 100));
          status(`${message.stage === 'reading' ? 'Reading' : 'Parsing'} ${file.name}: ${message.bytesProcessed.toLocaleString()} / ${message.totalBytes.toLocaleString()} bytes (${percent}%) · ${message.recordsProcessed || 0} records`);
        }
      });

      result.summary = { ...(result.summary || {}), sourceName: file.name, streaming: true, stream: summary };
      const merged = renderStream(result);
      status(`Streaming complete · ${summary.recordsProcessed.toLocaleString()} records · ${merged.findings.length.toLocaleString()} findings · ${summary.malformed} malformed · ${summary.dropped} dropped · ${summary.elapsedMs} ms`);
    } catch (error) {
      if (error.name === 'AbortError') status('Analysis cancelled. No partial investigation result was committed.');
      else {
        console.error(error);
        status(`Analysis failed safely: ${error.message}`, true);
      }
    } finally {
      if (cancel) cancel.classList.add('hidden');
      if (analyze) analyze.disabled = false;
      controller = null;
    }
  }

  function enhanceStreaming() {
    const input = $('#logFile');
    const drop = $('#logDrop');
    if (!input) return;

    input.onchange = (event) => analyzeFile(event.target.files?.[0]);
    if (drop) {
      drop.ondrop = (event) => {
        event.preventDefault();
        drop.classList.remove('drag');
        analyzeFile(event.dataTransfer?.files?.[0]);
      };
    }
  }

  function bridgeLegacy() {
    window.addEventListener('dbm:log-analysis', (event) => {
      const result = event.detail?.result;
      if (!result) return;

      bus?.emit('telemetry:loaded', result, { remember: true });
      const investigation = P.investigations?.active?.();
      if (!investigation) return;

      for (const finding of result.findings || []) {
        P.investigations.addFinding(investigation.id, finding);
      }

      const entities = new Map();
      for (const telemetry of (result.events || []).slice(0, 10000)) {
        const candidates = [
          ['host', telemetry.host], ['user', telemetry.user], ['ip', telemetry.srcIp],
          ['ip', telemetry.dstIp], ['process', telemetry.process], ['domain', telemetry.domain],
          ['url', telemetry.url]
        ];

        for (const [type, value] of candidates) {
          if (!value) continue;
          const key = `${type}:${value}`;
          const current = entities.get(key) || { type, value, count: 0, firstSeen: telemetry.timestamp, lastSeen: telemetry.timestamp };
          current.count += 1;
          if (telemetry.timestamp) {
            if (!current.firstSeen || telemetry.timestamp < current.firstSeen) current.firstSeen = telemetry.timestamp;
            if (!current.lastSeen || telemetry.timestamp > current.lastSeen) current.lastSeen = telemetry.timestamp;
          }
          entities.set(key, current);
        }
      }

      for (const entity of entities.values()) {
        P.investigations.addEntity(investigation.id, entity.type, entity.value, {
          firstSeen: entity.firstSeen,
          lastSeen: entity.lastSeen
        });
      }
    });

    window.addEventListener('dbm:case-opened', (event) => {
      bus?.emit('artifact:opened', event.detail, { remember: true });
    });
  }

  function init() {
    const tasks = [['legacy bridge', bridgeLegacy], ['streaming', enhanceStreaming]];
    for (const [name, task] of tasks) {
      try { task(); }
      catch (error) { console.error(`DolosBlackMagic bootstrap: ${name} failed`, error); }
    }
    bus?.emit('platform:ready', { version: '0.9.0', at: new Date().toISOString() }, { remember: true });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init, { once: true });
  else init();

  P.bootstrap = { init, analyzeFile, chooseMode, renderStream, status };
})(window);
