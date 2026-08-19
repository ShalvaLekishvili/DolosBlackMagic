(function (global) {
  'use strict';

  const P = global.DBMPlatform = global.DBMPlatform || {};
  const text = (v) => String(v ?? '');
  const num = (v) => Number(v);
  const get = (event, field) => field.split('.').reduce((value, key) => value == null ? undefined : value[key], event);

  const OPS = {
    equals: (a, b) => text(a) === text(b),
    notEquals: (a, b) => text(a) !== text(b),
    contains: (a, b) => text(a).toLowerCase().includes(text(b).toLowerCase()),
    startsWith: (a, b) => text(a).toLowerCase().startsWith(text(b).toLowerCase()),
    endsWith: (a, b) => text(a).toLowerCase().endsWith(text(b).toLowerCase()),
    exists: (a) => a !== undefined && a !== null && text(a) !== '',
    gt: (a, b) => num(a) > num(b),
    gte: (a, b) => num(a) >= num(b),
    lt: (a, b) => num(a) < num(b),
    lte: (a, b) => num(a) <= num(b),
    in: (a, b) => Array.isArray(b) && b.map(text).includes(text(a))
  };

  function safeRegex(pattern) {
    pattern = text(pattern);
    if (!pattern || pattern.length > 256) return null;
    if (/(?:\([^)]*[+*][^)]*\))[+*{]/.test(pattern)) return null;
    if (/(?:\.\*|\.\+).*(?:\.\*|\.\+)/.test(pattern)) return null;
    try { return new RegExp(pattern, 'i'); } catch { return null; }
  }

  function validateCondition(condition, path = 'condition') {
    const errors = [];
    if (!condition || typeof condition !== 'object') return [`${path}: invalid condition`];

    if (condition.all) {
      if (!Array.isArray(condition.all) || !condition.all.length) errors.push(`${path}.all: empty group`);
      else condition.all.forEach((entry, index) => errors.push(...validateCondition(entry, `${path}.all[${index}]`)));
      return errors;
    }

    if (condition.any) {
      if (!Array.isArray(condition.any) || !condition.any.length) errors.push(`${path}.any: empty group`);
      else condition.any.forEach((entry, index) => errors.push(...validateCondition(entry, `${path}.any[${index}]`)));
      return errors;
    }

    if (condition.not) return validateCondition(condition.not, `${path}.not`);
    if (!condition.field) errors.push(`${path}: missing field`);
    if (condition.op === 'regex') {
      if (!safeRegex(condition.value)) errors.push(`${path}: invalid or unsafe regex`);
    } else if (!OPS[condition.op]) {
      errors.push(`${path}: unknown operator ${condition.op}`);
    }
    return errors;
  }

  function matchCondition(event, condition) {
    if (condition.all) return condition.all.every((entry) => matchCondition(event, entry));
    if (condition.any) return condition.any.some((entry) => matchCondition(event, entry));
    if (condition.not) return !matchCondition(event, condition.not);
    const actual = get(event, condition.field);
    if (condition.op === 'regex') {
      const regex = safeRegex(condition.value);
      return Boolean(regex) && regex.test(text(actual));
    }
    return OPS[condition.op]?.(actual, condition.value) === true;
  }

  function eventTime(event) {
    const value = Date.parse(event.timestamp || '');
    return Number.isFinite(value) ? value : null;
  }

  function groupKey(event, fields = []) {
    return fields.map((field) => text(get(event, field)) || '∅').join('|');
  }

  function hash(value) {
    let result = 0;
    for (let i = 0; i < value.length; i++) result = ((result << 5) - result + value.charCodeAt(i)) | 0;
    return result;
  }

  function makeFinding(rule, events, extra = {}) {
    const evidence = events.slice(0, 50).map((event) => ({
      eventId: event.stableId || event.id,
      timestamp: event.timestamp || '',
      source: event.source || '',
      host: event.host || '',
      user: event.user || '',
      message: text(event.message).slice(0, 500),
      provenance: event.provenance || null
    }));

    return {
      id: `FND-${rule.id}-${Math.abs(hash(JSON.stringify(evidence.map((item) => item.eventId))))}`,
      ruleId: rule.id,
      name: rule.name,
      severity: rule.severity || 'medium',
      confidence: rule.confidence || 'medium',
      mitre: rule.mitre || [],
      tags: rule.tags || [],
      why: rule.why || rule.description || 'Declarative detection conditions matched.',
      falsePositive: rule.falsePositive || '',
      remediation: rule.remediation || '',
      eventIds: events.map((event) => event.stableId || event.id),
      evidence,
      ...extra
    };
  }

  function runThreshold(rule, events) {
    const config = rule.threshold || {};
    const windowMs = Math.max(1000, Number(config.windowMs || 300000));
    const threshold = Math.max(1, Number(config.count || 1));
    const distinctField = config.distinctField || '';
    const groups = new Map();
    const findings = [];

    for (const event of events) {
      if (!matchCondition(event, rule.condition)) continue;
      const current = eventTime(event);
      if (current == null) continue;
      const key = groupKey(event, config.groupBy || []);
      const bucket = groups.get(key) || [];
      bucket.push(event);
      while (bucket.length && current - eventTime(bucket[0]) > windowMs) bucket.shift();
      groups.set(key, bucket);

      const observed = distinctField
        ? new Set(bucket.map((item) => text(get(item, distinctField))).filter(Boolean)).size
        : bucket.length;

      if (observed >= threshold) {
        findings.push(makeFinding(rule, [...bucket], {
          correlation: true,
          correlationType: 'threshold',
          windowMs,
          group: key,
          threshold,
          observed,
          distinctField: distinctField || null
        }));
        groups.set(key, []);
      }
    }
    return findings;
  }

  function runSequence(rule, events) {
    const stages = rule.sequence?.stages || [];
    const windowMs = Math.max(1000, Number(rule.sequence?.windowMs || 300000));
    const groupBy = rule.sequence?.groupBy || [];
    const state = new Map();
    const findings = [];
    if (stages.length < 2) return findings;

    for (const event of events) {
      const current = eventTime(event);
      if (current == null) continue;
      const key = groupKey(event, groupBy);
      let groupState = state.get(key);
      if (!groupState || current - groupState.startedAt > windowMs) {
        groupState = { index: 0, startedAt: current, events: [] };
      }

      const stage = stages[groupState.index];
      if (stage && matchCondition(event, stage)) {
        groupState.events.push(event);
        groupState.index += 1;
        if (groupState.index === stages.length) {
          findings.push(makeFinding(rule, [...groupState.events], {
            correlation: true,
            correlationType: 'sequence',
            windowMs,
            group: key,
            stages: stages.length
          }));
          groupState = { index: 0, startedAt: current, events: [] };
        }
      }
      state.set(key, groupState);
    }
    return findings;
  }

  function validateRule(rule) {
    const errors = [];
    if (!rule?.id) errors.push('missing rule id');
    if (!rule?.name) errors.push('missing rule name');
    if (!rule?.condition && !rule?.sequence) errors.push('missing condition or sequence');
    if (rule.condition) errors.push(...validateCondition(rule.condition));

    if (rule.threshold) {
      if (Number(rule.threshold.count) < 1) errors.push('threshold count must be >= 1');
      if (Number(rule.threshold.windowMs) < 1000) errors.push('threshold window must be >= 1000 ms');
    }

    if (rule.sequence) {
      if (!Array.isArray(rule.sequence.stages) || rule.sequence.stages.length < 2) {
        errors.push('sequence requires >= 2 stages');
      } else {
        rule.sequence.stages.forEach((stage, index) => errors.push(...validateCondition(stage, `sequence.stages[${index}]`)));
      }
      if (Number(rule.sequence.windowMs) < 1000) errors.push('sequence window must be >= 1000 ms');
    }

    return { valid: errors.length === 0, errors };
  }

  function runRule(rule, events = []) {
    const validation = validateRule(rule);
    if (!validation.valid) return { valid: false, errors: validation.errors, findings: [], elapsedMs: 0 };
    const started = global.performance?.now?.() ?? Date.now();
    let findings;
    if (rule.sequence) findings = runSequence(rule, events);
    else if (rule.threshold) findings = runThreshold(rule, events);
    else findings = events.filter((event) => matchCondition(event, rule.condition)).map((event) => makeFinding(rule, [event]));
    const ended = global.performance?.now?.() ?? Date.now();
    return { valid: true, errors: [], findings, elapsedMs: Math.round(ended - started) };
  }

  const builtins = [
    {
      id: 'CORR-AUTH-SPRAY',
      name: 'Authentication spray pattern',
      severity: 'high',
      confidence: 'high',
      mitre: ['T1110.003'],
      tags: ['windows', 'linux', 'authentication'],
      description: 'Repeated authentication failures from one source against multiple accounts.',
      why: 'The same source produced repeated failures against several distinct usernames in a bounded window.',
      falsePositive: 'Shared gateways, jump hosts or misconfigured identity clients.',
      remediation: 'Validate source ownership, targeted accounts and any subsequent successful authentication.',
      condition: {
        any: [
          { field: 'eventId', op: 'equals', value: '4625' },
          { field: 'message', op: 'regex', value: '(?:failed password|authentication failure|invalid user)' }
        ]
      },
      threshold: { count: 3, windowMs: 180000, groupBy: ['srcIp'], distinctField: 'user' }
    },
    {
      id: 'CORR-AUTH-SUCCESS-AFTER-FAIL',
      name: 'Successful authentication after repeated failures',
      severity: 'high',
      confidence: 'medium',
      mitre: ['T1110', 'T1078'],
      tags: ['authentication', 'sequence'],
      description: 'Success follows a failure burst from the same source.',
      why: 'Repeated failed logons were followed by a successful logon from the same source in a short time window.',
      falsePositive: 'Users correcting a password after several mistakes.',
      remediation: 'Confirm user, source IP, device and whether the successful session was expected.',
      sequence: {
        windowMs: 300000,
        groupBy: ['srcIp'],
        stages: [
          { any: [
            { field: 'eventId', op: 'equals', value: '4625' },
            { field: 'message', op: 'regex', value: 'failed password|authentication failure' }
          ] },
          { any: [
            { field: 'eventId', op: 'equals', value: '4624' },
            { field: 'message', op: 'regex', value: 'accepted password|successful logon' }
          ] }
        ]
      }
    },
    {
      id: 'CORR-SERVICE-PROCESS',
      name: 'Service installation followed by process execution',
      severity: 'high',
      confidence: 'medium',
      mitre: ['T1543.003', 'T1059'],
      tags: ['windows', 'persistence', 'sequence'],
      description: 'New service installation followed by process execution on the same host.',
      why: 'Service installation and subsequent process creation occurred on the same host inside a bounded window.',
      falsePositive: 'Software deployment and endpoint-management tooling.',
      remediation: 'Review service binary path, signer, parent/child process lineage and change authorization.',
      sequence: {
        windowMs: 180000,
        groupBy: ['host'],
        stages: [
          { field: 'eventId', op: 'equals', value: '7045' },
          { any: [
            { field: 'eventId', op: 'equals', value: '4688' },
            { field: 'eventId', op: 'equals', value: '1' }
          ] }
        ]
      }
    }
  ];

  P.detectionsV3 = {
    OPS,
    safeRegex,
    validateCondition,
    matchCondition,
    validateRule,
    runRule,
    builtins,
    runAll(events, rules = builtins) {
      return rules.flatMap((rule) => runRule(rule, events).findings);
    }
  };
})(window);
