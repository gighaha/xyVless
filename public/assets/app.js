'use strict';

const VlessConverter = (function () {
  const NETWORKS = new Set(['tcp', 'ws', 'grpc', 'http', 'httpupgrade', 'xhttp', 'kcp', 'quic']);
  const SECURITIES = new Set(['none', 'tls', 'reality', 'xtls']);
  const OPTION_DEFAULTS = { mixed: true, sniffing: false, lanDirect: false };

  function decodeComponent(value) {
    try {
      return decodeURIComponent(value);
    } catch (err) {
      return value;
    }
  }

  function truthy(value) {
    if (value === undefined || value === null) return false;
    const text = String(value).trim().toLowerCase();
    return text === '1' || text === 'true' || text === 'yes' || text === 'on';
  }

  function formatHost(host) {
    if (!host) return '';
    const raw = String(host);
    if (raw.includes(':') && !raw.startsWith('[')) return '[' + raw + ']';
    return raw;
  }

  function splitHosts(value) {
    return String(value || '')
      .split(',')
      .map((item) => item.trim())
      .filter(Boolean);
  }

  function parsePort(value) {
    const port = Number(value);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      throw new Error('端口 “' + value + '” 不合法（应为 1-65535）');
    }
    return port;
  }

  function splitAuthority(authority) {
    if (!authority) throw new Error('缺少服务器地址');
    let host = '';
    let portRaw = '';
    if (authority.startsWith('[')) {
      const close = authority.indexOf(']');
      if (close < 0) throw new Error('IPv6 地址缺少右方括号');
      host = authority.slice(1, close);
      const rest = authority.slice(close + 1);
      if (!rest.startsWith(':')) throw new Error('IPv6 地址后缺少端口');
      portRaw = rest.slice(1);
    } else {
      const idx = authority.lastIndexOf(':');
      if (idx < 0) throw new Error('服务器地址缺少端口（应为 host:port）');
      host = authority.slice(0, idx);
      portRaw = authority.slice(idx + 1);
    }
    if (!host) throw new Error('服务器地址为空');
    return { host, port: parsePort(portRaw) };
  }

  function parseVlessLink(input) {
    const raw = String(input || '').trim();
    if (!raw) throw new Error('请先填写 VLESS 链接');
    if (!/^vless:\/\//i.test(raw)) throw new Error('链接必须以 vless:// 开头');

    let rest = raw.replace(/^vless:\/\//i, '');

    let remark = '';
    const hashAt = rest.indexOf('#');
    if (hashAt !== -1) {
      remark = decodeComponent(rest.slice(hashAt + 1)).trim();
      rest = rest.slice(0, hashAt);
    }

    let queryRaw = '';
    const queryAt = rest.indexOf('?');
    if (queryAt !== -1) {
      queryRaw = rest.slice(queryAt + 1);
      rest = rest.slice(0, queryAt);
    }
    rest = rest.replace(/\/+$/, '');

    const at = rest.lastIndexOf('@');
    if (at === -1) throw new Error('缺少 UUID 与地址分隔符 “@”');
    const uuid = decodeComponent(rest.slice(0, at)).trim();
    const { host, port } = splitAuthority(rest.slice(at + 1));

    if (!/^[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12}$/i.test(uuid)) {
      throw new Error('UUID “' + uuid + '” 格式不正确');
    }

    const params = {};
    const search = new URLSearchParams(queryRaw);
    for (const [key, value] of search.entries()) {
      params[key.toLowerCase()] = value;
    }

    const pick = (...keys) => {
      for (const key of keys) {
        const value = params[key.toLowerCase()];
        if (value !== undefined && value !== '') return value;
      }
      return '';
    };

    const network = (pick('type') || 'tcp').toLowerCase();
    if (!NETWORKS.has(network)) {
      throw new Error('暂不支持传输方式 type=' + network);
    }
    const security = (pick('security') || 'none').toLowerCase();
    if (!SECURITIES.has(security)) {
      throw new Error('暂不支持安全类型 security=' + security);
    }

    const hostParam = pick('host');
    const sni = pick('sni', 'servername', 'peer') || (security !== 'none' ? hostParam : '');
    const alpnRaw = pick('alpn');

    return {
      remark,
      uuid,
      address: host,
      port,
      params,
      network,
      security,
      encryption: pick('encryption') || 'none',
      flow: pick('flow'),
      sni,
      fingerprint: pick('fp', 'fingerprint'),
      alpn: alpnRaw ? splitHosts(alpnRaw) : [],
      publicKey: pick('pbk', 'publickey', 'public-key'),
      shortId: pick('sid', 'shortid'),
      spiderX: pick('spx', 'spiderx'),
      allowInsecure: truthy(pick('allowinsecure', 'insecure')),
      headerType: (pick('headertype', 'header') || 'none').toLowerCase(),
      path: pick('path'),
      host: hostParam,
      serviceName: pick('servicename', 'service'),
      mode: pick('mode'),
      seed: pick('seed'),
      quicSecurity: pick('quicsecurity'),
      quicKey: pick('key'),
      maxEarlyData: pick('ed'),
      earlyDataHeaderName: pick('eh'),
      packetEncoding: pick('packetencoding')
    };
  }

  function buildStreamSettings(parsed) {
    const ss = { network: parsed.network };

    if (parsed.security === 'tls') {
      const tls = {};
      if (parsed.sni) tls.serverName = parsed.sni;
      if (parsed.fingerprint) tls.fingerprint = parsed.fingerprint;
      if (parsed.alpn.length) tls.alpn = parsed.alpn;
      if (parsed.allowInsecure) tls.allowInsecure = true;
      ss.security = 'tls';
      ss.tlsSettings = tls;
    } else if (parsed.security === 'reality') {
      if (!parsed.publicKey) throw new Error('Reality 链接缺少 pbk（publicKey）参数');
      const reality = {
        serverName: parsed.sni,
        fingerprint: parsed.fingerprint || 'chrome',
        publicKey: parsed.publicKey,
        shortId: parsed.shortId,
        spiderX: parsed.spiderX
      };
      if (!reality.serverName) delete reality.serverName;
      ss.security = 'reality';
      ss.realitySettings = reality;
    } else if (parsed.security === 'xtls') {
      ss.security = 'xtls';
      ss.xtlsSettings = { serverName: parsed.sni, allowInsecure: parsed.allowInsecure };
    }

    switch (parsed.network) {
      case 'tcp': {
        if (parsed.headerType !== 'none') {
          const request = {};
          request.path = [parsed.path || '/'];
          request.headers = {};
          if (parsed.host) request.headers.Host = splitHosts(parsed.host);
          ss.tcpSettings = { header: { type: parsed.headerType === 'http' ? 'http' : parsed.headerType } };
          if (parsed.headerType === 'http') ss.tcpSettings.header.request = request;
        }
        break;
      }
      case 'ws': {
        const ws = { path: parsed.path || '/' };
        if (parsed.host) ws.headers = { Host: parsed.host };
        if (parsed.maxEarlyData) ws.maxEarlyData = Number(parsed.maxEarlyData);
        if (parsed.earlyDataHeaderName) ws.earlyDataHeaderName = parsed.earlyDataHeaderName;
        ss.wsSettings = ws;
        break;
      }
      case 'grpc': {
        const grpc = { serviceName: parsed.serviceName || '' };
        if (parsed.host) grpc.authority = parsed.host;
        if (parsed.mode === 'multi') grpc.multiMode = true;
        ss.grpcSettings = grpc;
        break;
      }
      case 'http': {
        const http = { path: parsed.path || '/' };
        if (parsed.host) http.host = splitHosts(parsed.host);
        ss.httpSettings = http;
        break;
      }
      case 'httpupgrade': {
        const upgrade = { path: parsed.path || '/' };
        if (parsed.host) upgrade.host = parsed.host;
        ss.httpupgradeSettings = upgrade;
        break;
      }
      case 'xhttp': {
        const xhttp = { path: parsed.path || '/' };
        if (parsed.host) xhttp.host = parsed.host;
        if (parsed.mode) xhttp.mode = parsed.mode;
        ss.xhttpSettings = xhttp;
        break;
      }
      case 'kcp': {
        const kcp = {
          mtu: 1350,
          tti: 20,
          uplinkCapacity: 5,
          downlinkCapacity: 20,
          congestion: false,
          readBufferSize: 1,
          writeBufferSize: 1,
          header: { type: parsed.headerType || 'none' }
        };
        if (parsed.seed) kcp.seed = parsed.seed;
        ss.kcpSettings = kcp;
        break;
      }
      case 'quic': {
        ss.quicSettings = {
          security: parsed.quicSecurity || 'none',
          key: parsed.quicKey || '',
          header: { type: parsed.headerType || 'none' }
        };
        break;
      }
    }

    return ss;
  }

  function buildMeta(parsed) {
    const items = [
      { label: '备注', value: parsed.remark },
      { label: '服务器', value: formatHost(parsed.address) + ':' + parsed.port },
      { label: 'UUID', value: parsed.uuid, mono: true },
      { label: '传输方式', value: parsed.network },
      { label: '安全类型', value: parsed.security },
      { label: '流控', value: parsed.flow },
      { label: 'SNI', value: parsed.sni },
      { label: '指纹', value: parsed.fingerprint },
      { label: '公钥 pbk', value: parsed.publicKey, mono: true },
      { label: 'ShortId', value: parsed.shortId, mono: true },
      { label: '路径', value: parsed.path },
      { label: 'Host', value: parsed.host },
      { label: '服务名', value: parsed.serviceName },
      { label: '模式', value: parsed.mode }
    ];
    return items.filter((item) => item.value !== '' && item.value !== undefined && item.value !== null);
  }

  function resolveOptions(options) {
    const source = options && typeof options === 'object' ? options : {};
    const resolved = {};
    for (const key of Object.keys(OPTION_DEFAULTS)) {
      resolved[key] = source[key] === undefined ? OPTION_DEFAULTS[key] : Boolean(source[key]);
    }
    return resolved;
  }

  function buildXrayConfig(input, options) {
    const parsed = typeof input === 'string' ? parseVlessLink(input) : input;
    const opts = resolveOptions(options);

    const user = { id: parsed.uuid, encryption: parsed.encryption || 'none' };
    if (parsed.flow) user.flow = parsed.flow;
    if (parsed.packetEncoding) user.packetEncoding = parsed.packetEncoding;

    const outbound = {
      tag: parsed.remark || 'vless-out',
      protocol: 'vless',
      settings: {
        vnext: [{
          address: parsed.address,
          port: parsed.port,
          users: [user]
        }]
      },
      streamSettings: buildStreamSettings(parsed)
    };

    const inbounds = [{
      tag: 'socks-in',
      listen: '127.0.0.1',
      port: 10808,
      protocol: 'socks',
      settings: { auth: 'noauth', udp: true }
    }];

    if (opts.mixed) {
      inbounds.push({
        tag: 'mixed-in',
        port: 7890,
        listen: '127.0.0.1',
        protocol: 'mixed',
        settings: { udp: true }
      });
    }

    if (opts.sniffing) {
      for (const inbound of inbounds) {
        inbound.sniffing = { enabled: true, destOverride: ['http', 'tls', 'quic'] };
      }
    }

    const config = {
      log: { loglevel: 'warning' },
      inbounds,
      outbounds: [
        outbound,
        { tag: 'direct', protocol: 'freedom' },
        { tag: 'block', protocol: 'blackhole' }
      ]
    };

    if (opts.lanDirect) {
      config.routing = {
        domainStrategy: 'IPIfNonMatch',
        rules: [
          { type: 'field', ip: ['geoip:private'], outboundTag: 'direct' },
          { type: 'field', network: 'tcp,udp', outboundTag: outbound.tag }
        ]
      };
    }

    return { config, meta: buildMeta(parsed), remark: parsed.remark };
  }

  function findVlessOutbound(config) {
    if (!config || typeof config !== 'object' || Array.isArray(config)) {
      throw new Error('配置必须是一个 JSON 对象');
    }
    const isVless = (item) =>
      item && typeof item === 'object' && String(item.protocol || '').toLowerCase() === 'vless';

    if (Array.isArray(config.outbounds)) {
      const found = config.outbounds.find(isVless);
      if (found) return found;
      throw new Error('outbounds 中没有 protocol 为 “vless” 的出站配置');
    }
    if (isVless(config)) return config;
    if (isVless(config.outbound)) return config.outbound;
    throw new Error('未找到 VLESS 出站配置（outbounds / outbound）');
  }

  function outboundToLink(outbound) {
    const settings = outbound.settings || {};
    const vnext = Array.isArray(settings.vnext) ? settings.vnext[0] : null;
    const server = vnext || (settings.address ? settings : null);
    if (!server) throw new Error('VLESS 出站缺少 settings.vnext 或 address');

    const address = String(server.address || server.host || '').trim();
    if (!address) throw new Error('出站缺少服务器地址 address');
    const port = parsePort(server.port);

    const user = (Array.isArray(server.users) && server.users[0]) || {};
    const uuid = String(user.id || user.uuid || '').trim();
    if (!uuid) throw new Error('出站缺少用户 id（UUID）');

    const ss = outbound.streamSettings || {};
    const network = String(ss.network || 'tcp').toLowerCase();
    const security = String(ss.security || 'none').toLowerCase();
    const tls = ss.tlsSettings || {};
    const reality = ss.realitySettings || {};
    const ws = ss.wsSettings || {};
    const grpc = ss.grpcSettings || {};
    const http = ss.httpSettings || {};
    const upgrade = ss.httpupgradeSettings || {};
    const xhttp = ss.xhttpSettings || {};
    const tcp = ss.tcpSettings || {};
    const kcp = ss.kcpSettings || {};
    const quic = ss.quicSettings || {};

    const params = [];
    const add = (key, value) => {
      if (value !== undefined && value !== null && value !== '') {
        params.push([key, String(value)]);
      }
    };

    add('encryption', user.encryption || 'none');
    add('security', security);
    add('type', network);
    add('flow', user.flow);

    const sni = tls.serverName || reality.serverName || '';
    add('sni', sni);
    add('fp', tls.fingerprint || reality.fingerprint);
    add('alpn', Array.isArray(tls.alpn) ? tls.alpn.join(',') : tls.alpn);
    add('allowInsecure', tls.allowInsecure ? 'true' : '');
    add('pbk', reality.publicKey);
    add('sid', reality.shortId);
    add('spx', reality.spiderX);
    add('packetEncoding', user.packetEncoding);

    if (network === 'tcp') {
      const headerType = tcp.header && tcp.header.type ? tcp.header.type : '';
      if (headerType && headerType !== 'none') add('headerType', headerType);
      if (headerType === 'http') {
        const request = (tcp.header && tcp.header.request) || {};
        add('path', Array.isArray(request.path) ? request.path[0] : request.path);
        const hostHeader = (request.headers && request.headers.Host) || request.headers.host;
        add('host', Array.isArray(hostHeader) ? hostHeader.join(',') : hostHeader);
      }
    } else if (network === 'ws') {
      add('path', ws.path);
      const wsHost = ws.headers && (ws.headers.Host || ws.headers.host);
      add('host', Array.isArray(wsHost) ? wsHost.join(',') : wsHost);
      add('ed', ws.maxEarlyData);
      add('eh', ws.earlyDataHeaderName);
    } else if (network === 'grpc') {
      add('serviceName', grpc.serviceName);
      add('host', grpc.authority);
      add('mode', grpc.multiMode ? 'multi' : '');
    } else if (network === 'http') {
      add('path', http.path);
      add('host', Array.isArray(http.host) ? http.host.join(',') : http.host);
    } else if (network === 'httpupgrade') {
      add('path', upgrade.path);
      add('host', Array.isArray(upgrade.host) ? upgrade.host.join(',') : upgrade.host);
    } else if (network === 'xhttp') {
      add('path', xhttp.path);
      add('host', Array.isArray(xhttp.host) ? xhttp.host.join(',') : xhttp.host);
      add('mode', xhttp.mode);
    } else if (network === 'kcp') {
      add('headerType', kcp.header && kcp.header.type);
      add('seed', kcp.seed);
    } else if (network === 'quic') {
      add('quicSecurity', quic.security);
      add('key', quic.key);
      add('headerType', quic.header && quic.header.type);
    }

    const query = params
      .map(([key, value]) => key + '=' + encodeURIComponent(value))
      .join('&');
    const remark = String(outbound.tag || '').trim();
    const link = 'vless://' + uuid + '@' + formatHost(address) + ':' + port +
      (query ? '?' + query : '') +
      (remark ? '#' + encodeURIComponent(remark) : '');

    const parsed = {
      remark,
      uuid,
      address,
      port,
      network,
      security,
      flow: user.flow || '',
      sni,
      fingerprint: tls.fingerprint || reality.fingerprint || '',
      publicKey: reality.publicKey || '',
      shortId: reality.shortId || '',
      path: network === 'ws' ? ws.path || '' : (http.path || upgrade.path || xhttp.path || ''),
      host: network === 'ws'
        ? (ws.headers && (ws.headers.Host || ws.headers.host)) || ''
        : (http.host ? (Array.isArray(http.host) ? http.host.join(',') : http.host) : (upgrade.host || xhttp.host || '')),
      serviceName: grpc.serviceName || '',
      mode: xhttp.mode || (grpc.multiMode ? 'multi' : '')
    };

    return { link, meta: buildMeta(parsed) };
  }

  function stripJsonNoise(source) {
    let text = source.replace(/^\uFEFF/, '');
    let out = '';
    let inString = false;
    let escaped = false;

    for (let i = 0; i < text.length; i++) {
      const ch = text[i];
      const next = text[i + 1];

      if (inString) {
        out += ch;
        if (escaped) escaped = false;
        else if (ch === '\\') escaped = true;
        else if (ch === '"') inString = false;
        continue;
      }

      if (ch === '"') {
        inString = true;
        out += ch;
        continue;
      }

      if (ch === '/' && next === '/') {
        while (i < text.length && text[i] !== '\n') i++;
        out += '\n';
        continue;
      }

      if (ch === '/' && next === '*') {
        i += 2;
        while (i < text.length && !(text[i] === '*' && text[i + 1] === '/')) i++;
        i++;
        continue;
      }

      out += ch;
    }

    let cleaned = '';
    inString = false;
    escaped = false;

    for (let i = 0; i < out.length; i++) {
      const ch = out[i];
      if (inString) {
        cleaned += ch;
        if (escaped) escaped = false;
        else if (ch === '\\') escaped = true;
        else if (ch === '"') inString = false;
        continue;
      }

      if (ch === '"') {
        inString = true;
        cleaned += ch;
        continue;
      }

      if (ch === ',') {
        let j = i + 1;
        while (j < out.length && /\s/.test(out[j])) j++;
        if (out[j] === '}' || out[j] === ']') continue;
      }

      cleaned += ch;
    }

    return cleaned;
  }

  function parseJsonConfig(text) {
    if (!text || !String(text).trim()) throw new Error('请先粘贴 Xray 配置');
    try {
      return JSON.parse(String(text));
    } catch (firstError) {
      try {
        return JSON.parse(stripJsonNoise(String(text)));
      } catch (secondError) {
        throw new Error('JSON 解析失败：' + firstError.message);
      }
    }
  }

  function configToLink(input) {
    const config = typeof input === 'string' ? parseJsonConfig(input) : input;
    return outboundToLink(findVlessOutbound(config));
  }

  return {
    parseVlessLink,
    buildXrayConfig,
    configToLink,
    findVlessOutbound,
    outboundToLink,
    parseJsonConfig
  };
})();

if (typeof module !== 'undefined' && module.exports) {
  module.exports = VlessConverter;
}

if (typeof document !== 'undefined') {
  const SAMPLE_LINK = 'vless://31a9cbc0-17df-460a-a8e4-2f52e7765863@43.213.64.132:62045?encryption=none&security=reality&flow=xtls-rprx-vision&type=tcp&sni=dash.cloudflare.com&pbk=OX_qPxc4o27C96Y9F9K5ZLB7Be17w8Q9dAmhovxs9Ug&fp=chrome#233boy-tcp-43.213.64.132';
  const THEME_KEY = 'xyvless-theme';

  function initApp() {
    const dom = {
      themeToggle: document.getElementById('themeToggle'),
      themeIcon: document.getElementById('themeIcon'),
      alert: document.getElementById('alert'),
      alertIcon: document.getElementById('alertIcon'),
      alertText: document.getElementById('alertText'),
      linkInput: document.getElementById('linkInput'),
      jsonBox: document.getElementById('jsonBox'),
      jsonStatus: document.getElementById('jsonStatus'),
      metaSection: document.getElementById('metaSection'),
      metaGrid: document.getElementById('metaGrid'),
      btnSample: document.getElementById('btnSample'),
      btnClearLink: document.getElementById('btnClearLink'),
      btnClearJson: document.getElementById('btnClearJson'),
      btnLinkToJson: document.getElementById('btnLinkToJson'),
      btnJsonToLink: document.getElementById('btnJsonToLink'),
      btnSwap: document.getElementById('btnSwap'),
      btnFormatJson: document.getElementById('btnFormatJson'),
      btnCopyJson: document.getElementById('btnCopyJson'),
      btnDownloadJson: document.getElementById('btnDownloadJson'),
      optMixed: document.getElementById('optMixed'),
      optSniffing: document.getElementById('optSniffing'),
      optLanDirect: document.getElementById('optLanDirect')
    };

    let alertTimer = 0;
    let lastRemark = '';

    function applyTheme(theme) {
      document.documentElement.dataset.theme = theme;
      dom.themeIcon.className = theme === 'dark' ? 'fa-solid fa-moon' : 'fa-solid fa-sun';
      try {
        localStorage.setItem(THEME_KEY, theme);
      } catch (err) {
        /* 忽略隐私模式下的存储异常 */
      }
    }

    function showAlert(kind, text) {
      clearTimeout(alertTimer);
      dom.alert.hidden = false;
      dom.alert.className = 'alert ' + kind;
      dom.alertIcon.className = kind === 'error'
        ? 'fa-solid fa-circle-exclamation'
        : 'fa-solid fa-circle-check';
      dom.alertText.textContent = text;
      alertTimer = setTimeout(() => {
        dom.alert.hidden = true;
      }, kind === 'error' ? 6000 : 3000);
    }

    function renderMeta(meta) {
      dom.metaGrid.textContent = '';
      if (!meta || !meta.length) {
        dom.metaSection.hidden = true;
        return;
      }
      for (const item of meta) {
        const cell = document.createElement('div');
        cell.className = 'meta-item';

        const label = document.createElement('span');
        label.className = 'meta-label';
        label.textContent = item.label;

        const value = document.createElement('span');
        value.className = 'meta-value' + (item.mono ? ' mono' : '');
        value.textContent = item.value;
        value.title = item.value;

        cell.append(label, value);
        dom.metaGrid.append(cell);
      }
      dom.metaSection.hidden = false;
    }

    function setStatus(text) {
      dom.jsonStatus.textContent = text;
    }

    function readOptions() {
      return {
        mixed: dom.optMixed.checked,
        sniffing: dom.optSniffing.checked,
        lanDirect: dom.optLanDirect.checked
      };
    }

    function linkToConfig() {
      try {
        const result = VlessConverter.buildXrayConfig(dom.linkInput.value, readOptions());
        const json = JSON.stringify(result.config, null, 2);
        dom.jsonBox.value = json;
        lastRemark = result.remark || '';
        renderMeta(result.meta);
        setStatus('已生成 · ' + (json.length / 1024).toFixed(1) + ' KB');
        showAlert('success', '已生成 Xray 配置，可直接复制或下载');
      } catch (err) {
        showAlert('error', err.message);
      }
    }

    function configToLink() {
      try {
        const result = VlessConverter.configToLink(dom.jsonBox.value);
        dom.linkInput.value = result.link;
        const remarkMeta = result.meta.find((item) => item.label === '备注');
        lastRemark = remarkMeta ? remarkMeta.value : '';
        renderMeta(result.meta);
        setStatus('已还原 VLESS 链接');
        showAlert('success', '已还原 VLESS 分享链接');
      } catch (err) {
        showAlert('error', err.message);
      }
    }

    async function copyJson() {
      const text = dom.jsonBox.value.trim();
      if (!text) {
        showAlert('error', '请先生成或粘贴 Xray 配置');
        return;
      }
      try {
        if (navigator.clipboard && window.isSecureContext) {
          await navigator.clipboard.writeText(text);
        } else {
          const temp = document.createElement('textarea');
          temp.value = text;
          temp.style.position = 'fixed';
          temp.style.opacity = '0';
          document.body.appendChild(temp);
          temp.select();
          const ok = document.execCommand('copy');
          document.body.removeChild(temp);
          if (!ok) throw new Error('浏览器拒绝了复制操作');
        }
        showAlert('success', '配置已复制到剪贴板');
      } catch (err) {
        showAlert('error', '复制失败：' + err.message);
      }
    }

    function downloadJson() {
      const text = dom.jsonBox.value.trim();
      if (!text) {
        showAlert('error', '请先生成或粘贴 Xray 配置');
        return;
      }
      const safeName = (lastRemark || 'xray-config')
        .replace(/[\\/:*?"<>|\s]+/g, '-')
        .slice(0, 60) || 'xray-config';
      const blob = new Blob([text.endsWith('\n') ? text : text + '\n'], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = safeName + '.json';
      document.body.appendChild(anchor);
      anchor.click();
      document.body.removeChild(anchor);
      URL.revokeObjectURL(url);
      showAlert('success', '已开始下载 ' + safeName + '.json');
    }

    function formatJson() {
      try {
        const config = VlessConverter.parseJsonConfig(dom.jsonBox.value);
        const json = JSON.stringify(config, null, 2);
        dom.jsonBox.value = json;
        setStatus('已格式化 · ' + (json.length / 1024).toFixed(1) + ' KB');
        showAlert('success', 'JSON 已格式化');
      } catch (err) {
        showAlert('error', err.message);
      }
    }

    const storedTheme = (() => {
      try {
        return localStorage.getItem(THEME_KEY);
      } catch (err) {
        return null;
      }
    })();
    const prefersLight = window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches;
    applyTheme(storedTheme || (prefersLight ? 'light' : 'dark'));

    dom.themeToggle.addEventListener('click', () => {
      applyTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark');
    });

    dom.btnLinkToJson.addEventListener('click', linkToConfig);
    dom.btnJsonToLink.addEventListener('click', configToLink);

    dom.btnSample.addEventListener('click', () => {
      dom.linkInput.value = SAMPLE_LINK;
      linkToConfig();
    });

    dom.btnClearLink.addEventListener('click', () => {
      dom.linkInput.value = '';
      dom.linkInput.focus();
    });

    dom.btnClearJson.addEventListener('click', () => {
      dom.jsonBox.value = '';
      dom.jsonStatus.textContent = '等待转换';
      dom.metaSection.hidden = true;
    });

    dom.btnSwap.addEventListener('click', () => {
      const link = dom.linkInput.value;
      dom.linkInput.value = dom.jsonBox.value;
      dom.jsonBox.value = link;
      dom.metaSection.hidden = true;
      dom.jsonStatus.textContent = '已交换内容';
    });

    dom.btnFormatJson.addEventListener('click', formatJson);
    dom.btnCopyJson.addEventListener('click', copyJson);
    dom.btnDownloadJson.addEventListener('click', downloadJson);

    dom.linkInput.addEventListener('keydown', (event) => {
      if ((event.ctrlKey || event.metaKey) && event.key === 'Enter') {
        event.preventDefault();
        linkToConfig();
      }
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initApp);
  } else {
    initApp();
  }
}
