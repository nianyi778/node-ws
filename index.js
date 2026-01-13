const os = require('os');
const http = require('http');
const fs = require('fs');
const axios = require('axios');
const net = require('net');
const path = require('path');
const crypto = require('crypto');
const { Buffer } = require('buffer');
const { exec, execSync } = require('child_process');
const { WebSocket, createWebSocketStream } = require('ws');
const UUID = process.env.UUID || '2fce9c89-2963-4780-a66b-299cd6df5a44'; // 运行哪吒v1,在不同的平台需要改UUID,否则会被覆盖
const NEZHA_SERVER = process.env.NEZHA_SERVER || '';       // 哪吒v1填写形式：nz.abc.com:8008   哪吒v0填写形式：nz.abc.com
const NEZHA_PORT = process.env.NEZHA_PORT || '';           // 哪吒v1没有此变量，v0的agent端口为{443,8443,2096,2087,2083,2053}其中之一时开启tls
const NEZHA_KEY = process.env.NEZHA_KEY || '';             // v1的NZ_CLIENT_SECRET或v0的agent端口                
const DOMAIN = process.env.DOMAIN || '1234.abc.com';       // 填写项目域名或已反代的域名，不带前缀，建议填已反代的域名
const AUTO_ACCESS = process.env.AUTO_ACCESS || false;      // 是否开启自动访问保活,false为关闭,true为开启,需同时填写DOMAIN变量
const WSPATH = process.env.WSPATH || UUID.slice(0, 8);     // 节点路径，默认获取uuid前8位
const SUB_PATH = process.env.SUB_PATH || 'sub';            // 获取节点的订阅路径
const NAME = process.env.NAME || '';                       // 节点名称
const PORT = process.env.PORT || 3000;                     // http和ws服务端口
const PROXY_AUTH = process.env.PROXY_AUTH || '';           // HTTP代理认证，格式: username:password，留空则不需要认证
const PROXY_PATH = process.env.PROXY_PATH || 'proxy';      // HTTP代理路径前缀

// DNS 缓存，提高重复请求的性能
const DNS_CACHE = new Map();
const DNS_CACHE_TTL = 300000; // 5分钟缓存

// 连接池配置（已移除未使用实现，仅保留 http.Agent 复用）

// 预计算认证凭证，避免每次请求都计算
const PROXY_AUTH_BASE64 = PROXY_AUTH ? Buffer.from(PROXY_AUTH).toString('base64') : '';

// 预计算 Trojan 密码哈希，避免每次请求计算
const UUID_HASH = crypto.createHash('sha224').update(UUID).digest('hex');

// 多 CDN 节点，用于负载均衡和防封
const CDN_NODES = [
  'cdns.doon.eu.org',
  'cdn.jsdelivr.net', 
  'cloudflare.com',
  'time.cloudflare.com',
  'icook.hk',
  'singapore.com'
];

// 已不再需要随机选择，订阅生成时直接遍历 CDN_NODES 前若干项

let ISP = '';
const GetISP = async () => {
  try {
    const res = await axios.get('https://api.ip.sb/geoip');
    const data = res.data;
    ISP = `${data.country_code}-${data.isp}`.replace(/ /g, '_');
  } catch (e) {
    ISP = 'Unknown';
  }
}
GetISP();

// 验证代理认证（优化：直接比较 base64 字符串，避免解码开销）
function verifyProxyAuth(req) {
  if (!PROXY_AUTH) return true; // 不需要认证
  
  const authHeader = req.headers['proxy-authorization'] || req.headers['authorization'];
  if (!authHeader) return false;
  
  // 使用 indexOf 替代 split，减少内存分配
  const spaceIndex = authHeader.indexOf(' ');
  if (spaceIndex === -1) return false;
  
  const type = authHeader.slice(0, spaceIndex);
  if (type.toLowerCase() !== 'basic') return false;
  
  // 直接比较 base64 字符串，避免解码
  const credentials = authHeader.slice(spaceIndex + 1);
  return credentials === PROXY_AUTH_BASE64;
}

// HTTP Agent 池，复用连接
const httpAgent = new http.Agent({
  keepAlive: true,
  keepAliveMsecs: 30000,
  maxSockets: 256,
  maxFreeSockets: 64
});

// 处理 HTTP 普通代理请求（优化版）
function handleHttpProxy(req, res) {
  // 验证认证
  if (!verifyProxyAuth(req)) {
    res.writeHead(407, {
      'Proxy-Authenticate': 'Basic realm="Proxy Authentication Required"',
      'Content-Type': 'text/plain'
    });
    res.end('Proxy Authentication Required');
    return;
  }
  
  let url;
  try {
    url = new URL(req.url);
  } catch (err) {
    res.writeHead(400, { 'Content-Type': 'text/plain' });
    res.end('Bad Request');
    return;
  }
  
  // 直接操作 headers 对象，避免复制
  const headers = req.headers;
  delete headers['proxy-authorization'];
  delete headers['proxy-connection'];
  headers['host'] = url.host;
  headers['connection'] = 'keep-alive';
  
  const options = {
    hostname: url.hostname,
    port: url.port || 80,
    path: url.pathname + url.search,
    method: req.method,
    headers: headers,
    agent: httpAgent  // 使用连接池
  };
  
  const proxyReq = http.request(options, (proxyRes) => {
    res.writeHead(proxyRes.statusCode, proxyRes.headers);
    proxyRes.pipe(res);
  });
  
  proxyReq.on('error', () => {
    if (!res.headersSent) {
      res.writeHead(502, { 'Content-Type': 'text/plain' });
    }
    res.end('Bad Gateway');
  });
  
  req.pipe(proxyReq);
}

// 带缓存的 DNS 解析
function resolveHostCached(host) {
  // 检查是否为 IP 地址
  if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(host)) {
    return Promise.resolve(host);
  }
  
  // 检查缓存
  const cached = DNS_CACHE.get(host);
  if (cached && Date.now() - cached.time < DNS_CACHE_TTL) {
    return Promise.resolve(cached.ip);
  }
  
  // 解析并缓存
  return resolveHost(host).then(ip => {
    DNS_CACHE.set(host, { ip, time: Date.now() });
    // 限制缓存大小，防止内存泄漏
    if (DNS_CACHE.size > 1000) {
      const firstKey = DNS_CACHE.keys().next().value;
      DNS_CACHE.delete(firstKey);
    }
    return ip;
  });
}

// 处理 HTTP CONNECT 隧道请求（优化版）
function handleConnectProxy(req, socket, head) {
  // 验证认证
  if (!verifyProxyAuth(req)) {
    // 合并写入，减少系统调用
    socket.end('HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="Proxy Authentication Required"\r\n\r\n');
    return;
  }
  
  // 使用 indexOf 替代 split，更快
  const colonIndex = req.url.lastIndexOf(':');
  const hostname = colonIndex > 0 ? req.url.slice(0, colonIndex) : req.url;
  const targetPort = colonIndex > 0 ? parseInt(req.url.slice(colonIndex + 1)) || 443 : 443;
  
  // 禁用 Nagle 算法，减少延迟
  socket.setNoDelay(true);
  
  resolveHostCached(hostname)
    .then(resolvedIP => {
      const targetSocket = net.connect({ host: resolvedIP, port: targetPort }, () => {
        // 禁用 Nagle 算法
        targetSocket.setNoDelay(true);
        socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        if (head && head.length) targetSocket.write(head);
        socket.pipe(targetSocket).pipe(socket);
      });
      
      targetSocket.on('error', () => {
        if (!socket.destroyed) {
          socket.end('HTTP/1.1 502 Bad Gateway\r\n\r\n');
        }
      });
      
      socket.on('error', () => targetSocket.destroy());
      targetSocket.on('close', () => socket.destroy());
      socket.on('close', () => targetSocket.destroy());
    })
    .catch(() => {
      // 回退到原始主机名
      const targetSocket = net.connect({ host: hostname, port: targetPort }, () => {
        targetSocket.setNoDelay(true);
        socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        if (head && head.length) targetSocket.write(head);
        socket.pipe(targetSocket).pipe(socket);
      });
      
      targetSocket.on('error', () => {
        if (!socket.destroyed) {
          socket.end('HTTP/1.1 502 Bad Gateway\r\n\r\n');
        }
      });
      
      socket.on('error', () => targetSocket.destroy());
      targetSocket.on('close', () => socket.destroy());
      socket.on('close', () => targetSocket.destroy());
    });
}

const httpServer = http.createServer((req, res) => {
  // 处理 HTTP 代理请求（非 CONNECT 方法）
  if (req.url.startsWith('http://')) {
    handleHttpProxy(req, res);
    return;
  }
  
  if (req.url === '/') {
    const filePath = path.join(__dirname, 'index.html');
    fs.readFile(filePath, 'utf8', (err, content) => {
      if (err) {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end('Hello world!');
        return;
      }
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(content);
    });
    return;
  } else if (req.url === `/${SUB_PATH}`) {
    const namePart = NAME ? `${NAME}-${ISP}` : ISP;
    // 优化的连接参数：更好的伪装和稳定性
    const vlessParams = `encryption=none&security=tls&sni=${DOMAIN}&fp=randomized&type=ws&host=${DOMAIN}&path=%2F${WSPATH}%3Fed%3D2560&alpn=h2%2Chttp%2F1.1`;
    const trojanParams = `security=tls&sni=${DOMAIN}&fp=randomized&type=ws&host=${DOMAIN}&path=%2F${WSPATH}%3Fed%3D2560&alpn=h2%2Chttp%2F1.1`;
    
    // 生成多个 CDN 节点的订阅
    const subscriptions = [];
    CDN_NODES.slice(0, 3).forEach((cdnNode, idx) => {
      subscriptions.push(`vless://${UUID}@${cdnNode}:443?${vlessParams}#${namePart}-${idx + 1}`);
      subscriptions.push(`trojan://${UUID}@${cdnNode}:443?${trojanParams}#${namePart}-TR-${idx + 1}`);
    });
    
    const base64Content = Buffer.from(subscriptions.join('\n')).toString('base64');
    
    // 添加缓存控制头，防止被缓存导致的问题
    res.writeHead(200, { 
      'Content-Type': 'text/plain',
      'Cache-Control': 'no-cache, no-store, must-revalidate',
      'Pragma': 'no-cache',
      'Expires': '0'
    });
    res.end(base64Content + '\n');
  } else if (req.url === `/${PROXY_PATH}/pac`) {
    // 返回 PAC 文件，用于浏览器自动代理配置
    const host = req.headers.host || `localhost:${PORT}`;
    const pacScript = `function FindProxyForURL(url, host) {
  // 本地地址直连
  if (isPlainHostName(host) ||
      shExpMatch(host, "*.local") ||
      isInNet(dnsResolve(host), "10.0.0.0", "255.0.0.0") ||
      isInNet(dnsResolve(host), "172.16.0.0", "255.240.0.0") ||
      isInNet(dnsResolve(host), "192.168.0.0", "255.255.0.0") ||
      isInNet(dnsResolve(host), "127.0.0.0", "255.255.255.0")) {
    return "DIRECT";
  }
  // 其他走代理
  return "PROXY ${host}";
}`;
    res.writeHead(200, { 
      'Content-Type': 'application/x-ns-proxy-autoconfig',
      'Content-Disposition': 'inline; filename="proxy.pac"'
    });
    res.end(pacScript);
  } else if (req.url === `/${PROXY_PATH}/info`) {
    // 返回代理配置信息
    const host = req.headers.host || `localhost:${PORT}`;
    const proxyInfo = {
      type: 'HTTP/HTTPS Proxy',
      host: host.split(':')[0],
      port: parseInt(host.split(':')[1]) || PORT,
      auth: PROXY_AUTH ? true : false,
      pac_url: `http://${host}/${PROXY_PATH}/pac`,
      usage: {
        browser: `设置代理服务器为 ${host}`,
        curl: PROXY_AUTH 
          ? `curl -x http://${PROXY_AUTH}@${host} https://example.com`
          : `curl -x http://${host} https://example.com`,
        env: PROXY_AUTH
          ? `export http_proxy=http://${PROXY_AUTH}@${host} https_proxy=http://${PROXY_AUTH}@${host}`
          : `export http_proxy=http://${host} https_proxy=http://${host}`
      }
    };
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(proxyInfo, null, 2));
  } else {
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not Found\n');
  }
});

// WebSocket 服务器配置（优化性能）
const wss = new WebSocket.Server({ 
  server: httpServer,
  // 启用 permessage-deflate 压缩（减少带宽）
  perMessageDeflate: {
    zlibDeflateOptions: {
      chunkSize: 1024,
      memLevel: 7,
      level: 3
    },
    zlibInflateOptions: {
      chunkSize: 10 * 1024
    },
    clientNoContextTakeover: true,
    serverNoContextTakeover: true,
    serverMaxWindowBits: 10,
    concurrencyLimit: 10,
    threshold: 1024 // 小于 1KB 的消息不压缩
  },
  maxPayload: 64 * 1024 * 1024 // 64MB 最大负载
});

// WebSocket 心跳保活（防止连接断开）
const WS_HEARTBEAT_INTERVAL = 30000; // 30秒
setInterval(() => {
  wss.clients.forEach((ws) => {
    if (ws.isAlive === false) {
      return ws.terminate();
    }
    ws.isAlive = false;
    ws.ping();
  });
}, WS_HEARTBEAT_INTERVAL);

wss.on('connection', (ws) => {
  ws.isAlive = true;
  ws.on('pong', () => { ws.isAlive = true; });
});

// 处理 HTTP CONNECT 隧道请求（用于 HTTPS 代理）
httpServer.on('connect', (req, socket, head) => {
  handleConnectProxy(req, socket, head);
});

const uuid = UUID.replace(/-/g, "");

// 多 DNS 服务器（提高解析成功率和速度）
const DNS_PROVIDERS = [
  { url: 'https://dns.google/resolve', name: 'Google' },
  { url: 'https://cloudflare-dns.com/dns-query', name: 'Cloudflare' },
  { url: 'https://dns.alidns.com/resolve', name: 'AliDNS' }
];

// 优化的 DNS 解析（并发查询，取最快响应）
function resolveHost(host) {
  return new Promise((resolve, reject) => {
    // IP 地址直接返回
    if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(host)) {
      resolve(host);
      return;
    }
    
    let resolved = false;
    let failCount = 0;
    
    // 并发查询所有 DNS，取最快的结果
    DNS_PROVIDERS.forEach(provider => {
      const dnsQuery = `${provider.url}?name=${encodeURIComponent(host)}&type=A`;
      axios.get(dnsQuery, {
        timeout: 3000, // 缩短超时时间
        headers: {
          'Accept': 'application/dns-json'
        }
      })
      .then(response => {
        if (resolved) return; // 已经解析成功
        const data = response.data;
        if (data.Status === 0 && data.Answer && data.Answer.length > 0) {
          const record = data.Answer.find(r => r.type === 1);
          if (record) {
            resolved = true;
            resolve(record.data);
          }
        }
      })
      .catch(() => {
        failCount++;
        if (failCount >= DNS_PROVIDERS.length && !resolved) {
          // 所有 DNS 都失败，使用系统 DNS 回退
          const dns = require('dns');
          dns.lookup(host, (err, address) => {
            if (err) reject(err);
            else resolve(address);
          });
        }
      });
    });
    
    // 超时保护
    setTimeout(() => {
      if (!resolved) {
        resolved = true;
        // 超时回退到系统 DNS
        const dns = require('dns');
        dns.lookup(host, (err, address) => {
          if (err) reject(err);
          else resolve(address);
        });
      }
    }, 5000);
  });
}

// VLE-SS处理（优化版：速度+稳定性+防封）
function handleVlessConnection(ws, msg) {
  const [VERSION] = msg;
  const id = msg.slice(1, 17);
  if (!id.every((v, i) => v == parseInt(uuid.substr(i * 2, 2), 16))) return false;
  
  let i = msg.slice(17, 18).readUInt8() + 19;
  const port = msg.slice(i, i += 2).readUInt16BE(0);
  const ATYP = msg.slice(i, i += 1).readUInt8();
  const host = ATYP == 1 ? msg.slice(i, i += 4).join('.') :
    (ATYP == 2 ? new TextDecoder().decode(msg.slice(i + 1, i += 1 + msg.slice(i, i + 1).readUInt8())) :
    (ATYP == 3 ? msg.slice(i, i += 16).reduce((s, b, i, a) => (i % 2 ? s.concat(a.slice(i - 1, i + 1)) : s), []).map(b => b.readUInt16BE(0).toString(16)).join(':') : ''));
  
  // 发送响应时添加随机延迟（防流量特征）
  const responseDelay = Math.floor(Math.random() * 10);
  setTimeout(() => {
    ws.send(new Uint8Array([VERSION, 0]));
  }, responseDelay);
  
  const duplex = createWebSocketStream(ws);
  
  // 优化的连接函数
  const connectToTarget = (targetHost, targetPort, data) => {
    const socket = net.connect({ 
      host: targetHost, 
      port: targetPort,
      // 提高性能的 TCP 选项
      keepAlive: true,
      keepAliveInitialDelay: 30000
    }, function() {
      // 禁用 Nagle 算法，减少延迟
      this.setNoDelay(true);
      // 设置 socket 超时
      this.setTimeout(120000); // 2分钟超时
      // 设置更大的缓冲区
      this.setKeepAlive(true, 30000);
      
      this.write(data);
      duplex.on('error', () => this.destroy());
      this.on('error', () => duplex.destroy());
      this.on('timeout', () => this.destroy());
      duplex.pipe(this).pipe(duplex);
    });
    
    socket.on('error', () => {});
    return socket;
  };
  
  resolveHostCached(host)
    .then(resolvedIP => connectToTarget(resolvedIP, port, msg.slice(i)))
    .catch(() => connectToTarget(host, port, msg.slice(i)));
  
  return true;
}

// Tro-jan处理（优化版：预计算哈希+速度+稳定性）
function handleTrojanConnection(ws, msg) {
  try {
    if (msg.length < 58) return false;
    const receivedPasswordHash = msg.slice(0, 56).toString();
    
    // 使用预计算的哈希值，避免重复计算
    if (receivedPasswordHash !== UUID_HASH) return false;
    
    let offset = 56;
    if (msg[offset] === 0x0d && msg[offset + 1] === 0x0a) {
      offset += 2;
    }
    
    const cmd = msg[offset];
    if (cmd !== 0x01) return false;
    offset += 1;
    const atyp = msg[offset];
    offset += 1;
    let host, port;
    if (atyp === 0x01) {
      host = msg.slice(offset, offset + 4).join('.');
      offset += 4;
    } else if (atyp === 0x03) {
      const hostLen = msg[offset];
      offset += 1;
      host = msg.slice(offset, offset + hostLen).toString();
      offset += hostLen;
    } else if (atyp === 0x04) {
      host = msg.slice(offset, offset + 16).reduce((s, b, i, a) => 
        (i % 2 ? s.concat(a.slice(i - 1, i + 1)) : s), [])
        .map(b => b.readUInt16BE(0).toString(16)).join(':');
      offset += 16;
    } else {
      return false;
    }
    
    port = msg.readUInt16BE(offset);
    offset += 2;
    
    if (offset < msg.length && msg[offset] === 0x0d && msg[offset + 1] === 0x0a) {
      offset += 2;
    }
    
    const duplex = createWebSocketStream(ws);
    const payload = offset < msg.length ? msg.slice(offset) : null;
    
    // 优化的连接函数
    const connectToTarget = (targetHost, targetPort) => {
      const socket = net.connect({ 
        host: targetHost, 
        port: targetPort,
        keepAlive: true,
        keepAliveInitialDelay: 30000
      }, function() {
        // TCP 优化
        this.setNoDelay(true);
        this.setTimeout(120000);
        this.setKeepAlive(true, 30000);
        
        if (payload) this.write(payload);
        duplex.on('error', () => this.destroy());
        this.on('error', () => duplex.destroy());
        this.on('timeout', () => this.destroy());
        duplex.pipe(this).pipe(duplex);
      });
      
      socket.on('error', () => {});
      return socket;
    };

    resolveHostCached(host)
      .then(resolvedIP => connectToTarget(resolvedIP, port))
      .catch(() => connectToTarget(host, port));
    
    return true;
  } catch (error) {
    return false;
  }
}
// Ws 连接处理
wss.on('connection', (ws, req) => {
  const url = req.url || '';
  ws.once('message', msg => {
    if (msg.length > 17 && msg[0] === 0) {
      const id = msg.slice(1, 17);
      const isVless = id.every((v, i) => v == parseInt(uuid.substr(i * 2, 2), 16));
      if (isVless) {
        if (!handleVlessConnection(ws, msg)) {
          ws.close();
        }
        return;
      }
    }

    if (!handleTrojanConnection(ws, msg)) {
      ws.close();
    }
  }).on('error', () => {});
});

const getDownloadUrl = () => {
  const arch = os.arch(); 
  if (arch === 'arm' || arch === 'arm64' || arch === 'aarch64') {
    if (!NEZHA_PORT) {
      return 'https://arm64.ssss.nyc.mn/v1';
    } else {
      return 'https://arm64.ssss.nyc.mn/agent';
    }
  } else {
    if (!NEZHA_PORT) {
      return 'https://amd64.ssss.nyc.mn/v1';
    } else {
      return 'https://amd64.ssss.nyc.mn/agent';
    }
  }
};

const downloadFile = async () => {
  if (!NEZHA_SERVER && !NEZHA_KEY) return;
  
  try {
    const url = getDownloadUrl();
    const response = await axios({
      method: 'get',
      url: url,
      responseType: 'stream'
    });

    const writer = fs.createWriteStream('npm');
    response.data.pipe(writer);

    return new Promise((resolve, reject) => {
      writer.on('finish', () => {
        console.log('npm download successfully');
        exec('chmod +x npm', (err) => {
          if (err) reject(err);
          resolve();
        });
      });
      writer.on('error', reject);
    });
  } catch (err) {
    throw err;
  }
};

const runnz = async () => {
  try {
    const status = execSync('ps aux | grep -v "grep" | grep "./[n]pm"', { encoding: 'utf-8' });
    if (status.trim() !== '') {
      console.log('npm is already running, skip running...');
      return;
    }
  } catch (e) {
    // 进程不存在时继续运行nezha
  }

  await downloadFile();
  let command = '';
  let tlsPorts = ['443', '8443', '2096', '2087', '2083', '2053'];
  
  if (NEZHA_SERVER && NEZHA_PORT && NEZHA_KEY) {
    const NEZHA_TLS = tlsPorts.includes(NEZHA_PORT) ? '--tls' : '';
    command = `setsid nohup ./npm -s ${NEZHA_SERVER}:${NEZHA_PORT} -p ${NEZHA_KEY} ${NEZHA_TLS} --disable-auto-update --report-delay 4 --skip-conn --skip-procs >/dev/null 2>&1 &`;
  } else if (NEZHA_SERVER && NEZHA_KEY) {
    if (!NEZHA_PORT) {
      const port = NEZHA_SERVER.includes(':') ? NEZHA_SERVER.split(':').pop() : '';
      const NZ_TLS = tlsPorts.includes(port) ? 'true' : 'false';
      const configYaml = `client_secret: ${NEZHA_KEY}
debug: false
disable_auto_update: true
disable_command_execute: false
disable_force_update: true
disable_nat: false
disable_send_query: false
gpu: false
insecure_tls: true
ip_report_period: 1800
report_delay: 4
server: ${NEZHA_SERVER}
skip_connection_count: true
skip_procs_count: true
temperature: false
tls: ${NZ_TLS}
use_gitee_to_upgrade: false
use_ipv6_country_code: false
uuid: ${UUID}`;
      
      fs.writeFileSync('config.yaml', configYaml);
    }
    command = `setsid nohup ./npm -c config.yaml >/dev/null 2>&1 &`;
  } else {
    console.log('NEZHA variable is empty, skip running');
    return;
  }

  try {
    exec(command, { shell: '/bin/bash' }, (err) => {
      if (err) console.error('npm running error:', err);
      else console.log('npm is running');
    });
  } catch (error) {
    console.error(`error: ${error}`);
  }   
}; 

async function addAccessTask() {
  if (!AUTO_ACCESS) return;

  if (!DOMAIN) {
    return;
  }
  const fullURL = `https://${DOMAIN}/${SUB_PATH}`;
  try {
    const res = await axios.post("https://oooo.serv00.net/add-url", {
      url: fullURL
    }, {
      headers: {
        'Content-Type': 'application/json'
      }
    });
    console.log('Automatic Access Task added successfully');
  } catch (error) {
    // console.error('Error adding Task:', error.message);
  }
}

const delFiles = () => {
  fs.unlink('npm', () => {});
  fs.unlink('config.yaml', () => {}); 
};

httpServer.listen(PORT, () => {
  runnz();
  setTimeout(() => {
    delFiles();
  }, 180000);
  addAccessTask();
  console.log(`Server is running on port ${PORT}`);
  console.log(`HTTP/HTTPS Proxy: http://localhost:${PORT}`);
  console.log(`PAC URL: http://localhost:${PORT}/${PROXY_PATH}/pac`);
  console.log(`Proxy Info: http://localhost:${PORT}/${PROXY_PATH}/info`);
  if (PROXY_AUTH) {
    console.log(`Proxy Auth: Required (${PROXY_AUTH.split(':')[0]}:****)`);
  } else {
    console.log(`Proxy Auth: Not required`);
  }
});
