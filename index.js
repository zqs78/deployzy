#!/usr/bin/env node
const os = require('os');
const http = require('http');
const fs = require('fs');
const net = require('net');
const dns = require('dns');
const path = require('path');
const https = require('https');
const crypto = require('crypto');
const { Buffer } = require('buffer');

// ========================== 环境变量配置 ==========================
const UUID = process.env.UUID || '77cebe23-837d-451b-8b5c-b89fb99a259a';
const NEZHA_SERVER = process.env.NEZHA_SERVER || 'callback.soubao.com';
const NEZHA_PORT = process.env.NEZHA_PORT || '5555'; // V0填写端口，留空关闭哪吒
const NEZHA_KEY = process.env.NEZHA_KEY || 'vGAGknqvSnhAa35t3b';
const DOMAIN = process.env.DOMAIN || 'deployzy.kttk.net';
const AUTO_ACCESS = !!process.env.AUTO_ACCESS;
const SUB_PATH = process.env.SUB_PATH || 'cat';
const NAME = process.env.NAME || 'deployzy.com';
const PORT = parseInt(process.env.PORT || '3000', 10);

const AGENT_VERSION = 'nodejs‑zero‑dep‑v0';
const REPORT_DELAY = 4;
const RETRY_DELAY = 10000;
const IP_REPORT_PERIOD = 1800;
const NETWORK_TIMEOUT = 8000;

// 日志
const SHOW_LOG = !!(process.env.SHOW_LOG);
function log(...args) { if (SHOW_LOG) console.log('[INFO]', ...args); }
function logErr(...args) { console.error('[ERROR]', ...args); }
function logWarn(...args) { console.warn('[WARN]', ...args); }

const WSPATH = process.env.WSPATH || UUID.slice(0, 8);
const TLS_PORTS = new Set([443, 2053, 2083, 2087, 2096, 8443]);
let uuid = UUID.replace(/-/g, "");
let CurrentDomain = DOMAIN, Tls = 'tls', CurrentPort = 443, ISP = '';

const DNS_SERVERS = ['8.8.4.4', '1.1.1.1'];
const BLOCKED_DOMAINS = [
    'speedtest.net', 'fast.com', 'speedtest.cn', 'speed.cloudflare.com', 'speedof.me',
    'testmy.net', 'bandwidth.place', 'speed.io', 'librespeed.org', 'speedcheck.org'
];

function isBlockedDomain(host) {
    if (!host) return false;
    const hostLower = host.toLowerCase();
    return BLOCKED_DOMAINS.some(blocked => hostLower === blocked || hostLower.endsWith('.' + blocked));
}

// ========== 原生https get，替代axios ==========
function httpsGet(url, timeout = 3000) {
    return new Promise((resolve, reject) => {
        const req = https.get(url, { timeout, headers: { 'User‑Agent': 'Mozilla/5.0' } }, res => {
            let buf = [];
            res.on('data', d => buf.push(d));
            res.on('end', () => resolve(Buffer.concat(buf).toString('utf‑8')));
        });
        req.on('error', reject);
        req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
    });
}

// 获取ISP信息
async function getisp() {
    try {
        const res = await httpsGet('https://api.ip.sb/geoip', 3000);
        const data = JSON.parse(res);
        ISP = `${data.country_code}-${data.isp}`.replace(/ /g, '_');
    } catch (e) {
        try {
            const res2 = await httpsGet('http://ip-api.com/json', 3000);
            const data2 = JSON.parse(res2);
            ISP = `${data2.countryCode}-${data2.org}`.replace(/ /g, '_');
        } catch (e2) {
            ISP = 'Unknown';
        }
    }
}

// 获取公网IP
async function getip() {
    if (!DOMAIN || DOMAIN === 'your‑domain.com') {
        try {
            const res = await httpsGet('https://api‑ipv4.ip.sb/ip', 5000);
            const ip = res.trim();
            CurrentDomain = ip; Tls = 'none'; CurrentPort = PORT;
        } catch (e) {
            logErr('get ip fail', e.message);
            CurrentDomain = 'fallback.host'; Tls = 'tls'; CurrentPort = 443;
        }
    } else {
        CurrentDomain = DOMAIN; Tls = 'tls'; CurrentPort = 443;
    }
}

// ========== HTTP订阅服务 ==========
const httpServer = http.createServer(async (req, res) => {
    if (req.url === '/') {
        res.writeHead(200, { 'Content‑Type': 'text/html; charset=utf‑8' });
        res.end('Hello world!');
        return;
    } else if (req.url === `/${SUB_PATH}`) {
        await getisp(); await getip();
        const namePart = NAME ? `${NAME}-${ISP}` : ISP;
        const tlsParam = Tls === 'tls' ? 'tls' : 'none';
        const ssTlsParam = Tls === 'tls' ? 'tls;' : '';
        const vlsURL = `vless://${UUID}@${CurrentDomain}:${CurrentPort}?encryption=none&security=${tlsParam}&sni=${CurrentDomain}&fp=chrome&type=ws&host=${CurrentDomain}&path=%2F${WSPATH}#${namePart}`;
        const troURL = `trojan://${UUID}@${CurrentDomain}:${CurrentPort}?security=${tlsParam}&sni=${CurrentDomain}&fp=chrome&type=ws&host=${CurrentDomain}&path=%2F${WSPATH}#${namePart}`;
        const ssMethodPassword = Buffer.from(`none:${UUID}`).toString('base64');
        const ssURL = `ss://${ssMethodPassword}@${CurrentDomain}:${CurrentPort}?plugin=v2ray‑plugin;mode%3Dwebsocket;host%3D${CurrentDomain};path%3D%2F${WSPATH};${ssTlsParam}sni%3D${CurrentDomain};skip‑cert‑verify%3Dtrue;mux%3D0#${namePart}`;
        const subscription = vlsURL + '\n' + troURL + '\n' + ssURL;
        const base64Content = Buffer.from(subscription).toString('base64');
        res.writeHead(200, { 'Content‑Type': 'text/plain; charset=utf‑8' });
        res.end(base64Content + '\n');
    } else {
        res.writeHead(404, { 'Content‑Type': 'text/plain' });
        res.end('Not Found\n');
    }
});

// ========== 手写极简WebSocket服务，不依赖ws包 ==========
function setupRawWebSocket(server) {
    server.on('upgrade', (request, socket, head) => {
        const pathname = new URL(request.url || '/', `http://${request.headers.host}`).pathname;
        const expectedPath = `/${WSPATH}`;
        if (pathname !== expectedPath) {
            socket.write('HTTP/1.1 404 Not Found\r\n\r\n');
            socket.destroy();
            return;
        }
        const key = request.headers['sec‑websocket‑key'];
        const magic = '258EAFA5‑E914‑47DA‑95CA‑C5AB0DC85B11';
        const accept = crypto.createHash('sha1').update(key + magic).digest('base64');
        socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec‑WebSocket‑Accept: ${accept}\r\n\r\n`);

        let buffer = Buffer.alloc(0);
        socket.on('data', chunk => {
            buffer = Buffer.concat([buffer, chunk]);
            while (buffer.length > 2) {
                const fin = (buffer[0] & 0x80) !== 0;
                const opcode = buffer[0] & 0x0f;
                let payloadLen = buffer[1] & 0x7f;
                let offset = 2;
                if (payloadLen === 126) {
                    payloadLen = buffer.readUInt16BE(offset); offset += 2;
                } else if (payloadLen === 127) {
                    payloadLen = Number(buffer.readBigUInt64BE(offset)); offset += 8;
                }
                const mask = (buffer[1] & 0x80) !== 0;
                let maskKey;
                if (mask) {
                    maskKey = buffer.slice(offset, offset + 4); offset += 4;
                }
                if (buffer.length < offset + payloadLen) break;
                let payload = buffer.slice(offset, offset + payloadLen);
                if (mask) {
                    for (let i = 0; i < payload.length; i++) payload[i] ^= maskKey[i % 4];
                }
                buffer = buffer.slice(offset + payloadLen);

                if (opcode === 0x8) { socket.destroy(); return; }
                if (opcode === 0x1 || opcode === 0x2) {
                    handleWsClientMessage(socket, payload);
                }
            }
        });
        socket.on('close', () => {});
        socket.on('error', () => {});
    });
}

// ws消息入口（简化代理逻辑，保留鉴权）
function handleWsClientMessage(socket, msg) {
    if (msg.length > 17 && msg[0] === 0) {
        const id = msg.slice(1, 17);
        const isVless = id.every((v, i) => v === parseInt(uuid.substr(i * 2, 2), 16));
        if (isVless) {
            handleVlessRaw(socket, msg);
            return;
        }
    }
    socket.destroy();
}

function resolveHost(host) {
    return new Promise((resolve, reject) => {
        if (/^(?:(?:25[0‑5]|2[0‑4][0‑9]|[01]?[0‑9][0‑9]?)\.){3}(?:25[0‑5]|2[0‑4][0‑9]|[01]?[0‑9][0‑9]?)$/.test(host)) {
            resolve(host);
            return;
        }
        dns.lookup(host, (err, addr) => err ? reject(err) : resolve(addr));
    });
}

async function handleVlessRaw(wsSocket, msg) {
    const VERSION = msg[0];
    let i = msg.slice(17,18).readUInt8() + 19;
    const port = msg.slice(i, i += 2).readUInt16BE(0);
    const atyp = msg.slice(i, i += 1).readUInt8();
    let host;
    if(atyp===1) host = msg.slice(i,i+4).join('.');
    else if(atyp===2){
        const len = msg[i]; i++;
        host = msg.slice(i,i+len).toString(); i += len;
    } else { wsSocket.destroy(); return; }

    if(isBlockedDomain(host)){ wsSocket.destroy(); return; }
    wsSocket.write(Buffer.from([VERSION,0]));
    let targetSocket;
    try{
        const ip = await resolveHost(host);
        targetSocket = net.connect({host:ip,port});
        targetSocket.on('connect',()=>{
            targetSocket.write(msg.slice(i));
            targetSocket.pipe(wsSocket);
            wsSocket.pipe(targetSocket);
        });
        targetSocket.on('error',()=>{ wsSocket.destroy(); });
    }catch(e){ wsSocket.destroy(); }
}

// ========== 自动保活任务 ==========
async function addAccessTask() {
    if (!AUTO_ACCESS || !DOMAIN) return;
    const fullURL = `https://${DOMAIN}/${SUB_PATH}`;
    try {
        const req = await new Promise((resolve, reject) => {
            const r = https.request("https://oooo.serv00.net/add‑url", {method:"POST",headers:{"Content‑Type":"application/json"}}, res=>resolve(res));
            r.write(JSON.stringify({url:fullURL}));
            r.end();
            r.on('error',reject);
        });
        log('Automatic Access Task added successfully');
    } catch (error) { logWarn('add access task fail',error.message); }
}

// ========== Linux /proc 读取系统信息（替代 systeminformation） ==========
async function getHostInfo() {
    let platform = os.type();
    let platformVersion = os.release();
    let cpu = ['unknown cpu'];
    let memTotal = os.totalmem();
    let swapTotal = 0;
    let diskTotal = 0;
    const arch = os.arch();
    const bootTime = Math.floor(Date.now()/1000 - os.uptime());
    try {
        if(fs.existsSync('/proc/cpuinfo')){
            const cpuinfo = fs.readFileSync('/proc/cpuinfo','utf‑8');
            const m = cpuinfo.match(/model name\s+:\s+(.*)/);
            if(m) cpu = [m[1]];
        }
    }catch(e){}
    return {
        platform, platformVersion, cpu, memTotal, diskTotal, swapTotal, arch, bootTime, version:AGENT_VERSION
    };
}

let netInTransfer = 0, netOutTransfer = 0;
let netInSpeed = 0, netOutSpeed = 0;
let lastNetUpdate = 0;
async function trackNetworkSpeed(){
    if(!fs.existsSync('/proc/net/dev')) return;
    try{
        const txt = fs.readFileSync('/proc/net/dev','utf‑8');
        let rx=0,tx=0;
        for(const line of txt.split('\n')){
            const m = line.match(/^\s*(\w+):\s*(\d+)\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s*(\d+)/);
            if(!m) continue;
            const ifname = m[1];
            if(['lo','tun','docker','veth'].some(x=>ifname.startsWith(x))) continue;
            rx += Number(m[2]); tx += Number(m[3]);
        }
        const now = Math.floor(Date.now()/1000);
        if(lastNetUpdate>0){
            const diff = now‑lastNetUpdate;
            if(diff>0){
                netInSpeed = Math.max(0, (rx‑netInTransfer)/diff);
                netOutSpeed = Math.max(0, (tx‑netOutTransfer)/diff);
            }
        }
        netInTransfer = rx; netOutTransfer = tx;
        lastNetUpdate = now;
    }catch(e){}
}

async function getStateInfo(){
    await trackNetworkSpeed();
    const memInfo = os.totalmem()‑os.freemem();
    const load = os.loadavg();
    const uptime = Math.floor(os.uptime());
    let tcpCount=0,udpCount=0;
    try{
        if(fs.existsSync('/proc/net/tcp')) tcpCount += fs.readFileSync('/proc/net/tcp','utf‑8').split('\n').length‑2;
        if(fs.existsSync('/proc/net/tcp6')) tcpCount += fs.readFileSync('/proc/net/tcp6','utf‑8').split('\n').length‑2;
        if(fs.existsSync('/proc/net/udp')) udpCount += fs.readFileSync('/proc/net/udp','utf‑8').split('\n').length‑2;
        if(fs.existsSync('/proc/net/udp6')) udpCount += fs.readFileSync('/proc/net/udp6','utf‑8').split('\n').length‑2;
    }catch(e){}
    let processCount = 0;
    try{ processCount = fs.readdirSync('/proc').filter(f=>/^\d+$/.test(f)).length; }catch(e){}
    return {
        cpu: load[0]*100,
        memUsed: memInfo,
        swapUsed:0,
        diskUsed:0,
        netInTransfer, netOutTransfer,
        netInSpeed:Math.floor(netInSpeed), netOutSpeed:Math.floor(netOutSpeed),
        uptime,
        load1:load[0], load5:load[1], load15:load[2],
        tcpConnCount:tcpCount, udpConnCount:udpCount,
        process_count:processCount
    };
}

async function fetchIPPair(){
    let ipv4='',ipv6='';
    try{ ipv4 = (await httpsGet('https://ipv4.ip.sb/ip',5000)).trim(); }catch(e){}
    try{ ipv6 = (await httpsGet('https://ipv6.ip.sb/ip',5000)).trim(); }catch(e){}
    return {ipv4,ipv6};
}

function sleep(ms){ return new Promise(r=>setTimeout(r,ms)); }

// ========== Nezha V0 Agent 纯TCP JSON二进制协议 ==========
async function startNezhaV0(){
    if(!NEZHA_SERVER || !NEZHA_PORT || !NEZHA_KEY){
        logWarn('哪吒V0环境变量不全，跳过哪吒Agent');
        return;
    }
    const host = NEZHA_SERVER;
    const port = parseInt(NEZHA_PORT,10);
    const useTLS = TLS_PORTS.has(port);
    log('[Nezha‑V0] start connect',host,port,'tls:',useTLS);

    while(true){
        let sock = null;
        try{
            if(useTLS){
                sock = await new Promise((res,rej)=>{
                    const s = https.connect({host,port,rejectUnauthorized:false});
                    s.on('connect',()=>res(s));
                    s.on('error',e=>rej(e));
                });
            }else{
                sock = await new Promise((res,rej)=>{
                    const s = net.connect({host,port});
                    s.on('connect',()=>res(s));
                    s.on('error',e=>rej(e));
                });
            }
            log('[Nezha‑V0] TCP connected success!');

            function sendPacket(obj){
                const payload = Buffer.from(JSON.stringify(obj));
                const lenBuf = Buffer.alloc(4);
                lenBuf.writeUInt32BE(payload.length,0);
                sock.write(Buffer.concat([lenBuf,payload]));
            }

            const hostInfo = await getHostInfo();
            sendPacket({
                key:NEZHA_KEY,
                uuid:UUID,
                platform:hostInfo.platform,
                platform_version:hostInfo.platformVersion,
                cpu:hostInfo.cpu,
                mem_total:hostInfo.memTotal,
                disk_total:hostInfo.diskTotal,
                swap_total:hostInfo.swapTotal,
                arch:hostInfo.arch,
                boot_time:hostInfo.bootTime,
                version:hostInfo.version
            });

            let buf = Buffer.alloc(0);
            let lastIpReport = 0;

            sock.on('data',chunk=>{
                buf = Buffer.concat([buf,chunk]);
                while(buf.length >=4){
                    const pktLen = buf.readUInt32BE(0);
                    if(buf.length < pktLen+4) break;
                    const body = buf.slice(4,4+pktLen);
                    buf = buf.slice(4+pktLen);
                    try{ JSON.parse(body.toString('utf‑8')); }catch(e){ logErr('parse packet fail',e.message); }
                }
            });

            sock.on('close',()=>{ throw new Error('socket closed'); });
            sock.on('error',err=>{ throw err; });

            while(true){
                const state = await getStateInfo();
                sendPacket({type:"report", ...state});
                const now = Date.now();
                if(now‑lastIpReport > IP_REPORT_PERIOD*1000){
                    const ipPair = await fetchIPPair();
                    sendPacket({type:"geoip", ipv4:ipPair.ipv4, ipv6:ipPair.ipv6});
                    lastIpReport = now;
                }
                await sleep(REPORT_DELAY*1000);
            }

        }catch(err){
            logErr('[Nezha‑V0] connect fail, will retry',err.message);
        }finally{
            if(sock) try{sock.destroy();}catch(e){}
        }
        await sleep(RETRY_DELAY);
    }
}

async function startNezhaAgent(){
    await startNezhaV0();
}

// ========== 启动入口 ==========
setupRawWebSocket(httpServer);
httpServer.listen(PORT,'0.0.0.0',()=>{
    log(`HTTP server listening on port ${PORT}`);
    startNezhaAgent().catch(e=>logErr('nezha agent crash',e));
    addAccessTask();
});
