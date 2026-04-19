const WebSocket = require('ws');
const http = require('http');
const express = require('express');
const cors = require('cors');
const winston = require('winston');
require('dotenv').config();
// 引入HTTP客户端库
const axios = require('axios');
const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || 'debug',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
    ),
    transports: [
        new winston.transports.File({ filename: 'server.log', maxsize: 10485760, maxFiles: 5 }),
        new winston.transports.Console({
            format: winston.format.combine(
                winston.format.colorize(),
                winston.format.simple()
            )
        })
    ]
});
// 统一的摩尔斯电码映射表（字母+数字+标点）
const MORSE_CODE_MAP = {
    'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.',
    'F': '..-.', 'G': '--.', 'H': '....', 'I': '..', 'J': '.---',
    'K': '-.-', 'L': '.-..', 'M': '--', 'N': '-.', 'O': '---',
    'P': '.--.', 'Q': '--.-', 'R': '.-.', 'S': '...', 'T': '-',
    'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-', 'Y': '-.--',
    'Z': '--..',
    '0': '-----', '1': '.----', '2': '..---', '3': '...--',
    '4': '....-', '5': '.....', '6': '-....', '7': '--...',
    '8': '---..', '9': '----.',
    '.': '.-.-.-',  // 句点/小数点
    '-': '-....-',  // 连字符/负号/破折号
    ':': '---...'   // 冒号
};
const ANTI_ATTACK_CONFIG = {
    MAX_MESSAGES_PER_CLIENT: 1200,
    MESSAGE_WINDOW_MS: 10000,
    MAX_MESSAGES_PER_FREQUENCY: 1000,
    FREQUENCY_WINDOW_MS: 10000,
    BASE_BAN_DURATION: 60000,
    REPEAT_BAN_MULTIPLIER: 2,
    MAX_BAN_DURATION: 3600000,
    MAX_CLIENTS_PER_IP: 5,
    MAX_FREQUENCIES_PER_IP: 3,
    IP_WINDOW_MS: 300000,
    MULTI_FREQ_BAN_DURATION: 86400000
};
const attackTracking = {
    clients: new Map(),
    frequencies: new Map(),
    ips: new Map()
};
function isClientBanned(clientId) {
    const clientData = attackTracking.clients.get(clientId);
    if (!clientData) return false;
    return clientData.bannedUntil > Date.now();
}
function isIpBanned(ip) {
    const ipData = attackTracking.ips.get(ip);
    if (!ipData) return false;
    return ipData.bannedUntil > Date.now();
}
function isIpOverLimit(ip, clientId, frequency) {
    const now = Date.now();
    let ipData = attackTracking.ips.get(ip);
   
    if (!ipData) {
        ipData = {
            clients: new Set([clientId]),
            frequencies: new Set([frequency]),
            windowStart: now,
            bannedUntil: 0
        };
        attackTracking.ips.set(ip, ipData);
        return false;
    }
   
    if (ipData.bannedUntil > now) {
        return true;
    }
   
    if (now - ipData.windowStart > ANTI_ATTACK_CONFIG.IP_WINDOW_MS) {
        ipData.clients.clear();
        ipData.frequencies.clear();
        ipData.windowStart = now;
    }
   
    ipData.clients.add(clientId);
    ipData.frequencies.add(frequency);
   
    if (ipData.clients.size > ANTI_ATTACK_CONFIG.MAX_CLIENTS_PER_IP) {
        ipData.bannedUntil = now + ANTI_ATTACK_CONFIG.BASE_BAN_DURATION;
        return true;
    }
   
    if (ipData.frequencies.size > ANTI_ATTACK_CONFIG.MAX_FREQUENCIES_PER_IP) {
        ipData.bannedUntil = now + ANTI_ATTACK_CONFIG.MULTI_FREQ_BAN_DURATION;
        return true;
    }
   
    return false;
}
function isClientOverLimit(clientId) {
    const now = Date.now();
    let clientData = attackTracking.clients.get(clientId);
   
    if (!clientData) {
        clientData = {
            count: 0,
            windowStart: now,
            bannedUntil: 0,
            banCount: 0
        };
        attackTracking.clients.set(clientId, clientData);
    }
   
    if (clientData.bannedUntil > now) {
        return true;
    }
   
    if (now - clientData.windowStart > ANTI_ATTACK_CONFIG.MESSAGE_WINDOW_MS) {
        clientData.count = 0;
        clientData.windowStart = now;
    }
   
    if (clientData.count >= ANTI_ATTACK_CONFIG.MAX_MESSAGES_PER_CLIENT) {
        clientData.banCount++;
        let banDuration = ANTI_ATTACK_CONFIG.BASE_BAN_DURATION *
            Math.pow(ANTI_ATTACK_CONFIG.REPEAT_BAN_MULTIPLIER, clientData.banCount - 1);
       
        banDuration = Math.min(banDuration, ANTI_ATTACK_CONFIG.MAX_BAN_DURATION);
        clientData.bannedUntil = now + banDuration;
        return true;
    }
   
    clientData.count++;
    return false;
}
function isFrequencyOverLimit(frequency) {
    const now = Date.now();
    const roundedFreq = Math.round(frequency * 1000) / 1000;
   
    let freqData = attackTracking.frequencies.get(roundedFreq);
   
    if (!freqData) {
        freqData = { count: 0, windowStart: now };
        attackTracking.frequencies.set(roundedFreq, freqData);
    }
   
    if (now - freqData.windowStart > ANTI_ATTACK_CONFIG.FREQUENCY_WINDOW_MS) {
        freqData.count = 0;
        freqData.windowStart = now;
    }
   
    if (freqData.count >= ANTI_ATTACK_CONFIG.MAX_MESSAGES_PER_FREQUENCY) {
        return true;
    }
   
    freqData.count++;
    return false;
}
function cleanupTrackingData() {
    const now = Date.now();
   
    attackTracking.clients.forEach((data, clientId) => {
        if (data.bannedUntil < now &&
            now - data.windowStart > ANTI_ATTACK_CONFIG.MESSAGE_WINDOW_MS) {
            attackTracking.clients.delete(clientId);
        }
    });
   
    attackTracking.frequencies.forEach((data, frequency) => {
        if (now - data.windowStart > ANTI_ATTACK_CONFIG.FREQUENCY_WINDOW_MS) {
            attackTracking.frequencies.delete(frequency);
        }
    });
   
    attackTracking.ips.forEach((data, ip) => {
        if (data.bannedUntil < now &&
            now - data.windowStart > ANTI_ATTACK_CONFIG.IP_WINDOW_MS) {
            attackTracking.ips.delete(ip);
        }
    });
   
    setTimeout(cleanupTrackingData, 60000);
}
const app = express();
const server = http.createServer(app);
const maliciousPaths = [
    /\/vendor\/phpunit\/phpunit\/src\/Util\/PHP\/eval-stdin\.php/,
    /\/index\.php\?s=\/index\/\\think\\app\/invokefunction/,
    /\/index\.php\?lang=.*\.\.\/.*/,
    /\/containers\/json/
];
const maliciousUserAgents = [
    /masscan/, /nmap/, /w3af/, /sqlmap/, /nikto/, /grabber/, /bot\/\d+/
];
app.use((req, res, next) => {
    let clientIp = req.ip;
    if (req.headers['x-forwarded-for']) {
        const ips = req.headers['x-forwarded-for'].split(',').map(ip => ip.trim());
        clientIp = ips[0];
    }
   
    if (clientIp && clientIp.startsWith('::ffff:')) {
        clientIp = clientIp.substring(7);
    }
   
    const isMaliciousPath = maliciousPaths.some(pattern => pattern.test(req.originalUrl));
    const userAgent = req.headers['user-agent'] || '';
    const isMaliciousAgent = maliciousUserAgents.some(pattern => pattern.test(userAgent));
   
    if (isMaliciousPath || isMaliciousAgent) {
        return res.redirect(302, 'https://bg6qed.com/');
    }
   
    const allowedMethods = ['GET', 'POST', 'OPTIONS'];
    if (!allowedMethods.includes(req.method)) {
        return res.status(405).json({ status: 'error', message: '方法不允许' });
    }
   
    next();
});
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true }));
const allowedOrigins = process.env.ALLOWED_ORIGINS ?
    process.env.ALLOWED_ORIGINS.split(',').map(origin => origin.trim()) :
    ['https://cw.438900.xyz', 'http://localhost:3000'];
app.use(cors({
    origin: (origin, callback) => {
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
    maxAge: 86400
}));
app.get('/health', (req, res) => {
    try {
        const stats = {
            status: 'ok',
            timestamp: Date.now(),
            uptime: process.uptime(),
            memory: process.memoryUsage(),
            connections: serverStats,
            cpu: {
                usage: process.cpuUsage()
            },
            antiAttack: {
                trackedClients: attackTracking.clients.size,
                trackedFrequencies: attackTracking.frequencies.size,
                bannedClients: Array.from(attackTracking.clients.entries())
                    .filter(([_, data]) => data.bannedUntil > Date.now())
                    .length,
                trackedIps: attackTracking.ips.size,
                bannedIps: Array.from(attackTracking.ips.entries())
                    .filter(([_, data]) => data.bannedUntil > Date.now())
                    .length
            }
        };
        res.status(200).json(stats);
    } catch (error) {
        res.status(500).json({ status: 'error', message: error.message });
    }
});
app.post('/reset-stats', (req, res) => {
    serverStats.messagesProcessed = 0;
    serverStats.messagesBroadcasted = 0;
    serverStats.messagesBlocked = 0;
    serverStats.timeBroadcastMessages = 0;
    serverStats.lastReset = Date.now();
   
    attackTracking.clients.clear();
    attackTracking.frequencies.clear();
    attackTracking.ips.clear();
   
    res.status(200).json({ status: 'ok', message: 'Stats reset' });
});
app.use((err, req, res, next) => {
    res.status(500).json({ status: 'error', message: '服务器内部错误' });
});
const wss = new WebSocket.Server({
    server,
    perMessageDeflate: {
        threshold: 1024
    },
    maxPayload: 1024 * 5
});
const clients = {
    rx: new Map(),
    tx: new Map()
};
const messageQueues = new Map();
function processMessageQueues() {
    messageQueues.forEach((queue, band) => {
        if (queue.length === 0) return;
        const rxBandKey = `rx${band}`;
        const rxClients = clients.rx.get(rxBandKey);
        if (!rxClients || rxClients.size === 0) {
            messageQueues.set(band, []);
            return;
        }
        const messages = [...new Set(queue)];
        serverStats.messagesBroadcasted += messages.length;
       
        rxClients.forEach(client => {
            if (client.readyState === WebSocket.OPEN) {
                try {
                    messages.forEach(msg => client.send(msg));
                } catch (error) {}
            }
        });
        messageQueues.set(band, []);
    });
    setTimeout(processMessageQueues, 5);
}
processMessageQueues();
const BROADCAST_BAND = '40';
const BROADCAST_FREQUENCY = 7.003;
const TIMING = {
    DOT_DURATION: 100,
    DASH_DURATION: 300,
    ELEMENT_GAP: 100,
    CHARACTER_GAP: 300,
    WORD_GAP: 700,
    MARKER_DURATION: 1000,
    SECTION_GAP: 2000
};
let broadcastInterval;
let issDataCache = null;
let isFetching = false; // 防止重复请求
let currentCycleFetched = false; // 标记当前周期是否已成功获取数据
// 获取国际空间站实时位置数据
async function fetchIssData() {
    // 如果当前周期已经获取过数据，直接返回缓存
    if (currentCycleFetched) {
        return issDataCache;
    }
   
    // 如果正在请求中，避免重复请求
    if (isFetching) {
        return null;
    }
   
    logger.info('获取国际空间站(ISS)实时位置数据');
    isFetching = true;
    let attempt = 0;
    let success = false;
   
    while (attempt < 2 && !success) {  // 最多重试1次（总2次尝试）
        try {
            // 使用公开的ISS位置API
            const response = await axios.get('http://api.open-notify.org/iss-now.json', {
                timeout: 5000,
                headers: {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36'
                }
            });
           
            if (response.data && response.data.iss_position) {
                const timestamp = new Date(response.data.timestamp * 1000).toISOString();  // 使用API的unix timestamp转换为ISO
                issDataCache = {
                    timestamp,
                    latitude: parseFloat(response.data.iss_position.latitude).toFixed(4),
                    longitude: parseFloat(response.data.iss_position.longitude).toFixed(4),
                    timestamp_unix: response.data.timestamp
                };
                logger.info(`成功获取ISS位置数据: 纬度 ${issDataCache.latitude}, 经度 ${issDataCache.longitude}`);
                success = true;
                currentCycleFetched = true; // 标记当前周期已成功获取
                break;
            } else {
                logger.error('ISS API返回的数据格式不正确');
                throw new Error('Invalid data format');
            }
        } catch (error) {
            attempt++;
            const statusCode = error.response?.status || '无状态码';
            logger.error(`获取ISS数据失败（尝试 ${attempt}/2），状态码: ${statusCode}，错误: ${error.message}`);
            if (attempt < 2) {
                // 重试前稍等
                await new Promise(resolve => setTimeout(resolve, 1000));
            }
        }
    }
   
    if (!success) {
        logger.error('ISS数据获取失败，已跳过本周期ISS广播');
    }
   
    isFetching = false; // 无论成功失败，都标记请求结束
    return success ? issDataCache : null;
}
// 生成时间广播序列
function generateTimeBroadcast() {
    const now = new Date();
    const hours = String(now.getHours()).padStart(2, '0');
    const minutes = String(now.getMinutes()).padStart(2, '0');
    const seconds = String(now.getSeconds()).padStart(2, '0');
    const timeStr = `${hours}${minutes}${seconds}`;
    const morseSequence = [{ type: 'marker', duration: TIMING.MARKER_DURATION }];
    for (let i = 0; i < timeStr.length; i++) {
        const char = timeStr[i];
        const code = MORSE_CODE_MAP[char] || '';
        for (const symbol of code) {
            morseSequence.push({
                type: symbol === '.' ? 'dot' : 'dash',
                duration: symbol === '.' ? TIMING.DOT_DURATION : TIMING.DASH_DURATION
            });
            morseSequence.push({
                type: 'gap',
                duration: TIMING.ELEMENT_GAP
            });
        }
        if (code.length > 0) {
            morseSequence[morseSequence.length - 1] = {
                type: 'gap',
                duration: i < timeStr.length - 1 ? TIMING.CHARACTER_GAP : TIMING.WORD_GAP
            };
        }
    }
    return morseSequence;
}
// 生成ISS位置数据广播序列
function generateIssBroadcast(data) {
    const sequence = [];
   
    sequence.push({ type: 'marker', duration: TIMING.MARKER_DURATION });
    sequence.push({ type: 'marker', duration: 500 });
   
    // 格式化ISS位置数据
    const dataString = `ISS POS ${data.latitude} ${data.longitude} ${data.timestamp.substring(11, 19)}`;
    logger.info(`生成ISS广播数据: ${dataString}`);
   
    // 处理每个字符
    for (let i = 0; i < dataString.length; i++) {
        const c = dataString[i];
       
        // 空格使用特殊处理
        if (c === ' ') {
            sequence.push({
                type: 'gap',
                duration: TIMING.WORD_GAP
            });
            continue;
        }
       
        const code = MORSE_CODE_MAP[c.toUpperCase()] || '';
        if (code) {
            for (const symbol of code) {
                sequence.push({
                    type: symbol === '.' ? 'dot' : 'dash',
                    duration: symbol === '.' ? TIMING.DOT_DURATION : TIMING.DASH_DURATION
                });
                sequence.push({
                    type: 'gap',
                    duration: TIMING.ELEMENT_GAP
                });
            }
           
            // 字符之间的间隔
            sequence.push({
                type: 'gap',
                duration: TIMING.CHARACTER_GAP
            });
        }
    }
   
    sequence.push({ type: 'marker', duration: TIMING.MARKER_DURATION });
   
    return sequence;
}
// 执行广播
async function performBroadcast() {
    try {
        // 尝试获取ISS数据（当前周期内只会实际请求一次，重试一次）
        const issData = await fetchIssData();
       
        let issSequence = null;
        if (issData) {
            issSequence = generateIssBroadcast(issData);
            logger.info('使用ISS位置数据生成广播序列');
        } else {
            logger.info('没有可用的ISS数据，仅广播时间信息');
        }
       
        const timeSequence = generateTimeBroadcast();
        let delay = 0;
        const broadcastClientId = 'broadcast-system';
       
        logger.info('开始执行定时广播');
       
        // 广播时间信息
        for (const element of timeSequence) {
            setTimeout(() => {
                const timestamp = Date.now();
                const signal = {
                    frequency: BROADCAST_FREQUENCY,
                    clientId: broadcastClientId,
                    type: element.type,
                    timestamp: timestamp,
                    duration: element.duration,
                    sequenceNumber: serverStats.timeBroadcastMessages + 1
                };
                if (element.type === 'dot' || element.type === 'dash') {
                    signal.startTimestamp = timestamp;
                    signal.endTimestamp = timestamp + element.duration;
                }
                const signalStr = JSON.stringify(signal);
                serverStats.timeBroadcastMessages++;
               
                if (!messageQueues.has(BROADCAST_BAND)) {
                    messageQueues.set(BROADCAST_BAND, []);
                }
                const queue = messageQueues.get(BROADCAST_BAND);
               
                if (queue.length < 1000) {
                    queue.push(signalStr);
                }
            }, delay);
            delay += element.duration;
        }
       
        delay += TIMING.SECTION_GAP;
       
        // 广播ISS位置信息
        if (issSequence) {
            for (const element of issSequence) {
                setTimeout(() => {
                    const timestamp = Date.now();
                    const signal = {
                        frequency: BROADCAST_FREQUENCY,
                        clientId: broadcastClientId,
                        type: element.type,
                        timestamp: timestamp,
                        duration: element.duration,
                        sequenceNumber: serverStats.timeBroadcastMessages + 1
                    };
                    if (element.type === 'dot' || element.type === 'dash') {
                        signal.startTimestamp = timestamp;
                        signal.endTimestamp = timestamp + element.duration;
                    }
                    const signalStr = JSON.stringify(signal);
                    serverStats.timeBroadcastMessages++;
                   
                    if (!messageQueues.has(BROADCAST_BAND)) {
                        messageQueues.set(BROADCAST_BAND, []);
                    }
                    const queue = messageQueues.get(BROADCAST_BAND);
                   
                    if (queue.length < 1000) {
                        queue.push(signalStr);
                    }
                }, delay);
                delay += element.duration;
            }
        } else {
            // 如果没有ISS数据，广播错误信息
            setTimeout(() => {
                const timestamp = Date.now();
                const errorSignal = {
                    frequency: BROADCAST_FREQUENCY,
                    clientId: broadcastClientId,
                    type: 'error',
                    timestamp: timestamp,
                    duration: TIMING.MARKER_DURATION,
                    sequenceNumber: serverStats.timeBroadcastMessages + 1
                };
               
                const signalStr = JSON.stringify(errorSignal);
                serverStats.timeBroadcastMessages++;
               
                if (!messageQueues.has(BROADCAST_BAND)) {
                    messageQueues.set(BROADCAST_BAND, []);
                }
                const queue = messageQueues.get(BROADCAST_BAND);
               
                if (queue.length < 1000) {
                    queue.push(signalStr);
                }
            }, delay);
        }
       
        // 广播周期结束时记录完成信息并重置标志
        setTimeout(() => {
            logger.info(`广播完成`);
            currentCycleFetched = false; // 重置当前周期标志，允许下一周期获取新数据
        }, delay);
       
    } catch (error) {
        logger.error(`广播过程中出错: ${error.message}`);
        currentCycleFetched = false; // 出错时也重置标志
    }
}
// 计算到下一个偶数分钟的延迟（每2分钟在偶数分钟开始）
function getDelayToNextInterval() {
    const now = new Date();
    const minutes = now.getMinutes();
    const seconds = now.getSeconds();
    const milliseconds = now.getMilliseconds();
    let delayMinutes;
   
    if (minutes % 2 === 0) {
        // 如果当前是偶数分钟，延迟到下一个偶数分钟（+2分钟）
        delayMinutes = 2;
    } else {
        // 如果是奇数分钟，延迟到下一个偶数分钟（+1分钟）
        delayMinutes = 1;
    }
   
    const delayMs = delayMinutes * 60 * 1000 - seconds * 1000 - milliseconds;
    return Math.max(0, delayMs);
}
// 启动广播和数据更新
function startBroadcasts() {
    // 清除现有定时器
    if (broadcastInterval) clearInterval(broadcastInterval);
    // 设置初始广播延迟
    const initialDelay = getDelayToNextInterval();
    logger.info(`距离下一次广播还有 ${initialDelay / 1000} 秒`);
   
    // 安排首次广播
    setTimeout(() => {
        performBroadcast();
       
        // 设置定期广播（每2分钟）
        broadcastInterval = setInterval(() => {
            performBroadcast();
        }, 2 * 60 * 1000);
    }, initialDelay);
}
function cleanupConnections() {
    clients.rx.forEach((clientsSet, band) => {
        let removed = 0;
        clientsSet.forEach(client => {
            if (client.readyState !== WebSocket.OPEN) {
                clientsSet.delete(client);
                removed++;
            }
        });
        if (removed > 0) {
            if (clientsSet.size === 0) {
                clients.rx.delete(band);
                delete serverStats.rxConnections[band];
            } else {
                serverStats.rxConnections[band] = clientsSet.size;
            }
            updateTotalConnections();
        }
    });
    clients.tx.forEach((clientsSet, band) => {
        let removed = 0;
        clientsSet.forEach(client => {
            if (client.readyState !== WebSocket.OPEN) {
                clientsSet.delete(client);
                removed++;
            }
        });
        if (removed > 0) {
            if (clientsSet.size === 0) {
                clients.tx.delete(band);
                delete serverStats.txConnections[band];
            } else {
                serverStats.txConnections[band] = clientsSet.size;
            }
            updateTotalConnections();
        }
    });
    setTimeout(cleanupConnections, 30000);
}
function updateTotalConnections() {
    let total = 0;
    clients.rx.forEach(set => total += set.size);
    clients.tx.forEach(set => total += set.size);
    serverStats.totalConnections = total;
}
wss.on('connection', (ws, req) => {
    try {
        let clientIp = req.socket.remoteAddress;
       
        if (req.headers['x-forwarded-for']) {
            const ips = req.headers['x-forwarded-for'].split(',').map(ip => ip.trim());
            clientIp = ips[0];
        }
       
        if (clientIp && clientIp.startsWith('::ffff:')) {
            clientIp = clientIp.substring(7);
        }
       
        const url = new URL(req.url, `http://${req.headers.host}`);
        const bandType = url.pathname.substring(1);
        if (!bandType || (!bandType.startsWith('rx') && !bandType.startsWith('tx'))) {
            ws.close(1008, '无效的连接路径');
            return;
        }
        const isRx = bandType.startsWith('rx');
        const band = bandType.substring(2);
        const typeKey = isRx ? 'rx' : 'tx';
        const key = bandType;
        ws.isAlive = true;
        ws.lastActivity = Date.now();
        ws.sequenceNumber = 0;
        ws.clientIp = clientIp;
        ws.connectionId = Date.now().toString(36) + Math.random().toString(36).substr(2, 6);
        ws.on('pong', () => {
            ws.isAlive = true;
            ws.lastActivity = Date.now();
        });
        ws.on('message', () => {
            ws.lastActivity = Date.now();
        });
        if (!clients[typeKey].has(key)) {
            clients[typeKey].set(key, new Set());
        }
        const clientsSet = clients[typeKey].get(key);
        clientsSet.add(ws);
        if (isRx) {
            serverStats.rxConnections[key] = (serverStats.rxConnections[key] || 0) + 1;
        } else {
            serverStats.txConnections[key] = (serverStats.txConnections[key] || 0) + 1;
        }
        updateTotalConnections();
        if (isRx) {
            ws.on('message', (message) => {});
        } else {
            ws.on('message', (message) => {
                try {
                    let signal;
                    try {
                        signal = JSON.parse(message);
                    } catch (parseError) {
                        return;
                    }
                    if (!signal.clientId || typeof signal.frequency !== 'number') {
                        return;
                    }
                    if (isIpBanned(ws.clientIp)) {
                        serverStats.messagesBlocked++;
                        if (ws.readyState === WebSocket.OPEN) {
                            ws.close(1008, 'IP已被临时封禁');
                        }
                        return;
                    }
                    if (isClientBanned(signal.clientId)) {
                        serverStats.messagesBlocked++;
                        if (ws.readyState === WebSocket.OPEN) {
                            ws.close(1008, '客户端已被临时封禁');
                        }
                        return;
                    }
                    if (isIpOverLimit(ws.clientIp, signal.clientId, signal.frequency)) {
                        serverStats.messagesBlocked++;
                        if (ws.readyState === WebSocket.OPEN) {
                            ws.send(JSON.stringify({
                                error: '当前IP客户端连接过多或使用频率过多，请稍后再试',
                                code: 'TOO_MANY_CLIENTS_OR_FREQUENCIES'
                            }));
                            setTimeout(() => {
                                if (ws.readyState === WebSocket.OPEN) {
                                    ws.close(1008, 'IP客户端连接或频率使用过多');
                                }
                            }, 1000);
                        }
                        return;
                    }
                    if (isClientOverLimit(signal.clientId)) {
                        serverStats.messagesBlocked++;
                        if (ws.readyState === WebSocket.OPEN) {
                            ws.send(JSON.stringify({
                                error: '消息发送过于频繁，请稍后再试',
                                code: 'TOO_MANY_MESSAGES'
                            }));
                            setTimeout(() => {
                                if (ws.readyState === WebSocket.OPEN) {
                                    ws.close(1008, '消息发送过于频繁');
                                }
                            }, 1000);
                        }
                        return;
                    }
                    if (isFrequencyOverLimit(signal.frequency)) {
                        serverStats.messagesBlocked++;
                        if (ws.readyState === WebSocket.OPEN) {
                            ws.send(JSON.stringify({
                                error: '当前频率消息过于拥挤，请稍后再试或更换频率',
                                code: 'FREQUENCY_CONGESTED'
                            }));
                        }
                        return;
                    }
                    serverStats.messagesProcessed++;
                    ws.sequenceNumber++;
                   
                    const txSignal = {
                        frequency: signal.frequency,
                        clientId: signal.clientId,
                        type: signal.type,
                        timestamp: Date.now(),
                        sequenceNumber: ws.sequenceNumber
                    };
                    if (signal.type === 'end' && signal.startTimestamp) {
                        txSignal.startTimestamp = signal.startTimestamp;
                        txSignal.endTimestamp = Date.now();
                        txSignal.duration = txSignal.endTimestamp - signal.startTimestamp;
                    } else if (signal.type === 'start') {
                        txSignal.startTimestamp = Date.now();
                    }
                    const signalStr = JSON.stringify(txSignal);
                    if (!messageQueues.has(band)) {
                        messageQueues.set(band, []);
                    }
                    const queue = messageQueues.get(band);
                    if (queue.length < 1000) {
                        queue.push(signalStr);
                    }
                } catch (error) {
                    if (ws.readyState === WebSocket.OPEN) {
                        ws.send(JSON.stringify({ error: error.message }));
                    }
                }
            });
        }
        ws.on('close', (code, reason) => {
            if (clients[typeKey].has(key)) {
                const clientsSet = clients[typeKey].get(key);
                clientsSet.delete(ws);
                if (isRx) {
                    serverStats.rxConnections[key] = Math.max(0, (serverStats.rxConnections[key] || 0) - 1);
                } else {
                    serverStats.txConnections[key] = Math.max(0, (serverStats.txConnections[key] || 0) - 1);
                }
                updateTotalConnections();
                if (clientsSet.size === 0) {
                    clients[typeKey].delete(key);
                    if (isRx) {
                        delete serverStats.rxConnections[key];
                    } else {
                        delete serverStats.txConnections[key];
                    }
                }
            }
        });
        ws.on('error', (error) => {});
    } catch (error) {
        ws.close(1011, '服务器处理连接时出错');
    }
});
const pingInterval = setInterval(() => {
    const now = Date.now();
    const timeoutThreshold = 3600000;
    wss.clients.forEach(ws => {
        if (now - ws.lastActivity > timeoutThreshold) {
            return ws.terminate();
        }
        if (ws.isAlive) {
            ws.isAlive = false;
            try {
                ws.ping('keep-alive', false);
            } catch (error) {}
        } else {
            ws.terminate();
        }
    });
}, 30000);
function gracefulShutdown(signal) {
    if (broadcastInterval) clearInterval(broadcastInterval);
    if (pingInterval) clearInterval(pingInterval);
    wss.on('connection', (ws) => {
        ws.close(1001, '服务器正在关闭');
    });
    let closedConnections = 0;
    const totalConnections = wss.clients.size;
   
    wss.clients.forEach(client => {
        client.close(1001, '服务器正在关闭');
        client.on('close', () => {
            closedConnections++;
            if (closedConnections === totalConnections) {
                closeServers();
            }
        });
    });
    if (totalConnections === 0) {
        closeServers();
    }
    setTimeout(() => {
        closeServers();
    }, 10000);
    function closeServers() {
        wss.close(() => {
            server.close(() => {
                process.exit(0);
            });
        });
    }
}
let serverStats = {
    totalConnections: 0,
    rxConnections: {},
    txConnections: {},
    messagesProcessed: 0,
    messagesBroadcasted: 0,
    messagesBlocked: 0,
    timeBroadcastMessages: 0,
    lastReset: Date.now()
};
const PORT = process.env.PORT || 8080;
server.listen(PORT, '0.0.0.0', () => {
    logger.info(`服务器运行在 http://0.0.0.0:${PORT}`);
    startBroadcasts();
    cleanupConnections();
    cleanupTrackingData();
});
server.on('error', (error) => {
    logger.error(`服务器启动失败: ${error.message}`);
    process.exit(1);
});
process.on('SIGINT', () => gracefulShutdown('SIGINT'));
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGHUP', () => gracefulShutdown('SIGHUP'));
process.on('uncaughtException', (error) => {
    logger.error(`未捕获异常: ${error.message}`);
    process.exit(1);
});
process.on('unhandledRejection', (reason) => {
    logger.error(`未处理的Promise拒绝: ${reason}`);
});
