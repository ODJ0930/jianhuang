const express = require('express');
const app = express();
const http = require('http');
const httpServer = http.createServer(app);
const io = require('socket.io')(httpServer);
const { URL } = require('url');
const https = require('https');
const fs = require('fs');
const path = require('path');
const { Worker } = require('worker_threads');
const os = require('os');
const crypto = require('crypto');
const session = require('express-session');
const yargs = require('yargs/yargs');
// 简化命令行参数处理，避免使用hideBin

// 解析命令行参数
const argv = yargs(process.argv.slice(2))
  .option('password', {
    alias: 'p',
    description: '设置访问密码',
    type: 'string'
  })
  .help()
  .argv;

// 密码配置文件路径
const PASSWORD_FILE = path.join(__dirname, '.password');

// 密码哈希函数
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');
  return { salt, hash };
}

// 验证密码
function verifyPassword(password, salt, storedHash) {
  const hash = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');
  return storedHash === hash;
}

// 保存密码到文件
function savePassword(password) {
  const { salt, hash } = hashPassword(password);
  fs.writeFileSync(PASSWORD_FILE, JSON.stringify({ salt, hash }));
  console.log('密码已设置');
}

// 检查是否已设置密码
function isPasswordSet() {
  return fs.existsSync(PASSWORD_FILE);
}

// 获取存储的密码信息
function getStoredPassword() {
  if (!isPasswordSet()) return null;
  try {
    const data = fs.readFileSync(PASSWORD_FILE, 'utf8');
    return JSON.parse(data);
  } catch (err) {
    console.error('读取密码文件失败:', err);
    return null;
  }
}

// 如果通过命令行参数设置了密码
if (argv.password) {
  savePassword(argv.password);
}

// 如果没有设置密码，设置一个默认密码
if (!isPasswordSet()) {
  const defaultPassword = 'admin';
  savePassword(defaultPassword);
  console.log(`已设置默认密码: ${defaultPassword}`);
  console.log('请使用 --password 参数修改密码，例如: node node.js --password 新密码');
}

// 创建自定义的任务控制器替代AbortController
function createTaskController() {
  return {
    interval: null,
    autoStopTimer: null,
    aborted: false,
    autoStopTimeEnabled: false,
    autoStopTimeValue: 30, // 默认30分钟
    autoStopDataEnabled: false,
    autoStopDataValue: 1, // 默认1GB
    abort: function() {
      this.aborted = true;
    },
    isAborted: function() {
      return this.aborted;
    }
  };
}

// 创建worker.js文件
const workerScript = `
const { parentPort } = require('worker_threads');
const http = require('http');
const https = require('https');
const { URL } = require('url');

parentPort.on('message', ({ url, id }) => {
  const urlObj = new URL(url);
  const lib = urlObj.protocol === 'https:' ? https : http;
  let bytesDownloaded = 0;
  let running = true;
  let paused = false; // 新增暂停状态标志
  
  function download() {
    if (!running) return;
    if (paused) {
      // 如果处于暂停状态，等待一段时间后再检查
      setTimeout(() => download(), 100);
      return;
    }
    
    console.log(\`Worker \${id}: 开始下载 \${url}\`);
    
    const options = {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': '*/*'
      },
      timeout: 10000, // 10秒超时
      rejectUnauthorized: false // 允许自签名证书
    };
    
    const req = lib.get(url, options, (res) => {
      let remoteIP = '';
      if (res.socket && res.socket.remoteAddress) {
        remoteIP = res.socket.remoteAddress;
        console.log(\`Worker \${id}: 连接到远程IP \${remoteIP}\`);
        parentPort.postMessage({ type: 'ip', ip: remoteIP });
      }
      
      res.on('data', (chunk) => {
        bytesDownloaded += chunk.length;
        parentPort.postMessage({ type: 'progress', bytes: chunk.length });
      });
      
      res.on('end', () => {
        if (running) {
          console.log(\`Worker \${id}: 单次下载完成，将重新开始\`);
          setTimeout(() => download(), 100);
        }
      });
      
      res.on('error', (err) => {
        if (!running) return;
        console.error(\`Worker \${id} 响应错误: \${err.message}\`);
        setTimeout(() => {
          if (running) {
            console.log(\`Worker \${id}: 尝试恢复下载\`);
            download();
          }
        }, 1000);
      });
    });
    
    req.on('error', (err) => {
      if (!running) return;
      console.error(\`Worker \${id} 请求错误: \${err.message}\`);
      setTimeout(() => {
        if (running) {
          console.log(\`Worker \${id}: 尝试恢复下载\`);
          download();
        }
      }, 1000);
    });
    
    req.on('timeout', () => {
      console.log(\`Worker \${id}: 请求超时\`);
      req.destroy();
      if (running) {
        setTimeout(() => download(), 1000);
      }
    });
  }
  
  // 开始下载循环
  download();
  
  // 监听消息
  parentPort.on('message', (msg) => {
    if (msg.type === 'stop') {
      console.log(\`Worker \${id}: 收到停止信号\`);
      running = false;
    } else if (msg.type === 'pause') {
      console.log(\`Worker \${id}: 收到暂停信号\`);
      paused = true;
    } else if (msg.type === 'resume') {
      console.log(\`Worker \${id}: 收到恢复信号\`);
      if (paused) {
        paused = false;
        // 如果当前是暂停状态，恢复下载
        download();
      }
    }
  });
});
`;

// 创建worker.js文件
try {
  fs.writeFileSync(path.join(__dirname, 'worker.js'), workerScript);
  console.log('成功创建worker.js文件');
} catch (err) {
  console.error('创建worker.js文件失败:', err);
}

app.use(express.json());

// 配置会话中间件
app.use(session({
  secret: crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 } // 24小时过期
}));

// 身份验证中间件
function requireAuth(req, res, next) {
  // 如果未设置密码，则不需要验证
  if (!isPasswordSet()) {
    return next();
  }
  
  // 检查会话中的认证状态
  if (req.session.authenticated) {
    return next();
  }
  
  // 对登录页面和认证API不进行拦截
  if (req.path === '/login.html' || req.path.startsWith('/auth/')) {
    return next();
  }
  
  // 对API请求返回401状态码
  if (req.path.startsWith('/api/') || req.xhr || req.headers.accept?.includes('application/json')) {
    return res.status(401).json({ error: '未授权访问' });
  }
  
  // 重定向到登录页面
  res.redirect('/login.html');
}

// 应用身份验证中间件
app.use(requireAuth);

// 静态文件服务
app.use(express.static('public'));

let downloadRunning = false;
let totalBytes = 0;
let currentController = null; // 当前请求的 AbortController
let currentTaskStartTime = null; // 当前任务启动时间（毫秒数）
let records = []; // 保存每次任务的数据记录
let activeWorkers = []; // 活跃的工作线程
let currentRemoteIP = '未知';

// 获取CPU核心数来决定线程数，但最多使用64个线程
const MAX_THREADS = Math.min(os.cpus().length, 64);
console.log(`系统有 ${os.cpus().length} 个CPU核心，将使用 ${MAX_THREADS} 个下载线程`);

// 创建工作线程
function createWorkerPool(url, controller, customThreadCount) {
  const workerCount = customThreadCount || MAX_THREADS;
  console.log(`启动 ${workerCount} 个下载线程`);
  
  for (let i = 0; i < workerCount; i++) {
    try {
      const worker = new Worker(path.join(__dirname, 'worker.js'));
      
      // 记录每秒从工作线程接收的字节数
      worker.on('message', (message) => {
        if (message.type === 'progress') {
          totalBytes += message.bytes;
        } else if (message.type === 'ip') {
          currentRemoteIP = message.ip;
          console.log(`更新远程IP: ${currentRemoteIP}`);
        }
      });
      
      worker.on('error', (err) => {
        console.error(`Worker ${i} 错误:`, err);
        // 尝试重启这个worker
        if (downloadRunning) {
          console.log(`尝试重启 Worker ${i}`);
          try {
            const newWorker = new Worker(path.join(__dirname, 'worker.js'));
            newWorker.postMessage({ url, id: i });
            // 替换activeWorkers中的worker
            const index = activeWorkers.indexOf(worker);
            if (index !== -1) {
              activeWorkers[index] = newWorker;
            } else {
              activeWorkers.push(newWorker);
            }
          } catch (e) {
            console.error(`重启 Worker ${i} 失败:`, e);
          }
        }
      });
      
      // 启动工作线程的下载任务
      worker.postMessage({ url, id: i });
      activeWorkers.push(worker);
    } catch (err) {
      console.error(`创建 Worker ${i} 失败:`, err);
    }
  }
}

// 修改 downloadLoop 函数，使其不依赖于前端连接，并添加服务器端自动停止功能
function downloadLoop(downloadUrl, controller, threadCount) {
  if (!downloadRunning) return;
  
  // 创建多个工作线程进行下载
  createWorkerPool(downloadUrl, controller, threadCount);
  
  const startTime = Date.now();
  let lastTotalBytes = 0;
  
  // 设置基于时间的自动停止
  if (controller.autoStopTimeEnabled && controller.autoStopTimeValue > 0) {
    const timeoutMs = controller.autoStopTimeValue * 60 * 1000; // 转换为毫秒
    console.log(`设置自动停止时间: ${controller.autoStopTimeValue}分钟 (${timeoutMs}毫秒)`);
    
    controller.autoStopTimer = setTimeout(() => {
      if (downloadRunning && !controller.isAborted()) {
        console.log(`已达到设定的时间限制: ${controller.autoStopTimeValue}分钟，自动停止测试`);
        
        // 停止下载
        downloadRunning = false;
        
        if (controller.interval) {
          clearInterval(controller.interval);
        }
        
        controller.abort();
        
        const endTime = Date.now();
        const durationSec = (endTime - currentTaskStartTime) / 1000;
        
        // 停止所有工作线程
        terminateWorkers();
        
        const record = {
          startTime: new Date(currentTaskStartTime).toLocaleString(),
          endTime: new Date(endTime).toLocaleString(),
          durationSec: durationSec.toFixed(2),
          totalGB: (totalBytes / (1024 * 1024 * 1024)).toFixed(3),
          averageSpeedMbps: durationSec > 0 ? (((totalBytes * 8) / durationSec) / 1e6).toFixed(3) : "0.000",
          threads: activeWorkers.length,
          autoStopped: true,
          stopReason: "时间限制"
        };
        
        console.log('自动停止测试记录:', record);
        records.push(record);
        
        // 通知所有客户端测试已自动停止
        io.emit('auto_stopped', {
          reason: "时间限制",
          record: record
        });
      }
    }, timeoutMs);
  }
  
  const statInterval = setInterval(() => {
    const currentTime = Date.now();
    const duration = (currentTime - startTime) / 1000;
    const intervalDuration = 1; // 1秒
    const bytesDuringInterval = totalBytes - lastTotalBytes;
    const speedMbps = ((bytesDuringInterval * 8 / intervalDuration) / 1e6);
    const totalGB = totalBytes / (1024 * 1024 * 1024);
    
    console.log(`统计: ${totalGB.toFixed(3)} GB, 当前速度: ${speedMbps.toFixed(3)} Mbps, IP: ${currentRemoteIP}`);
    
    // 检查是否达到流量限制
    if (controller.autoStopDataEnabled && controller.autoStopDataValue > 0 && 
        totalGB >= controller.autoStopDataValue && downloadRunning && !controller.isAborted()) {
      
      console.log(`已达到设定的流量限制: ${controller.autoStopDataValue}GB，自动停止测试`);
      
      // 停止下载
      downloadRunning = false;
      
      clearInterval(statInterval);
      if (controller.autoStopTimer) {
        clearTimeout(controller.autoStopTimer);
      }
      
      controller.abort();
      
      const endTime = Date.now();
      const durationSec = (endTime - currentTaskStartTime) / 1000;
      
      // 停止所有工作线程
      terminateWorkers();
      
      const record = {
        startTime: new Date(currentTaskStartTime).toLocaleString(),
        endTime: new Date(endTime).toLocaleString(),
        durationSec: durationSec.toFixed(2),
        totalGB: (totalBytes / (1024 * 1024 * 1024)).toFixed(3),
        averageSpeedMbps: durationSec > 0 ? (((totalBytes * 8) / durationSec) / 1e6).toFixed(3) : "0.000",
        threads: activeWorkers.length,
        autoStopped: true,
        stopReason: "流量限制"
      };
      
      console.log('自动停止测试记录:', record);
      records.push(record);
      
      // 通知所有客户端测试已自动停止
      io.emit('auto_stopped', {
        reason: "流量限制",
        record: record
      });
      
      return;
    }
    
    // 即使没有连接的客户端，也继续发送统计数据
    io.emit('stats', {
      totalGB: totalGB.toFixed(3),
      lastSpeedMbps: speedMbps.toFixed(3),
      ip: currentRemoteIP,
      threads: activeWorkers.length,
      duration: duration.toFixed(0)
    });
    
    lastTotalBytes = totalBytes;
  }, 1000);
  
  controller.interval = statInterval;
}

// 终止所有工作线程的助手函数
function terminateWorkers() {
  console.log(`正在终止 ${activeWorkers.length} 个工作线程`);
  
  for (const worker of activeWorkers) {
    try {
      worker.postMessage({ type: 'stop' });
      worker.terminate();
    } catch (err) {
      console.error('终止工作线程时发生错误:', err);
    }
  }
  
  activeWorkers = [];
  console.log('所有工作线程已终止');
}

app.post('/start', (req, res) => {
  const { url, threadCount, autoStopTimeEnabled, autoStopTimeValue, autoStopDataEnabled, autoStopDataValue } = req.body;
  console.log(`收到开始请求，URL: ${url}, 线程数: ${threadCount || MAX_THREADS}`);
  console.log(`自动停止设置 - 时间: ${autoStopTimeEnabled ? autoStopTimeValue + '分钟' : '禁用'}, 流量: ${autoStopDataEnabled ? autoStopDataValue + 'GB' : '禁用'}`);
  
  if (!url) {
    console.log('请求中缺少URL参数');
    return res.status(400).json({ error: '缺少 URL 参数' });
  }
  
  // 如果有之前未结束的任务，先取消
  if (currentController) {
    console.log('取消之前的未完成任务');
    currentController.abort();
    if (currentController.interval) {
      clearInterval(currentController.interval);
    }
    if (currentController.autoStopTimer) {
      clearTimeout(currentController.autoStopTimer);
    }
    
    terminateWorkers();
    currentController = null;
  }
  
  totalBytes = 0;
  downloadRunning = true;
  currentTaskStartTime = Date.now();
  currentController = createTaskController();
  
  // 保存自动停止设置到控制器
  currentController.autoStopTimeEnabled = autoStopTimeEnabled;
  currentController.autoStopTimeValue = autoStopTimeValue;
  currentController.autoStopDataEnabled = autoStopDataEnabled;
  currentController.autoStopDataValue = autoStopDataValue;
  
  console.log(`开始新的下载任务: ${url}`);
  
  // 使用用户指定的线程数量，如果未指定则使用系统最大值
  let userThreadCount;
  if (threadCount !== null && threadCount !== undefined) {
    // 确保线程数不超过系统最大值
    userThreadCount = Math.min(parseInt(threadCount), MAX_THREADS);
    console.log(`用户指定线程数: ${threadCount}, 调整后: ${userThreadCount}`);
  } else {
    userThreadCount = MAX_THREADS;
    console.log(`使用系统最大线程数: ${userThreadCount}`);
  }
  
  downloadLoop(url, currentController, userThreadCount);
  
  return res.json({
    status: '开始下载',
    url,
    threads: userThreadCount
  });
});

// 添加 Socket.IO 连接和断开事件处理
io.on('connection', (socket) => {
  console.log('客户端已连接:', socket.id);
  
  // 如果有正在运行的任务，立即发送当前状态
  if (downloadRunning && currentController) {
    socket.emit('task_status', { 
      running: true,
      totalGB: (totalBytes / (1024 * 1024 * 1024)).toFixed(3),
      ip: currentRemoteIP,
      threads: activeWorkers.length
    });
  }
  
  socket.on('disconnect', () => {
    console.log('客户端已断开连接:', socket.id);
    // 客户端断开连接时不停止下载任务
  });
});

// 修改 app.post('/stop') 路由，移除前端关闭页面时自动停止的行为
app.post('/stop', (req, res) => {
  console.log('收到停止请求');
  
  // 正常停止请求的处理逻辑
  downloadRunning = false;
  
  if (currentController) {
    if (currentController.interval) {
      clearInterval(currentController.interval);
    }
    
    if (currentController.autoStopTimer) {
      clearTimeout(currentController.autoStopTimer);
    }
    
    currentController.abort();
    currentController = null;
    
    const endTime = Date.now();
    const durationSec = (endTime - currentTaskStartTime) / 1000;
    
    // 停止所有工作线程
    terminateWorkers();
    
    const record = {
      startTime: new Date(currentTaskStartTime).toLocaleString(),
      endTime: new Date(endTime).toLocaleString(),
      durationSec: durationSec.toFixed(2),
      totalGB: (totalBytes / (1024 * 1024 * 1024)).toFixed(3),
      averageSpeedMbps: durationSec > 0 ? (((totalBytes * 8) / durationSec) / 1e6).toFixed(3) : "0.000",
      threads: activeWorkers.length
    };
    
    console.log('测试记录:', record);
    records.push(record);
    
    return res.json({ status: '停止下载', record });
  } else {
    return res.status(400).json({ error: '没有正在进行的下载任务' });
  }
});

// 添加页面关闭通知路由
app.post('/notify-page-close', (req, res) => {
    console.log('收到页面关闭通知，测试将继续在服务器端运行');
    // 只返回确认信息，不停止测试
    return res.json({ status: '页面关闭通知已接收，测试继续运行' });
});

// 新增路由，返回所有任务的记录
app.get('/records', (req, res) => {
  res.json(records);
});

// 身份验证相关API
// 登录API
app.post('/auth/login', (req, res) => {
  const { password } = req.body;
  
  if (!password) {
    return res.status(400).json({ error: '请提供密码' });
  }
  
  const storedPassword = getStoredPassword();
  if (!storedPassword) {
    return res.status(500).json({ error: '服务器密码配置错误' });
  }
  
  if (verifyPassword(password, storedPassword.salt, storedPassword.hash)) {
    // 设置会话认证状态
    req.session.authenticated = true;
    return res.json({ success: true });
  } else {
    return res.status(401).json({ error: '密码错误' });
  }
});

// 登出API
app.post('/auth/logout', (req, res) => {
  req.session.authenticated = false;
  res.json({ success: true });
});

// 检查认证状态API
app.get('/auth/status', (req, res) => {
  res.json({ authenticated: !!req.session.authenticated });
});

// 修改密码API（需要已经登录）
app.post('/auth/change-password', (req, res) => {
  if (!req.session.authenticated) {
    return res.status(401).json({ error: '未授权访问' });
  }
  
  const { newPassword } = req.body;
  
  if (!newPassword || newPassword.length < 1) {
    return res.status(400).json({ error: '请提供有效的新密码' });
  }
  
  try {
    savePassword(newPassword);
    res.json({ success: true, message: '密码已更新' });
  } catch (err) {
    console.error('更新密码失败:', err);
    res.status(500).json({ error: '更新密码失败' });
  }
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// 登录页面路由
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// 添加获取系统信息的路由
app.get('/system-info', (req, res) => {
  res.json({
    maxThreads: MAX_THREADS
  });
});

// 检查并创建public目录
const publicDir = path.join(__dirname, 'public');
if (!fs.existsSync(publicDir)) {
  console.log('创建public目录');
  fs.mkdirSync(publicDir);
}

// 监听Docker的SIGTERM信号
process.on('SIGTERM', () => {
  console.log('收到SIGTERM信号，正在关闭服务...');
  if (currentController) {
    if (currentController.interval) {
      clearInterval(currentController.interval);
    }
    currentController.abort();
  }
  terminateWorkers();
  httpServer.close(() => {
    console.log('HTTP服务器已关闭');
    process.exit(0);
  });
});

// 启动HTTP服务器
httpServer.listen(3000, '0.0.0.0', () => {
  console.log('服务器启动，监听 0.0.0.0:3000 端口');
  console.log(`系统有 ${os.cpus().length} 个CPU核心，将使用 ${MAX_THREADS} 个下载线程`);
});
