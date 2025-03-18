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

// 创建自定义的任务控制器替代AbortController
function createTaskController() {
  return {
    interval: null,
    aborted: false,
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

// 修改 downloadLoop 函数，使其不依赖于前端连接
function downloadLoop(downloadUrl, controller, threadCount) {
  if (!downloadRunning) return;
  
  // 创建多个工作线程进行下载
  createWorkerPool(downloadUrl, controller, threadCount);
  
  const startTime = Date.now();
  let lastTotalBytes = 0;
  
  const statInterval = setInterval(() => {
    const currentTime = Date.now();
    const duration = (currentTime - startTime) / 1000;
    const intervalDuration = 1; // 1秒
    const bytesDuringInterval = totalBytes - lastTotalBytes;
    const speedMbps = ((bytesDuringInterval * 8 / intervalDuration) / 1e6);
    const totalGB = totalBytes / (1024 * 1024 * 1024);
    
    console.log(`统计: ${totalGB.toFixed(3)} GB, 当前速度: ${speedMbps.toFixed(3)} Mbps, IP: ${currentRemoteIP}`);
    
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
  const { url, threadCount } = req.body;
  console.log(`收到开始请求，URL: ${url}, 线程数: ${threadCount || MAX_THREADS}`);
  
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
    
    terminateWorkers();
    currentController = null;
  }
  
  totalBytes = 0;
  downloadRunning = true;
  currentTaskStartTime = Date.now();
  currentController = createTaskController();
  
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
  
  // 检查请求中是否包含 fromBeforeUnload 参数
  const { fromBeforeUnload } = req.body;
  
  // 如果是从 beforeunload 事件发出的请求，不停止下载
  if (fromBeforeUnload) {
    console.log('浏览器关闭，但任务将继续运行');
    return res.json({ status: '浏览器关闭，任务继续运行' });
  }
  
  // 正常停止请求的处理逻辑
  downloadRunning = false;
  
  if (currentController) {
    if (currentController.interval) {
      clearInterval(currentController.interval);
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

// 新增路由，返回所有任务的记录
app.get('/records', (req, res) => {
  res.json(records);
});



app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
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
