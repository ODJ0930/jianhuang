
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
    
    console.log(`Worker ${id}: 开始下载 ${url}`);
    
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
        console.log(`Worker ${id}: 连接到远程IP ${remoteIP}`);
        parentPort.postMessage({ type: 'ip', ip: remoteIP });
      }
      
      res.on('data', (chunk) => {
        bytesDownloaded += chunk.length;
        parentPort.postMessage({ type: 'progress', bytes: chunk.length });
      });
      
      res.on('end', () => {
        if (running) {
          console.log(`Worker ${id}: 单次下载完成，将重新开始`);
          setTimeout(() => download(), 100);
        }
      });
      
      res.on('error', (err) => {
        if (!running) return;
        console.error(`Worker ${id} 响应错误: ${err.message}`);
        setTimeout(() => {
          if (running) {
            console.log(`Worker ${id}: 尝试恢复下载`);
            download();
          }
        }, 1000);
      });
    });
    
    req.on('error', (err) => {
      if (!running) return;
      console.error(`Worker ${id} 请求错误: ${err.message}`);
      setTimeout(() => {
        if (running) {
          console.log(`Worker ${id}: 尝试恢复下载`);
          download();
        }
      }, 1000);
    });
    
    req.on('timeout', () => {
      console.log(`Worker ${id}: 请求超时`);
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
      console.log(`Worker ${id}: 收到停止信号`);
      running = false;
    } else if (msg.type === 'pause') {
      console.log(`Worker ${id}: 收到暂停信号`);
      paused = true;
    } else if (msg.type === 'resume') {
      console.log(`Worker ${id}: 收到恢复信号`);
      if (paused) {
        paused = false;
        // 如果当前是暂停状态，恢复下载
        download();
      }
    }
  });
});
