const express = require('express');
const { exec } = require('child_process');
const si = require('systeminformation');
const bcrypt = require('bcryptjs');
const path = require('path');
const { format } = require('date-fns');
const fs = require('fs').promises;
const fsSync = require('fs');
const fsExtra = require('fs-extra');
const mammoth = require('mammoth');
const mime = require('mime-types');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const { parseFile } = require('music-metadata');

const app = express();

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// 优化：添加压缩中间件（对非视频文件启用gzip压缩）
const compression = require('compression');
app.use(compression({
    filter: (req, res) => {
        // 视频文件不压缩（已压缩），其他文件压缩
        if (req.headers['accept-encoding'] && req.headers['accept-encoding'].includes('gzip')) {
            const contentType = res.getHeader('content-type') || '';
            return !/^video\//.test(contentType);
        }
        return false;
    },
    level: 6 // 压缩级别（1-9，6是平衡点）
}));

// 优化：设置全局HTTP头
app.use((req, res, next) => {
    // 保持连接活跃，减少TCP握手开销
    res.setHeader('Connection', 'keep-alive');
    // 启用CORS（如果需要）
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Range');
    // 优化视频流传输
    if (/^video\//.test(req.headers['content-type'] || '')) {
        res.setHeader('X-Content-Type-Options', 'nosniff');
    }
    next();
});

// 设置字体文件的 MIME 类型
app.use((req, res, next) => {
    if (req.path.match(/\.(woff|woff2|ttf|eot|svg)$/)) {
        const ext = path.extname(req.path).toLowerCase();
        const mimeTypes = {
            '.woff': 'font/woff',
            '.woff2': 'font/woff2',
            '.ttf': 'font/ttf',
            '.eot': 'application/vnd.ms-fontobject',
            '.svg': 'image/svg+xml'
        };
        res.setHeader('Content-Type', mimeTypes[ext] || 'application/octet-stream');
        // 允许跨域加载字体
        res.setHeader('Access-Control-Allow-Origin', '*');
    }
    next();
});

// 为HTML文件添加防缓存头
app.use((req, res, next) => {
    if (req.path.endsWith('.html')) {
        res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate, max-age=0');
        res.setHeader('Pragma', 'no-cache');
        res.setHeader('Expires', '0');
    }
    next();
});

app.use(express.static(path.join(__dirname, 'public')));

// 网盘根目录配置
const CLOUD_DIR = 'C:\\Users\\Administrator\\服务\\Web控制\\云';
const CLOUD_ROOT = path.resolve(CLOUD_DIR);
fsExtra.ensureDirSync(CLOUD_DIR);

// 管理员密码哈希（请替换为实际密码哈希）
const passwordHash = '$2a$10$tsXJvyiWcP8MDf3I5/Iym.PbMUdxT3RdDiNCY/Q7AVWEUBBpzDTPS';

// 文件上传配置
const upload = multer({
    storage: multer.diskStorage({
        destination: (req, file, cb) => {
            // 优先使用 query 参数（前端可能通过 URL 传递 path，以确保 multer 在处理文件时能获得路径）
            const requestedPath = (req.query && req.query.path) || req.body.path || '';
            const targetDir = path.join(CLOUD_DIR, requestedPath || '');
            fsExtra.ensureDirSync(targetDir);
            cb(null, targetDir);
        },
        filename: (req, file, cb) => {
            // 确保中文等非 ASCII 字符正确保存。
            const originalName = Buffer.from(file.originalname || '', 'latin1').toString('utf8');
            const ext = path.extname(originalName);
            const name = path.basename(originalName, ext);

            // 与 destination 回调中相同的目标目录计算方式
            const requestedPath = (req.query && req.query.path) || req.body.path || '';
            const targetDir = path.join(CLOUD_DIR, requestedPath || '');

            // 如果文件名冲突，则在名称后追加 " (n)"，n 从 1 开始递增，直到不冲突
            let finalName = `${name}${ext}`;
            let counter = 1;
            while (fsExtra.existsSync(path.join(targetDir, finalName))) {
                finalName = `${name} (${counter})${ext}`;
                counter += 1;
            }

            cb(null, finalName);
        }
    }),
    limits: { 
        fileSize: 1024 * 1024 * 10000, // 限制10GB
        files: 1 // 限制每次只能上传一个文件
    }
});


// 系统状态缓存
const systemStatusCache = {
    cpu: 0,
    memory: 0,
    lastUpdated: new Date().toISOString()
};

// 日志工具
const log = (message, type = 'info') => {
    const time = format(new Date(), 'yyyy-MM-dd HH:mm:ss');
    console.log(`[${time}] [${type.toUpperCase()}] ${message}`);
};

// 验证密码
// NOTE: 使用 bcrypt.compareSync 保持同步行为，简化调用处的控制流程。
// 设计考量：此项目为本地管理面板，密码验证不会承载高并发请求，
// 因此使用同步接口避免在每个路由中引入异步复杂度；若未来需要高并发或分布式
// 验证，应改为异步 bcrypt.compare 并在路由中 await 它。
const verifyPassword = (inputPassword) => bcrypt.compareSync(inputPassword, passwordHash);

// 验证路径是否在网盘目录内（安全检查）
// 使用 path.resolve + path.relative 以防止前缀匹配绕过（例如 Cloud 和 Cloud2）
// 所有来自客户端的路径都必须经过此校验，禁止绝对路径或 ".." 越界。
// 返回 true 表示路径位于 CLOUD_DIR 内 或 等于根目录（空路径）。
const isValidPath = (userPath) => {
    try {
        const cloudRoot = path.resolve(CLOUD_DIR);
        const fullPath = path.resolve(cloudRoot, userPath || '');
        const relative = path.relative(cloudRoot, fullPath);

        // relative === '' 表示等于根目录
        // 如果相对路径以 '..' 开始或是绝对路径则表示在 root 之外
        return relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative));
    } catch (err) {
        return false;
    }
};

// 获取并规范化Content-Type
const getContentType = (filePath) => {
    const lookupTypeRaw = mime.lookup(filePath) || 'application/octet-stream';
    let contentType = lookupTypeRaw;
    try {
        if (/^text\//.test(lookupTypeRaw) && !/charset=/i.test(lookupTypeRaw)) {
            contentType = lookupTypeRaw + '; charset=utf-8';
        }
        if (contentType === 'application/mp4' || /\.mp4$/i.test(filePath)) {
            contentType = 'video/mp4';
        }
    } catch (e) {
        contentType = lookupTypeRaw;
    }
    return contentType;
};

// 判断是否为视频文件
const isVideoFile = (contentType, filePath) => {
    return /^video\//.test(contentType) || contentType === 'application/mp4' || /\.(mp4|avi|mov|mkv|webm|flv|wmv)$/i.test(filePath);
};

// 计算视频分块的结束位置
const calculateVideoChunkEnd = (start, fileSize) => {
    let maxChunkSize = 2 * 1024 * 1024; // 默认2MB
    if (start === 0) {
        maxChunkSize = 10 * 1024 * 1024; // 开头10MB（包含元数据）
    } else if (start >= fileSize - 10 * 1024 * 1024) {
        maxChunkSize = 5 * 1024 * 1024; // 末尾5MB（包含可能的末尾元数据）
    }
    return Math.min(start + maxChunkSize - 1, fileSize - 1);
};

// 发送文件流（简化代码）
const sendFileStream = (res, fullPath, start, end, contentType, fileSize, inline, logPrefix = '') => {
    const chunkSize = (end - start) + 1;
    res.status(206);
    res.setHeader('Content-Range', `bytes ${start}-${end}/${fileSize}`);
    res.setHeader('Accept-Ranges', 'bytes');
    res.setHeader('Content-Length', chunkSize);
    res.setHeader('Content-Type', contentType);
    if (inline && isVideoFile(contentType, fullPath)) {
        res.setHeader('Cache-Control', 'public, max-age=3600');
    }
    if (!inline) {
        const filename = path.basename(fullPath);
        const encodedFilename = encodeURIComponent(filename);
        const asciiFilename = filename.replace(/[^ -]/g, '_').replace(/"/g, '');
        res.setHeader('Content-Disposition', `attachment; filename="${asciiFilename}"; filename*=UTF-8''${encodedFilename}`);
    }

    const highWaterMark = isVideoFile(contentType, fullPath) ? 1024 * 1024 : undefined;
    const stream = fsSync.createReadStream(fullPath, { start, end, highWaterMark });
    stream.on('error', (err) => {
        log(`文件流出错: ${err.message}`, 'error');
        try { res.destroy(); } catch (e) {}
    });
    stream.pipe(res);
    stream.on('end', () => log(`${logPrefix}传输完成: ${fullPath}, ${chunkSize} bytes`));
};

// 定时更新系统状态（每5秒）
const updateSystemStatus = async () => {
    try {
        log('开始更新系统状态');
        const [cpuLoad, memory] = await Promise.all([
            si.currentLoad(),
            si.mem()
        ]);

        // 更新缓存
        systemStatusCache.cpu = Math.round(cpuLoad.currentLoad || 0);
        systemStatusCache.memory = Math.round((memory.used / memory.total) * 100 || 0);
        systemStatusCache.lastUpdated = new Date().toISOString();
        
        log('系统状态更新成功');
    } catch (error) {
        log(`状态更新失败: ${error.message}`, 'error');
        // 单独尝试更新内存信息作为降级方案
        try {
            const memory = await si.mem();
            systemStatusCache.memory = Math.round((memory.used / memory.total) * 100 || 0);
        } catch (memError) {
            log(`内存信息更新失败: ${memError.message}`, 'error');
        }
    }
};

// 初始更新一次状态，然后定时更新
updateSystemStatus();
setInterval(updateSystemStatus, 5000);

// 接口：获取系统状态
app.get('/api/status', (req, res) => {
    res.json({
        ...systemStatusCache,
        clientIp: req.ip
    });
});

// 验证密码接口（前端可用来验证密码是否正确）
app.post('/api/auth/verify', (req, res) => {
    try {
        const password = req.body.password;
        if (!password) return res.json({ success: false, message: '未提供密码' });

        const ok = verifyPassword(password);
        if (ok) return res.json({ success: true, message: '密码正确' });
        return res.json({ success: false, message: '密码错误' });
    } catch (error) {
        return res.json({ success: false, message: error.message });
    }
});

// 系统控制接口
app.post('/api/shutdown', async (req, res) => {
    if (!verifyPassword(req.body.password)) {
        log(`关机尝试失败: 密码错误 (IP: ${req.ip})`, 'warn');
        return res.json({ success: false, message: '密码错误' });
    }
    
    log(`执行关机命令 (IP: ${req.ip})`, 'warn');
    exec('shutdown /s /t 0', (error) => {
        res.json({ 
            success: !error, 
            message: error ? `执行失败: ${error.message}` : '关机命令已执行' 
        });
    });
});

app.post('/api/restart', (req, res) => {
    if (!verifyPassword(req.body.password)) {
        log(`重启尝试失败: 密码错误 (IP: ${req.ip})`, 'warn');
        return res.json({ success: false, message: '密码错误' });
    }
    
    log(`执行重启命令 (IP: ${req.ip})`, 'warn');
    exec('shutdown /r /t 0', (error) => {
        res.json({ 
            success: !error, 
            message: error ? `执行失败: ${error.message}` : '重启命令已执行' 
        });
    });
});


// 网盘功能接口
// 1. 获取目录文件列表
app.post('/api/cloud/list', async (req, res) => {
    try {
        if (!verifyPassword(req.body.password)) {
            log(`网盘列表访问失败: 密码错误 (IP: ${req.ip})`, 'warn');
            return res.json({ success: false, message: '密码错误' });
        }

        const userPath = req.body.path || '';
        if (!isValidPath(userPath)) {
            return res.json({ success: false, message: '无效路径' });
        }

        const targetDir = path.join(CLOUD_DIR, userPath);
        const files = await fs.readdir(targetDir, { withFileTypes: true });
        
        const fileList = await Promise.all(files.map(async (file) => {
            const stats = await fs.stat(path.join(targetDir, file.name));
            return {
                name: file.name,
                isDirectory: file.isDirectory(),
                size: stats.size, // 字节数
                modified: stats.mtime.toISOString(),
                path: path.join(userPath, file.name),
                // 添加类型检测逻辑，用于决定预览链接
                type: getFileType(path.join(targetDir, file.name))
            };
        }));

        res.json({
            success: true,
            currentPath: userPath,
            parentPath: path.dirname(userPath) !== userPath ? path.dirname(userPath) : '',
            files: fileList
        });
    } catch (error) {
        log(`网盘列表获取失败: ${error.message}`, 'error');
        res.json({ success: false, message: error.message });
    }
});

// 辅助函数：确定文件类型
function getFileType(filePath) {
    const ext = path.extname(filePath).toLowerCase().replace('.', '');
    if (['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'epub'].includes(ext)) {
        return 'document';
    }
    if (['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'svg'].includes(ext)) {
        return 'image';
    }
    if (['mp4', 'avi', 'mov', 'mkv', 'webm', 'flv', 'wmv'].includes(ext)) {
        return 'video';
    }
    if (['mp3', 'wav', 'ogg', 'flac', 'aac', 'm4a'].includes(ext)) {
        return 'audio';
    }
    if (['txt', 'md', 'json', 'xml', 'log', 'csv', 'js', 'css', 'html', 'py', 'java', 'cpp', 'c', 'h', 'sql', 'ts'].includes(ext)) {
        return 'text';
    }
    return 'other';
}

// 2. 创建文件夹
app.post('/api/cloud/mkdir', async (req, res) => {
    try {
        if (!verifyPassword(req.body.password)) {
            return res.json({ success: false, message: '密码错误' });
        }

        const { path: parentPath, name } = req.body;
        if (!name || !isValidPath(parentPath)) {
            return res.json({ success: false, message: '无效参数' });
        }

        const newDirPath = path.join(CLOUD_DIR, parentPath, name);
        await fs.mkdir(newDirPath, { recursive: true });
        
        log(`创建文件夹: ${newDirPath} (IP: ${req.ip})`);
        res.json({ success: true, message: '文件夹创建成功' });
    } catch (error) {
        log(`创建文件夹失败: ${error.message}`, 'error');
        res.json({ success: false, message: error.message });
    }
});

// 3. 上传文件
app.post('/api/cloud/upload', upload.single('file'), async (req, res) => {
    try {
        if (!verifyPassword(req.body.password)) {
            // 上传失败时清理临时文件
            if (req.file) await fs.unlink(req.file.path);
            return res.json({ success: false, message: '密码错误' });
        }

        if (!req.file) {
            return res.json({ success: false, message: '未找到文件' });
        }

        log(`文件上传成功: ${req.file.path} (IP: ${req.ip})`);
        res.json({
            success: true,
            message: '文件上传成功',
            filename: req.file.filename,
            path: path.join(req.body.path || '', req.file.filename)
        });
    } catch (error) {
        log(`文件上传失败: ${error.message}`, 'error');
        res.json({ success: false, message: error.message });
    }
});


// 4. 下载文件
app.post('/api/cloud/download', async (req, res) => {
    try {
        if (!verifyPassword(req.body.password)) {
            return res.json({ success: false, message: '密码错误' });
        }

        const { path: filePath } = req.body;
        if (!filePath) {
            return res.json({ success: false, message: '未提供路径' });
        }

        if (!isValidPath(filePath)) {
            return res.json({ success: false, message: '无效路径' });
        }

        const fullPath = path.resolve(CLOUD_DIR, filePath);
        const stats = await fs.stat(fullPath);
        
        if (stats.isDirectory()) {
            return res.json({ success: false, message: '不能下载文件夹' });
        }

    // 使用流式传输并设置兼容 UTF-8 的 Content-Disposition
    const filename = path.basename(fullPath);
    const encodedFilename = encodeURIComponent(filename);
    // 为保证 header 安全，生成 ASCII 友好的 filename 作为回退
    const asciiFilename = filename.replace(/[^ -]/g, '_').replace(/"/g, '');
    const disposition = `attachment; filename="${asciiFilename}"; filename*=UTF-8''${encodedFilename}`;
    res.setHeader('Content-Disposition', disposition);
    // 使用 mime-types.lookup 来确定更准确的 Content-Type
    const lookupType = mime.lookup(fullPath) || 'application/octet-stream';
    res.setHeader('Content-Type', lookupType);
    res.setHeader('Content-Length', stats.size);

        const stream = require('fs').createReadStream(fullPath);
        stream.on('error', (err) => {
            log(`文件流出错: ${err.message}`, 'error');
            if (!res.headersSent) {
                res.status(500).json({ success: false, message: '读取文件失败' });
            } else {
                res.destroy();
            }
        });

        stream.pipe(res);
        stream.on('end', () => {
            log(`文件下载完成: ${fullPath} (IP: ${req.ip})`);
        });
    } catch (error) {
        log(`文件下载失败: ${error.message}`, 'error');
        res.json({ success: false, message: error.message });
    }
});

// 5. 删除文件/文件夹
app.post('/api/cloud/delete', async (req, res) => {
    try {
        if (!verifyPassword(req.body.password)) {
            return res.json({ success: false, message: '密码错误' });
        }

        const { path: targetPath } = req.body;
        if (!isValidPath(targetPath)) {
            return res.json({ success: false, message: '无效路径' });
        }

        const fullPath = path.join(CLOUD_DIR, targetPath);
        await fsExtra.remove(fullPath);
        
        log(`删除成功: ${fullPath} (IP: ${req.ip})`);
        res.json({ success: true, message: '删除成功' });
    } catch (error) {
        log(`删除失败: ${error.message}`, 'error');
        res.json({ success: false, message: error.message });
    }
});

// 兼容性更好的下载接口（GET），便于浏览器直接通过链接下载大文件
app.get('/api/cloud/download', async (req, res) => {
    try {
        const password = req.query.password;
        const filePath = req.query.path;

        if (!verifyPassword(password)) {
            return res.status(401).json({ success: false, message: '密码错误' });
        }

        if (!filePath) {
            return res.status(400).json({ success: false, message: '未提供路径' });
        }

        if (!isValidPath(filePath)) {
            return res.status(400).json({ success: false, message: '无效路径' });
        }

        const fullPath = path.resolve(CLOUD_DIR, filePath);
        const stats = await fs.stat(fullPath);

        if (stats.isDirectory()) {
            return res.status(400).json({ success: false, message: '不能下载文件夹' });
        }

        const inline = req.query.inline === '1' || req.query.inline === 'true';
        const contentType = getContentType(fullPath);
        const range = req.headers.range;
        const fileSize = stats.size;
        const isVideo = isVideoFile(contentType, fullPath);
        
        // 处理视频文件（预览模式）：智能分块传输
        if (isVideo && inline) {
            let start = 0;
            let end;
            
            if (range) {
                const parts = range.replace(/bytes=/, '').split('-');
                const requestedStart = parseInt(parts[0], 10);
                if (!isNaN(requestedStart) && requestedStart >= 0 && requestedStart < fileSize) {
                    start = requestedStart;
                    end = calculateVideoChunkEnd(start, fileSize);
                } else {
                    end = Math.min(10 * 1024 * 1024 - 1, fileSize - 1);
                }
            } else {
                end = Math.min(10 * 1024 * 1024 - 1, fileSize - 1);
            }
            
            log(`视频分块传输: ${fullPath}, 范围: ${start}-${end}/${fileSize} (${((end-start+1)/1024/1024).toFixed(2)}MB) (IP: ${req.ip})`);
            sendFileStream(res, fullPath, start, end, contentType, fileSize, inline, '视频分块');
            return;
        }

        // 处理Range请求
        if (range) {
            const parts = range.replace(/bytes=/, '').split('-');
            const start = parseInt(parts[0], 10);
            let end = parts[1] ? parseInt(parts[1], 10) : fileSize - 1;
            
            // 视频文件强制限制块大小
            if (isVideo) {
                end = calculateVideoChunkEnd(start, fileSize);
            }
            
            if (isNaN(start) || isNaN(end) || start > end || end >= fileSize) {
                res.status(416).setHeader('Content-Range', `bytes */${fileSize}`);
                return res.end();
            }
            
            sendFileStream(res, fullPath, start, end, contentType, fileSize, inline, '文件部分');
            return;
        }
        
        // 无Range请求：视频文件强制返回部分内容，其他文件返回完整文件
        if (isVideo && inline) {
            const start = 0;
            const end = Math.min(10 * 1024 * 1024 - 1, fileSize - 1);
            log(`视频强制分块（无Range）: ${fullPath}, 范围: ${start}-${end}/${fileSize} (${((end-start+1)/1024/1024).toFixed(2)}MB) (IP: ${req.ip})`);
            sendFileStream(res, fullPath, start, end, contentType, fileSize, inline, '视频强制分块');
            return;
        }
        
        // 返回完整文件
        res.setHeader('Accept-Ranges', 'bytes');
        res.setHeader('Content-Length', fileSize);
        res.setHeader('Content-Type', contentType);
        if (inline && isVideo) {
            res.setHeader('Cache-Control', 'public, max-age=3600');
        }
        if (!inline) {
            const filename = path.basename(fullPath);
            const encodedFilename = encodeURIComponent(filename);
            const asciiFilename = filename.replace(/[^ -]/g, '_').replace(/"/g, '');
            res.setHeader('Content-Disposition', `attachment; filename="${asciiFilename}"; filename*=UTF-8''${encodedFilename}`);
        }

        const highWaterMark = isVideo ? 1024 * 1024 : undefined;
        const stream = fsSync.createReadStream(fullPath, { highWaterMark });
        stream.on('error', (err) => {
            log(`文件流出错: ${err.message}`, 'error');
            if (!res.headersSent) {
                res.status(500).json({ success: false, message: '读取文件失败' });
            } else {
                res.destroy();
            }
        });
        stream.pipe(res);
        stream.on('end', () => log(`文件下载完成: ${fullPath} (IP: ${req.ip})`));
    } catch (error) {
        log(`文件下载失败: ${error.message}`, 'error');
        if (!res.headersSent) {
            res.status(500).json({ success: false, message: error.message });
        }
    }
});

// 支持路径形式的下载 URL
app.get('/api/cloud/download/*', async (req, res) => {
    try {
        // 从路径段中恢复原始文件路径（e.g. req.params[0] === 'some%2Fpath%2Ffile.epub'）
        const encodedPath = req.params[0] || '';
        const filePathFromUrl = decodeURIComponent(encodedPath);

        const password = req.query.password;
        const inline = req.query.inline === '1' || req.query.inline === 'true';

        if (!verifyPassword(password)) {
            return res.status(401).json({ success: false, message: '密码错误' });
        }

        if (!filePathFromUrl) {
            return res.status(400).json({ success: false, message: '未提供路径' });
        }

        if (!isValidPath(filePathFromUrl)) {
            return res.status(400).json({ success: false, message: '无效路径' });
        }

        const fullPath = path.resolve(CLOUD_DIR, filePathFromUrl);
        const stats = await fs.stat(fullPath);

        if (stats.isDirectory()) {
            return res.status(400).json({ success: false, message: '不能下载文件夹' });
        }

        const contentType = getContentType(fullPath);
        const range = req.headers.range;
        const fileSize = stats.size;
        const isVideo = isVideoFile(contentType, fullPath);
        
        // 处理视频文件（预览模式）：智能分块传输
        if (isVideo && inline) {
            let start = 0;
            let end;
            
            if (range) {
                const parts = range.replace(/bytes=/, '').split('-');
                const requestedStart = parseInt(parts[0], 10);
                if (!isNaN(requestedStart) && requestedStart >= 0 && requestedStart < fileSize) {
                    start = requestedStart;
                    end = calculateVideoChunkEnd(start, fileSize);
                } else {
                    end = Math.min(10 * 1024 * 1024 - 1, fileSize - 1);
                }
            } else {
                end = Math.min(10 * 1024 * 1024 - 1, fileSize - 1);
            }
            
            log(`视频分块传输 (path-segment): ${fullPath}, 范围: ${start}-${end}/${fileSize} (${((end-start+1)/1024/1024).toFixed(2)}MB) (IP: ${req.ip})`);
            sendFileStream(res, fullPath, start, end, contentType, fileSize, inline, '视频分块 (path-segment)');
            return;
        }

        // 处理Range请求
        if (range) {
            const parts = range.replace(/bytes=/, '').split('-');
            const start = parseInt(parts[0], 10);
            let end = parts[1] ? parseInt(parts[1], 10) : fileSize - 1;
            
            // 视频文件强制限制块大小
            if (isVideo) {
                end = calculateVideoChunkEnd(start, fileSize);
            }
            
            if (isNaN(start) || isNaN(end) || start > end || end >= fileSize) {
                res.status(416).setHeader('Content-Range', `bytes */${fileSize}`);
                return res.end();
            }
            
            sendFileStream(res, fullPath, start, end, contentType, fileSize, inline, '文件部分 (path-segment)');
            return;
        }
        
        // 无Range请求：视频文件强制返回部分内容，其他文件返回完整文件
        if (isVideo && inline) {
            const start = 0;
            const end = Math.min(10 * 1024 * 1024 - 1, fileSize - 1);
            log(`视频强制分块（无Range）(path-segment): ${fullPath}, 范围: ${start}-${end}/${fileSize} (${((end-start+1)/1024/1024).toFixed(2)}MB) (IP: ${req.ip})`);
            sendFileStream(res, fullPath, start, end, contentType, fileSize, inline, '视频强制分块 (path-segment)');
            return;
        }
        
        // 返回完整文件
        res.setHeader('Accept-Ranges', 'bytes');
        res.setHeader('Content-Length', fileSize);
        res.setHeader('Content-Type', contentType);
        if (inline && isVideo) {
            res.setHeader('Cache-Control', 'public, max-age=3600');
        }
        if (!inline) {
            const filename = path.basename(fullPath);
            const encodedFilename = encodeURIComponent(filename);
            const asciiFilename = filename.replace(/[^\u0000-\u007f]/g, '_').replace(/"/g, '');
            res.setHeader('Content-Disposition', `attachment; filename="${asciiFilename}"; filename*=UTF-8''${encodedFilename}`);
        }

        const highWaterMark = isVideo ? 1024 * 1024 : undefined;
        const stream = fsSync.createReadStream(fullPath, { highWaterMark });
        stream.on('error', (err) => {
            log(`文件流出错: ${err.message}`, 'error');
            if (!res.headersSent) {
                res.status(500).json({ success: false, message: '读取文件失败' });
            } else {
                res.destroy();
            }
        });
        stream.pipe(res);
        stream.on('end', () => log(`文件下载完成 (path-segment): ${fullPath} (IP: ${req.ip})`));
    } catch (error) {
        log(`文件下载失败 (path-segment): ${error.message}`, 'error');
        if (!res.headersSent) {
            res.status(500).json({ success: false, message: error.message });
        }
    }
});

// 6. 重命名文件/文件夹
app.post('/api/cloud/rename', async (req, res) => {
    try {
        if (!verifyPassword(req.body.password)) {
            return res.json({ success: false, message: '密码错误' });
        }

        const oldPath = req.body.path;
        const newName = req.body.newName;

        if (!oldPath || !newName) {
            return res.json({ success: false, message: '缺少参数: path 或 newName' });
        }

        if (!isValidPath(oldPath)) {
            return res.json({ success: false, message: '无效的原始路径' });
        }

        // newName 只能是单个文件/文件夹名，不能包含路径分隔符
        if (path.basename(newName) !== newName || newName.indexOf(path.sep) !== -1) {
            return res.json({ success: false, message: '无效的新名称' });
        }

        const oldFull = path.resolve(CLOUD_DIR, oldPath);
        const parentDir = path.dirname(oldPath);
        const destDir = path.resolve(CLOUD_DIR, parentDir || '');

        // 确保旧路径存在
        const oldStats = await fs.stat(oldFull);

        // 处理冲突：如果目标名已存在，则按 Windows 风格追加 " (n)"
        const ext = path.extname(newName);
        const base = path.basename(newName, ext);
        let candidate = newName;
        let counter = 1;
        while (fsExtra.existsSync(path.join(destDir, candidate))) {
            candidate = `${base} (${counter})${ext}`;
            counter += 1;
        }

        const newFull = path.join(destDir, candidate);

        await fsExtra.move(oldFull, newFull);

        log(`重命名成功: ${oldFull} -> ${newFull} (IP: ${req.ip})`);
        // 返回相对云盘路径
        const relativeNew = path.relative(path.resolve(CLOUD_DIR), newFull).split(path.sep).join('/');
        res.json({ success: true, message: '重命名成功', newName: candidate, newPath: relativeNew });
    } catch (error) {
        log(`重命名失败: ${error.message}`, 'error');
        res.json({ success: false, message: error.message });
    }
});

// 7. 批量移动文件/文件夹
app.post('/api/cloud/move', async (req, res) => {
    try {
        if (!verifyPassword(req.body.password)) {
            return res.json({ success: false, message: '密码错误' });
        }

        const items = req.body.items; // array of relative paths
        const targetPath = req.body.targetPath || '';

        if (!Array.isArray(items) || items.length === 0) {
            return res.json({ success: false, message: '未提供要移动的项' });
        }

        if (!isValidPath(targetPath)) {
            return res.json({ success: false, message: '目标路径无效' });
        }

        const results = [];
        const destDir = path.resolve(CLOUD_DIR, targetPath || '');
        await fsExtra.ensureDir(destDir);

        for (const rel of items) {
            if (!isValidPath(rel)) {
                results.push({ item: rel, success: false, message: '无效路径' });
                continue;
            }

            const srcFull = path.resolve(CLOUD_DIR, rel);
            try {
                const stats = await fs.stat(srcFull);
                // 目标文件名保留原名，处理冲突
                const baseName = path.basename(rel);
                let candidate = baseName;
                let counter = 1;
                while (fsExtra.existsSync(path.join(destDir, candidate))) {
                    const ext = path.extname(baseName);
                    const nameOnly = path.basename(baseName, ext);
                    candidate = `${nameOnly} (${counter})${ext}`;
                    counter += 1;
                }
                const destFull = path.join(destDir, candidate);
                await fsExtra.move(srcFull, destFull);
                results.push({ item: rel, success: true, dest: path.relative(path.resolve(CLOUD_DIR), destFull).split(path.sep).join('/') });
            } catch (err) {
                results.push({ item: rel, success: false, message: err.message });
            }
        }

        const moved = results.filter(r => r.success).length;
        log(`批量移动: ${moved}/${items.length} (IP: ${req.ip})`);
        res.json({ success: true, message: '批量移动完成', moved, results });
    } catch (error) {
        log(`批量移动失败: ${error.message}`, 'error');
        res.json({ success: false, message: error.message });
    }
});


// 9. 预览接口：docx 转 HTML、epub 返回 mime
app.get('/api/cloud/preview', async (req, res) => {
    try {
        const password = req.query.password;
        const filePath = req.query.path;

        if (!verifyPassword(password)) return res.status(401).json({ success: false, message: '密码错误' });
        if (!filePath) return res.status(400).json({ success: false, message: '未提供路径' });
        if (!isValidPath(filePath)) return res.status(400).json({ success: false, message: '无效路径' });

        const fullPath = path.resolve(CLOUD_DIR, filePath);
        const stats = await fs.stat(fullPath);
        if (stats.isDirectory()) return res.status(400).json({ success: false, message: '不能预览文件夹' });

        const ext = path.extname(fullPath).toLowerCase().replace('.', '');

        if (ext === 'docx') {
            // 使用 mammoth 转换为 HTML
            try {
                const result = await mammoth.convertToHtml({ path: fullPath });
                const html = `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><style>body{font-family: system-ui, Arial, sans-serif;padding:16px;}</style></head><body>${result.value}</body></html>`;
                res.setHeader('Content-Type', 'text/html; charset=utf-8');
                return res.send(html);
            } catch (err) {
                log(`docx 转换失败: ${err.message}`, 'error');
                return res.status(500).json({ success: false, message: 'DOCX 转换失败' });
            }
        }

        if (ext === 'epub') {
            const q = new URLSearchParams({ password: req.query.password || '', path: filePath, inline: '1' }).toString();
            return res.redirect(`/api/cloud/download?${q}`);
        }

        // 其他类型：重定向到 download endpoint 使用 inline=1
        const q = new URLSearchParams({ password: req.query.password || '', path: filePath, inline: '1' }).toString();
        return res.redirect(`/api/cloud/download?${q}`);
    } catch (err) {
        log(`预览失败: ${err.message}`, 'error');
        if (!res.headersSent) return res.status(500).json({ success: false, message: err.message });
    }
});

// 从MP3/音频文件ID3标签提取专辑封面
app.get('/api/cloud/audio/metadata', async (req, res) => {
    try {
        const password = req.query.password;
        const filePath = req.query.path;

        if (!verifyPassword(password)) return res.status(401).json({ success: false, message: '密码错误' });
        if (!filePath) return res.status(400).json({ success: false, message: '未提供路径' });
        if (!isValidPath(filePath)) return res.status(400).json({ success: false, message: '无效路径' });

        const fullPath = path.resolve(CLOUD_DIR, filePath);
        const stats = await fs.stat(fullPath);
        if (!stats.isFile()) return res.status(400).json({ success: false, message: '必须是文件' });

        // 解析音频元数据（包括ID3标签）
        const metadata = await parseFile(fullPath);
        
        // 检查是否有专辑封面
        let pictureBuf = null;
        let pictureMime = null;
        
        if (metadata.common && metadata.common.picture && metadata.common.picture.length > 0) {
            const pic = metadata.common.picture[0];
            pictureBuf = pic.data;
            pictureMime = pic.format || 'image/jpeg';
        }
        
        if (pictureBuf) {
            res.set('Content-Type', pictureMime);
            res.set('Cache-Control', 'public, max-age=86400');
            return res.send(pictureBuf);
        }
        
        return res.status(404).json({ success: false, message: '找不到专辑封面' });
    } catch (err) {
        log(`音频元数据提取失败: ${err.message}`, 'error');
        if (!res.headersSent) return res.status(500).json({ success: false, message: err.message });
    }
});

// 新增API：获取目录中的音频文件列表
app.post('/api/cloud/audio/playlist', async (req, res) => {
    try {
        if (!verifyPassword(req.body.password)) {
            return res.json({ success: false, message: '密码错误' });
        }

        const dirPath = req.body.path || '';
        if (!isValidPath(dirPath)) {
            return res.json({ success: false, message: '无效路径' });
        }

        const targetDir = path.join(CLOUD_DIR, dirPath);
        
        // 检查目录存在
        try {
            const stats = await fs.stat(targetDir);
            if (!stats.isDirectory()) {
                return res.json({ success: false, message: '路径不是目录' });
            }
        } catch (err) {
            return res.json({ success: false, message: '目录不存在' });
        }

        const files = await fs.readdir(targetDir);
        const audioExtensions = ['.mp3', '.wav', '.flac', '.aac', '.m4a', '.ogg', '.wma', '.opus'];
        
        // 过滤和排序音频文件
        const audioFiles = files
            .filter(file => audioExtensions.some(ext => file.toLowerCase().endsWith(ext)))
            .sort((a, b) => a.localeCompare(b))
            .map((name, index) => ({
                index: index,
                name: name,
                path: path.join(dirPath, name).replace(/\\/g, '/')
            }));

        res.json({
            success: true,
            path: dirPath,
            files: audioFiles
        });
    } catch (error) {
        log(`音频播放列表获取失败: ${error.message}`, 'error');
        res.json({ success: false, message: error.message });
    }
});

// 新增API：获取目录中的视频文件列表（用于前端构建播放列表）
app.post('/api/cloud/video/playlist', async (req, res) => {
    try {
        if (!verifyPassword(req.body.password)) {
            return res.json({ success: false, message: '密码错误' });
        }

        const dirPath = req.body.path || '';
        if (!isValidPath(dirPath)) {
            return res.json({ success: false, message: '无效路径' });
        }

        const targetDir = path.join(CLOUD_DIR, dirPath);
        
        // 检查目录存在
        try {
            const stats = await fs.stat(targetDir);
            if (!stats.isDirectory()) {
                return res.json({ success: false, message: '路径不是目录' });
            }
        } catch (err) {
            return res.json({ success: false, message: '目录不存在' });
        }

        const files = await fs.readdir(targetDir);
        const videoExtensions = ['.mp4', '.avi', '.mov', '.mkv', '.webm', '.flv', '.wmv', '.m4v'];
        
        // 过滤和排序视频文件
        const videoFiles = files
            .filter(file => videoExtensions.some(ext => file.toLowerCase().endsWith(ext)))
            .sort((a, b) => a.localeCompare(b))
            .map((name, index) => ({
                index: index,
                name: name,
                path: path.join(dirPath, name).replace(/\\/g, '/')
            }));

        res.json({
            success: true,
            path: dirPath,
            files: videoFiles
        });
    } catch (error) {
        log(`视频播放列表获取失败: ${error.message}`, 'error');
        res.json({ success: false, message: error.message });
    }
});

// 启动服务
// 允许通过环境变量 PORT 指定端口，便于开发/测试时使用非 80 端口运行（无需管理员权限）
const PORT = process.env.PORT || 80;
const server = app.listen(PORT, () => {
    log(`HTTP服务已启动，访问 http://localhost:${PORT}`);
    log(`网盘根目录: ${CLOUD_DIR}`);
    log('提示：请以管理员身份运行，否则可能无法执行系统命令');
});
