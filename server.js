const path = require('path');

// .env 必须从"可执行文件所在目录"读取：
// 双击 exe 时工作目录可能是 C:\Windows\System32 之类，
// 用默认的 cwd 相对路径会找不到配置。放在文件顶部先解析再 load。
const IS_PACKAGED_EARLY = typeof process.pkg !== 'undefined';
const BASE_DIR_EARLY = IS_PACKAGED_EARLY ? path.dirname(process.execPath) : __dirname;
require('dotenv').config({ path: path.join(BASE_DIR_EARLY, '.env') });

const express = require('express');
const { spawn } = require('child_process');
const si = require('systeminformation');
const bcrypt = require('bcryptjs');
const { format } = require('date-fns');
const fs = require('fs').promises;
const fsSync = require('fs');
const fsExtra = require('fs-extra');
const mammoth = require('mammoth');
const mime = require('mime-types');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const { parseFile } = require('music-metadata');
const jwt = require('jsonwebtoken');
const isPathInside = require('is-path-inside').default;
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const winston = require('winston');
require('winston-daily-rotate-file');

const app = express();

/* ==========================================================================
   运行根目录解析（支持打包成 exe 后运行）
   --------------------------------------------------------------------------
   打包后 process.pkg 为真，此时 __dirname 指向 exe 内部的虚拟路径
   （形如 C:\snapshot\...），用它读写文件会失败。因此：
     · 已打包 -> 取 exe 所在目录，public/ 与 .env 放在 exe 同级
     · 未打包 -> 仍是项目目录，开发方式不变
   所有需要"落盘"的路径（public、logs、网盘默认目录）都基于 BASE_DIR。
   ========================================================================== */
const IS_PACKAGED = typeof process.pkg !== 'undefined';
const BASE_DIR = IS_PACKAGED ? path.dirname(process.execPath) : __dirname;

// 静态资源目录：打包后 public/ 与 exe 同级（保持前端可随时替换，无需重新打包）
const PUBLIC_DIR = path.join(BASE_DIR, 'public');

if (!fsSync.existsSync(PUBLIC_DIR)) {
    console.error(
        `\n[启动失败] 未找到静态资源目录：\n  ${PUBLIC_DIR}\n\n` +
        `请确认 public 文件夹与可执行文件放在同一目录下。\n`
    );
    process.exit(1);
}

// 限制请求体大小为 1MB，防止内存耗尽
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ limit: '1mb', extended: true }));

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

app.use(express.static(PUBLIC_DIR));

// ========== 安全中间件配置 ==========

// Cookie 解析器
app.use(cookieParser());

// Helmet 安全头（包含 CSP）
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "blob:"],
            connectSrc: ["'self'"],
            fontSrc: ["'self'", "data:"],
            objectSrc: ["'none'"],
            baseUri: ["'self'"],
            formAction: ["'self'"]
        }
    },
    crossOriginEmbedderPolicy: false, // 允许跨域资源加载
    hsts: {
        maxAge: 31536000, // 1年
        includeSubDomains: true,
        preload: true
    }
}));

// 速率限制配置 - 支持代理环境 (x-forwarded-for)
const getClientIp = (req) => {
    return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || req.socket?.remoteAddress || 'unknown';
};

const authLimiter = rateLimit({
    windowMs: 60 * 1000, // 1分钟
    max: 5, // 最多5次请求
    message: { success: false, message: '请求过于频繁，请稍后再试' },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: getClientIp
});

const uploadLimiter = rateLimit({
    windowMs: 60 * 1000, // 1分钟
    max: 10, // 最多10次上传
    message: { success: false, message: '上传过于频繁，请稍后再试' },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: getClientIp
});

const apiLimiter = rateLimit({
    windowMs: 60 * 1000, // 1分钟
    max: 60, // 最多60次API请求
    message: { success: false, message: '请求过于频繁，请稍后再试' },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: getClientIp
});

// 应用速率限制
app.use('/api/auth/login', authLimiter);
app.use('/api/cloud/upload', uploadLimiter);
app.use('/api/', apiLimiter);

// Winston 结构化日志
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
        winston.format.errors({ stack: true }),
        winston.format.printf(({ timestamp, level, message, ...meta }) => {
            let log = `${timestamp} [${level.toUpperCase()}] ${message}`;
            if (Object.keys(meta).length > 0) {
                // 脱敏敏感字段
                const sanitized = { ...meta };
                if (sanitized.password) sanitized.password = '[REDACTED]';
                if (sanitized.token) sanitized.token = '[REDACTED]';
                if (sanitized.authorization) sanitized.authorization = '[REDACTED]';
                if (sanitized.cookie) sanitized.cookie = '[REDACTED]';
                log += ` ${JSON.stringify(sanitized)}`;
            }
            return log;
        })
    ),
    transports: [
        new winston.transports.Console({
            format: winston.format.combine(
                winston.format.colorize(),
                winston.format.printf(({ timestamp, level, message, ...meta }) => {
                    let log = `${timestamp} [${level}] ${message}`;
                    if (Object.keys(meta).length > 0) {
                        const sanitized = { ...meta };
                        if (sanitized.password) sanitized.password = '[REDACTED]';
                        if (sanitized.token) sanitized.token = '[REDACTED]';
                        if (sanitized.authorization) sanitized.authorization = '[REDACTED]';
                        if (sanitized.cookie) sanitized.cookie = '[REDACTED]';
                        log += ` ${JSON.stringify(sanitized)}`;
                    }
                    return log;
                })
            )
        }),
        new winston.transports.DailyRotateFile({
            filename: 'logs/application-%DATE%.log',
            datePattern: 'YYYY-MM-DD',
            maxSize: '20m',
            maxFiles: '30d',
            dirname: path.join(BASE_DIR, 'logs'),
            format: winston.format.combine(
                winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
                winston.format.json()
            )
        }),
        new winston.transports.DailyRotateFile({
            filename: 'logs/error-%DATE%.log',
            datePattern: 'YYYY-MM-DD',
            maxSize: '20m',
            maxFiles: '30d',
            dirname: path.join(BASE_DIR, 'logs'),
            level: 'error',
            format: winston.format.combine(
                winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
                winston.format.json()
            )
        })
    ]
});

// 确保日志目录存在
fsExtra.ensureDirSync(path.join(BASE_DIR, 'logs'));

// JWT 配置
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
    logger.error('JWT_SECRET 环境变量未设置，请在 .env 文件中配置');
    process.exit(1);
}
const JWT_EXPIRY = process.env.JWT_EXPIRY || '7d'; // 7天过期

// Token 验证中间件
const authenticateToken = (req, res, next) => {
    // 优先从 HttpOnly Cookie 获取 token
    const token = req.cookies?.authToken;
    
    // 兼容：从 Authorization Header 获取（用于 API 客户端）
    const authHeader = req.headers['authorization'];
    const headerToken = authHeader && authHeader.split(' ')[1];
    
    const finalToken = token || headerToken;
    
    if (!finalToken) {
        return res.status(401).json({ success: false, message: '未授权，请先登录' });
    }
    
    jwt.verify(finalToken, JWT_SECRET, (err, user) => {
        if (err) {
            logger.warn('Token 验证失败', { ip: req.ip, error: err.message });
            return res.status(403).json({ success: false, message: 'Token 无效或已过期' });
        }
        req.user = user;
        next();
    });
};

// 登录接口 - 签发 JWT 并设置 HttpOnly Cookie
app.post('/api/auth/login', async (req, res) => {
    try {
        const { password } = req.body;
        if (!password) {
            return res.json({ success: false, message: '未提供密码' });
        }
        
        const ok = verifyPassword(password);
        if (!ok) {
            logger.warn('登录失败：密码错误', { ip: req.ip });
            return res.json({ success: false, message: '密码错误' });
        }
        
        // 签发 JWT
        const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: JWT_EXPIRY });
        
        // 设置 HttpOnly Cookie
        // secure: 仅在实际使用 HTTPS 时设为 true（支持反向代理的 x-forwarded-proto）
        const isSecure = req.secure || req.headers['x-forwarded-proto'] === 'https';
        res.cookie('authToken', token, {
            httpOnly: true,
            secure: isSecure,
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000 // 7天
        });
        
        logger.info('登录成功', { ip: req.ip });
        res.json({ success: true, message: '登录成功' });
    } catch (error) {
        logger.error('登录接口错误', { ip: req.ip, error: error.message });
        res.json({ success: false, message: error.message });
    }
});

// 登出接口 - 清除 Cookie
app.post('/api/auth/logout', (req, res) => {
    const isSecure = req.secure || req.headers['x-forwarded-proto'] === 'https';
    res.clearCookie('authToken', {
        httpOnly: true,
        secure: isSecure,
        sameSite: 'strict'
    });
    logger.info('登出', { ip: req.ip });
    res.json({ success: true, message: '已登出' });
});

// 获取当前用户信息
app.get('/api/auth/me', authenticateToken, (req, res) => {
    res.json({ success: true, user: req.user });
});

// 网盘根目录配置（从环境变量读取，默认为可执行文件同级的 云 文件夹）
// 规范化路径：处理 .env 中可能存在的双反斜杠等问题
const rawCloudDir = process.env.CLOUD_DIR || path.join(BASE_DIR, '云');
const CLOUD_DIR = path.normalize(rawCloudDir.replace(/\\\\/g, '\\'));
const CLOUD_ROOT = path.resolve(CLOUD_DIR);

// 网盘目录必须可写；不可写时给出明确提示而不是静默失败
try {
    fsExtra.ensureDirSync(CLOUD_DIR);
} catch (err) {
    console.error(
        `\n[启动失败] 无法创建网盘目录：\n  ${CLOUD_DIR}\n` +
        `原因：${err.message}\n\n` +
        `如果程序放在 Program Files 等受保护位置，请在 .env 中指定一个可写目录，例如：\n` +
        `  CLOUD_DIR=D:\\\\Cloud\n`
    );
    process.exit(1);
}

// 管理员密码哈希（从环境变量读取，请在 .env 中设置 PASSWORD_HASH）
const passwordHash = process.env.PASSWORD_HASH;
if (!passwordHash) {
    logger.error('PASSWORD_HASH 环境变量未设置，请在 .env 文件中配置（使用 bcrypt 生成的哈希）');
    process.exit(1);
}

// 文件上传配置
// 禁止的 Windows 保留设备名
const WINDOWS_RESERVED_NAMES = ['CON', 'PRN', 'AUX', 'NUL', 
    'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9',
    'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9'];

// 禁止的可执行文件扩展名
const EXECUTABLE_EXTENSIONS = ['.exe', '.bat', '.cmd', '.ps1', '.msi', '.scr', '.vbs', '.js', '.jar', '.com', '.pif', '.application', '.gadget', '.msc', '.msp', '.hta', '.cpl', '.inf', '.reg', '.scf', '.lnk', '.wsf', '.wsh', '.ps1xml', '.ps2', '.ps2xml', '.psc1', '.psc2', '.msh', '.msh1', '.msh2', '.mshxml', '.msh1xml', '.msh2xml', '.jse', '.vbe', '.ws', '.wsc'];

// 检查文件名是否为 Windows 保留名
const isWindowsReservedName = (filename) => {
    const nameWithoutExt = path.basename(filename, path.extname(filename)).toUpperCase();
    return WINDOWS_RESERVED_NAMES.includes(nameWithoutExt);
};

// 检查文件扩展名是否为可执行文件
const isExecutableExtension = (filename) => {
    const ext = path.extname(filename).toLowerCase();
    return EXECUTABLE_EXTENSIONS.includes(ext);
};

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
            // 使用原子性检查避免竞态条件：尝试以独占模式创建文件，失败则重试
            let finalName = `${name}${ext}`;
            let counter = 1;
            const maxAttempts = 1000; // 防止无限循环
            
            while (counter <= maxAttempts) {
                const fullPath = path.join(targetDir, finalName);
                try {
                    // 尝试以独占模式创建文件 (wx flag)，如果文件已存在会抛出 EEXIST
                    const fd = fsSync.openSync(fullPath, 'wx');
                    fsSync.closeSync(fd);
                    // 删除刚创建的空文件，multer 会重新写入实际内容
                    fsSync.unlinkSync(fullPath);
                    break; // 成功找到可用文件名
                } catch (err) {
                    if (err.code === 'EEXIST') {
                        // 文件已存在，尝试下一个名称
                        counter += 1;
                        finalName = `${name} (${counter})${ext}`;
                    } else {
                        // 其他错误，传递给 multer 处理
                        return cb(err);
                    }
                }
            }
            
            if (counter > maxAttempts) {
                return cb(new Error('无法生成唯一文件名，尝试次数过多'));
            }

            cb(null, finalName);
        }
    }),
    fileFilter: (req, file, cb) => {
        const originalName = Buffer.from(file.originalname || '', 'latin1').toString('utf8');
        
        // 1. 检查 Windows 保留名
        if (isWindowsReservedName(originalName)) {
            logger.warn('上传被拒绝：Windows 保留文件名', { ip: req.ip, filename: originalName });
            return cb(new Error('不允许上传 Windows 保留文件名 (CON, PRN, AUX, NUL, COM1-9, LPT1-9)'), false);
        }
        
        // 2. 检查可执行文件扩展名
        if (isExecutableExtension(originalName)) {
            logger.warn('上传被拒绝：可执行文件扩展名', { ip: req.ip, filename: originalName });
            return cb(new Error('不允许上传可执行文件 (.exe, .bat, .cmd, .ps1, .msi, .scr, .vbs, .js, .jar 等)'), false);
        }
        
        // 3. MIME 类型检查（仅记录警告，不阻止上传）
        const expectedMime = mime.lookup(originalName);
        if (expectedMime && file.mimetype !== expectedMime) {
            logger.warn('MIME 类型不匹配', { 
                ip: req.ip, 
                filename: originalName, 
                declaredMime: file.mimetype, 
                expectedMime 
            });
        }
        
        cb(null, true);
    },
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

// 缓存过期时间（毫秒）
const SYSTEM_STATUS_CACHE_TTL = 60000; // 60秒

// 验证密码 - 使用异步 bcrypt.compare 避免阻塞事件循环
const verifyPassword = async (inputPassword) => {
    return await bcrypt.compare(inputPassword, passwordHash);
};

// 验证路径是否在网盘目录内（安全检查）
// 使用 path.resolve + path.relative + is-path-inside 以防止前缀匹配绕过（例如 Cloud 和 Cloud2）
// 所有来自客户端的路径都必须经过此校验，禁止绝对路径或 ".." 越界。
// 返回 true 表示路径位于 CLOUD_DIR 内 或 等于根目录（空路径）。
const isValidPath = (userPath) => {
    try {
        // 使用已规范化的 CLOUD_ROOT，确保一致性
        const cloudRoot = CLOUD_ROOT;
        // 规范化用户路径后再解析，防止路径遍历和编码问题
        const normalizedUserPath = path.normalize(userPath || '').replace(/^[\/\\]+/, '');
        const fullPath = path.resolve(cloudRoot, normalizedUserPath);
        
        // 1. 基础检查：使用 is-path-inside 库（更安全）
        // 先规范化两个路径再比较，避免大小写、分隔符、编码差异导致的误判
        const normCloudRoot = path.normalize(cloudRoot);
        const normFullPath = path.normalize(fullPath);
        
        if (!isPathInside(normFullPath, normCloudRoot) && normFullPath !== normCloudRoot) {
            return false;
        }
        
        // 2. 禁止 Windows 保留设备名（CON, PRN, AUX, NUL, COM1-9, LPT1-9）
        const basename = path.basename(fullPath).toUpperCase();
        const reservedNames = ['CON', 'PRN', 'AUX', 'NUL', 
            'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9',
            'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9'];
        const nameWithoutExt = basename.split('.')[0];
        if (reservedNames.includes(nameWithoutExt)) {
            return false;
        }
        
        // 3. 禁止 UNC 路径（\\server\share）
        if (fullPath.startsWith('\\\\')) {
            return false;
        }
        
        // 4. 禁止跨驱动器访问（确保在同一驱动器）
        const cloudRootDrive = path.parse(cloudRoot).root;
        const fullPathDrive = path.parse(fullPath).root;
        if (cloudRootDrive !== fullPathDrive) {
            return false;
        }
        
        // 5. 禁止符号链接攻击（检查真实路径是否仍在 cloudRoot 内）
        try {
            const realPath = fsSync.realpathSync.native(fullPath);
            if (!isPathInside(realPath, cloudRoot) && realPath !== cloudRoot) {
                return false;
            }
        } catch (e) {
            // 文件不存在时忽略 realpath 检查
        }
        
        return true;
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
    // 防御性检查：文件大小必须大于0
    if (fileSize <= 0) {
        return 0;
    }
    // 防御性检查：start 不能大于等于文件大小
    if (start >= fileSize) {
        return fileSize - 1;
    }
    let maxChunkSize = 2 * 1024 * 1024; // 默认2MB
    if (start === 0) {
        maxChunkSize = 10 * 1024 * 1024; // 开头10MB（包含元数据）
    } else if (start >= fileSize - 10 * 1024 * 1024) {
        maxChunkSize = 5 * 1024 * 1024; // 末尾5MB（包含可能的末尾元数据）
    }
    // 确保结束位置不超过文件大小
    const end = Math.min(start + maxChunkSize - 1, fileSize - 1);
    // 确保结束位置不小于开始位置
    return Math.max(end, start);
};

// 发送文件流（支持视频分块流式传输）
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
        logger.error('文件流出错', { error: err.message });
        try { res.destroy(); } catch (e) {}
    });
    stream.pipe(res);
    stream.on('end', () => logger.info(`${logPrefix}传输完成`, { path: fullPath, bytes: chunkSize }));
};

// 处理视频分块传输 - 专为 DPlayer 优化
// 当收到 Range 请求时，根据 start position 计算 appropriate chunk size
// DPlayer 通常会请求连续的小块，我们需要确保每个块都有合适的大小
const handleVideoChunk = (req, res, fullPath, fileSize, contentType, inline = false) => {
    const range = req.headers.range;
    let start = 0;
    let end;
    
    if (range) {
        const parts = range.replace(/bytes=/, '').split('-');
        const requestedStart = parseInt(parts[0], 10);
        if (!isNaN(requestedStart) && requestedStart >= 0 && requestedStart < fileSize) {
            start = requestedStart;
        } else {
            // 无效的 Range 请求，返回整个文件开头
            start = 0;
        }
    }
    
    // 根据 start position 计算合适的块大小
    // 开头返回较大块（包含元数据），中间返回标准块，末尾返回较小块
    let maxChunkSize;
    if (start === 0) {
        // 开头：返回 10MB 包含元数据，让 DPlayer 可以快速获取第一帧
        maxChunkSize = 10 * 1024 * 1024;
    } else if (start >= fileSize - 10 * 1024 * 1024) {
        // 末尾：返回 5MB 包含可能的末尾元数据
        maxChunkSize = 5 * 1024 * 1024;
    } else {
        // 中间：返回 2MB 标准块
        maxChunkSize = 2 * 1024 * 1024;
    }
    
    end = Math.min(start + maxChunkSize - 1, fileSize - 1);
    
    // 确保结束位置不小于开始位置
    if (end < start) {
        end = start;
    }
    
    // 设置响应头
    res.status(206);
    res.setHeader('Content-Range', `bytes ${start}-${end}/${fileSize}`);
    res.setHeader('Accept-Ranges', 'bytes');
    res.setHeader('Content-Length', (end - start) + 1);
    res.setHeader('Content-Type', contentType);
    
    if (inline && isVideoFile(contentType, fullPath)) {
        res.setHeader('Cache-Control', 'public, max-age=3600');
    }
    
    // 记录请求信息
    logger.info(`视频分块传输`, { 
        ip: req.ip, 
        path: fullPath, 
        range: `${start}-${end}/${fileSize}`, 
        sizeMB: ((end-start+1)/1024/1024).toFixed(2) 
    });
    
    // 发送数据流
    const highWaterMark = isVideoFile(contentType, fullPath) ? 1024 * 1024 : undefined;
    const stream = fsSync.createReadStream(fullPath, { start, end, highWaterMark });
    stream.on('error', (err) => {
        logger.error('文件流出错', { error: err.message });
        try { res.destroy(); } catch (e) {}
    });
    stream.pipe(res);
    stream.on('end', () => logger.info(`视频分块传输完成`, { path: fullPath, bytes: (end-start+1) }));
};

// 定时更新系统状态
const updateSystemStatus = async () => {
    try {
        logger.info('开始更新系统状态');
        const [cpuLoad, memory] = await Promise.all([
            si.currentLoad(),
            si.mem()
        ]);

        // 更新缓存
        systemStatusCache.cpu = Math.round(cpuLoad.currentLoad || 0);
        systemStatusCache.memory = Math.round((memory.used / memory.total) * 100 || 0);
        systemStatusCache.lastUpdated = new Date().toISOString();
        
        logger.info('系统状态更新成功');
    } catch (error) {
        logger.error('状态更新失败', { error: error.message });
        // 单独尝试更新内存信息作为降级方案
        try {
            const memory = await si.mem();
            systemStatusCache.memory = Math.round((memory.used / memory.total) * 100 || 0);
        } catch (memError) {
            logger.error('内存信息更新失败', { error: memError.message });
        }
    }
};

// 初始更新一次状态，然后定时更新
updateSystemStatus();
setInterval(updateSystemStatus, 30000);

// 接口：获取系统状态
app.get('/api/status', (req, res) => {
    const now = Date.now();
    const lastUpdated = new Date(systemStatusCache.lastUpdated).getTime();
    
    // 如果缓存过期，返回 503 服务不可用
    if (now - lastUpdated > SYSTEM_STATUS_CACHE_TTL) {
        return res.status(503).json({
            success: false,
            message: '系统状态暂时不可用，请稍后重试',
            lastUpdated: systemStatusCache.lastUpdated
        });
    }
    
    res.json({
        ...systemStatusCache,
        clientIp: req.ip
    });
});

// 系统控制接口 - 使用 authenticateToken 中间件和 spawn 防止命令注入
app.post('/api/shutdown', authenticateToken, async (req, res) => {
    logger.warn('执行关机命令', { ip: req.ip, user: req.user });
    
    // 使用 spawn 代替 exec，防止命令注入
    const shutdownProcess = spawn('shutdown', ['/s', '/t', '0'], { windowsHide: true });
    
    shutdownProcess.on('error', (error) => {
        logger.error('关机命令执行失败', { ip: req.ip, error: error.message });
        res.json({ success: false, message: `执行失败: ${error.message}` });
    });
    
    shutdownProcess.on('close', (code) => {
        if (code === 0) {
            logger.warn('关机命令已执行', { ip: req.ip });
            res.json({ success: true, message: '关机命令已执行' });
        } else {
            logger.error('关机命令返回非零退出码', { ip: req.ip, code });
            res.json({ success: false, message: `执行失败，退出码: ${code}` });
        }
    });
});

app.post('/api/restart', authenticateToken, (req, res) => {
    logger.warn('执行重启命令', { ip: req.ip, user: req.user });
    
    // 使用 spawn 代替 exec，防止命令注入
    const restartProcess = spawn('shutdown', ['/r', '/t', '0'], { windowsHide: true });
    
    restartProcess.on('error', (error) => {
        logger.error('重启命令执行失败', { ip: req.ip, error: error.message });
        res.json({ success: false, message: `执行失败: ${error.message}` });
    });
    
    restartProcess.on('close', (code) => {
        if (code === 0) {
            logger.warn('重启命令已执行', { ip: req.ip });
            res.json({ success: true, message: '重启命令已执行' });
        } else {
            logger.error('重启命令返回非零退出码', { ip: req.ip, code });
            res.json({ success: false, message: `执行失败，退出码: ${code}` });
        }
    });
});


// 网盘功能接口 - 使用 authenticateToken 中间件
// 1. 获取目录文件列表
app.post('/api/cloud/list', authenticateToken, async (req, res) => {
    try {
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
        logger.error('网盘列表获取失败', { ip: req.ip, error: error.message });
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
app.post('/api/cloud/mkdir', authenticateToken, async (req, res) => {
    try {
        const { path: parentPath, name } = req.body;
        if (!name || !isValidPath(parentPath)) {
            return res.json({ success: false, message: '无效参数' });
        }

        const newDirPath = path.join(CLOUD_DIR, parentPath, name);
        await fs.mkdir(newDirPath, { recursive: true });
        
        logger.info('创建文件夹', { ip: req.ip, path: newDirPath });
        res.json({ success: true, message: '文件夹创建成功' });
    } catch (error) {
        logger.error('创建文件夹失败', { ip: req.ip, error: error.message });
        res.json({ success: false, message: error.message });
    }
});

// 3. 上传文件
app.post('/api/cloud/upload', authenticateToken, upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.json({ success: false, message: '未找到文件' });
        }

        logger.info('文件上传成功', { ip: req.ip, path: req.file.path });
        res.json({
            success: true,
            message: '文件上传成功',
            filename: req.file.filename,
            path: path.join(req.body.path || '', req.file.filename)
        });
    } catch (error) {
        logger.error('文件上传失败', { ip: req.ip, error: error.message });
        res.json({ success: false, message: error.message });
    }
});


// 4. 下载文件 (POST)
app.post('/api/cloud/download', authenticateToken, async (req, res) => {
    try {
        const { path: filePath } = req.body;
        if (!filePath) {
            return res.json({ success: false, message: '未提供路径' });
        }

        if (!isValidPath(filePath)) {
            return res.json({ success: false, message: '无效路径' });
        }

        const fullPath = path.resolve(CLOUD_ROOT, filePath);
        const stats = await fs.stat(fullPath);
        
        if (stats.isDirectory()) {
            return res.json({ success: false, message: '不能下载文件夹' });
        }

        // 处理视频文件流式传输（支持 DPlayer 分块播放）
        const inline = req.query.inline === '1' || req.query.inline === 'true';
        const contentType = getContentType(fullPath);
        const fileSize = stats.size;
        const isVideo = isVideoFile(contentType, fullPath);
        
        // 如果是视频文件且请求 inline 播放，使用分块传输模式
        if (isVideo && inline) {
            handleVideoChunk(req, res, fullPath, fileSize, contentType, inline);
            return;
        }
        
        // 处理Range请求（用于视频 seeking 或文件部分下载）
        const range = req.headers.range;
        if (range && isVideo) {
            handleVideoChunk(req, res, fullPath, fileSize, contentType, false);
            return;
        }
        
        // 无Range请求：视频文件强制返回部分内容（前10MB），其他文件返回完整文件
        if (isVideo && inline) {
            // 对于视频预览，返回前10MB作为样本
            const end = Math.min(10 * 1024 * 1024 - 1, fileSize - 1);
            const chunkSize = (end - 0) + 1;
            
            res.status(206);
            res.setHeader('Content-Range', `bytes 0-${end}/${fileSize}`);
            res.setHeader('Accept-Ranges', 'bytes');
            res.setHeader('Content-Length', chunkSize);
            res.setHeader('Content-Type', contentType);
            res.setHeader('Cache-Control', 'public, max-age=3600');
            
            const stream = fsSync.createReadStream(fullPath, { start: 0, end, highWaterMark: 1024 * 1024 });
            stream.on('error', (err) => {
                logger.error('文件流出错', { error: err.message });
                if (!res.headersSent) {
                    res.status(500).json({ success: false, message: '读取文件失败' });
                } else {
                    res.destroy();
                }
            });
            stream.pipe(res);
            stream.on('end', () => logger.info('视频预览传输完成', { ip: req.ip, path: fullPath, bytes: chunkSize }));
            return;
        }
        
        // 完整文件下载（非视频或非inline模式）
        res.setHeader('Content-Length', fileSize);
        
        const stream = fsSync.createReadStream(fullPath);
        stream.on('error', (err) => {
            logger.error('文件流出错', { error: err.message });
            if (!res.headersSent) {
                res.status(500).json({ success: false, message: '读取文件失败' });
            } else {
                res.destroy();
            }
        });
        stream.pipe(res);
        stream.on('end', () => logger.info('文件下载完成', { ip: req.ip, path: fullPath }));
    } catch (error) {
        logger.error('文件下载失败', { ip: req.ip, error: error.message });
        res.json({ success: false, message: error.message });
    }
});

// 5. 删除文件/文件夹
app.post('/api/cloud/delete', authenticateToken, async (req, res) => {
    try {
        const { path: targetPath } = req.body;
        if (!isValidPath(targetPath)) {
            return res.json({ success: false, message: '无效路径' });
        }

        const fullPath = path.join(CLOUD_DIR, targetPath);
        await fsExtra.remove(fullPath);
        
        logger.info('删除成功', { ip: req.ip, path: fullPath });
        res.json({ success: true, message: '删除成功' });
    } catch (error) {
        logger.error('删除失败', { ip: req.ip, error: error.message });
        res.json({ success: false, message: error.message });
    }
});

// 共享的文件下载处理逻辑
const handleFileDownload = async (req, res, fullPath, filePathForLog, logPrefix = '') => {
    try {
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
            
            logger.info(`视频分块传输${logPrefix}`, { ip: req.ip, path: filePathForLog, range: `${start}-${end}/${fileSize}`, sizeMB: ((end-start+1)/1024/1024).toFixed(2) });
            sendFileStream(res, fullPath, start, end, contentType, fileSize, inline, `视频分块${logPrefix}`);
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
            
            sendFileStream(res, fullPath, start, end, contentType, fileSize, inline, `文件部分${logPrefix}`);
            return;
        }
        
        // 无Range请求：视频文件强制返回部分内容，其他文件返回完整文件
        if (isVideo && inline) {
            const start = 0;
            const end = Math.min(10 * 1024 * 1024 - 1, fileSize - 1);
            logger.info(`视频强制分块（无Range）${logPrefix}`, { ip: req.ip, path: filePathForLog, range: `${start}-${end}/${fileSize}`, sizeMB: ((end-start+1)/1024/1024).toFixed(2) });
            sendFileStream(res, fullPath, start, end, contentType, fileSize, inline, `视频强制分块${logPrefix}`);
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
            logger.error('文件流出错', { ip: req.ip, error: err.message });
            if (!res.headersSent) {
                res.status(500).json({ success: false, message: '读取文件失败' });
            } else {
                res.destroy();
            }
        });
        stream.pipe(res);
        stream.on('end', () => logger.info('文件下载完成', { ip: req.ip, path: filePathForLog }));
    } catch (error) {
        logger.error('文件下载失败', { ip: req.ip, error: error.message });
        if (!res.headersSent) {
            res.status(500).json({ success: false, message: error.message });
        }
    }
};

// 兼容性更好的下载接口（GET），便于浏览器直接通过链接下载大文件
app.get('/api/cloud/download', authenticateToken, async (req, res) => {
    try {
        const filePath = req.query.path;

        if (!filePath) {
            return res.status(400).json({ success: false, message: '未提供路径' });
        }

        if (!isValidPath(filePath)) {
            return res.status(400).json({ success: false, message: '无效路径' });
        }

        const fullPath = path.resolve(CLOUD_ROOT, filePath);
        await handleFileDownload(req, res, fullPath, fullPath);
    } catch (error) {
        logger.error('文件下载失败', { ip: req.ip, error: error.message });
        if (!res.headersSent) {
            res.status(500).json({ success: false, message: error.message });
        }
    }
});

// 支持路径形式的下载 URL
app.get('/api/cloud/download/*', authenticateToken, async (req, res) => {
    try {
        // 从路径段中恢复原始文件路径（e.g. req.params[0] === 'some%2Fpath%2Ffile.epub'）
        const encodedPath = req.params[0] || '';
        const filePathFromUrl = decodeURIComponent(encodedPath);

        const inline = req.query.inline === '1' || req.query.inline === 'true';

        if (!filePathFromUrl) {
            return res.status(400).json({ success: false, message: '未提供路径' });
        }

        if (!isValidPath(filePathFromUrl)) {
            return res.status(400).json({ success: false, message: '无效路径' });
        }

        const fullPath = path.resolve(CLOUD_ROOT, filePathFromUrl);
        await handleFileDownload(req, res, fullPath, fullPath, ' (path-segment)');
    } catch (error) {
        logger.error('文件下载失败', { ip: req.ip, error: error.message });
        if (!res.headersSent) {
            res.status(500).json({ success: false, message: error.message });
        }
    }
});

// 6. 重命名文件/文件夹
app.post('/api/cloud/rename', authenticateToken, async (req, res) => {
    try {
        const oldPath = req.body.path;
        const newName = req.body.newName;

        if (!oldPath || !newName) {
            return res.json({ success: false, message: '缺少参数: path 或 newName' });
        }

        if (!isValidPath(oldPath)) {
            return res.json({ success: false, message: '无效的原始路径' });
        }

        // newName 只能是单个文件/文件夹名，不能包含路径分隔符 (Windows 和 Unix)
        if (path.basename(newName) !== newName || newName.includes(path.sep) || newName.includes('/')) {
            return res.json({ success: false, message: '无效的新名称' });
        }

        const oldFull = path.resolve(CLOUD_ROOT, oldPath);
        const parentDir = path.dirname(oldPath);
        const destDir = path.resolve(CLOUD_ROOT, parentDir || '');

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

        logger.info('重命名成功', { ip: req.ip, oldPath: oldFull, newPath: newFull });
        // 返回相对云盘路径
        const relativeNew = path.relative(CLOUD_ROOT, newFull).split(path.sep).join('/');
        res.json({ success: true, message: '重命名成功', newName: candidate, newPath: relativeNew });
    } catch (error) {
        logger.error('重命名失败', { ip: req.ip, error: error.message });
        res.json({ success: false, message: error.message });
    }
});

// 7. 批量移动文件/文件夹
app.post('/api/cloud/move', authenticateToken, async (req, res) => {
    try {
        const items = req.body.items; // array of relative paths
        const targetPath = req.body.targetPath || '';

        if (!Array.isArray(items) || items.length === 0) {
            return res.json({ success: false, message: '未提供要移动的项' });
        }

        if (!isValidPath(targetPath)) {
            return res.json({ success: false, message: '目标路径无效' });
        }

        const results = [];
        const destDir = path.resolve(CLOUD_ROOT, targetPath || '');
        await fsExtra.ensureDir(destDir);

        for (const rel of items) {
            if (!isValidPath(rel)) {
                results.push({ item: rel, success: false, message: '无效路径' });
                continue;
            }

            const srcFull = path.resolve(CLOUD_ROOT, rel);
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
                results.push({ item: rel, success: true, dest: path.relative(CLOUD_ROOT, destFull).split(path.sep).join('/') });
            } catch (err) {
                results.push({ item: rel, success: false, message: err.message });
            }
        }

        const moved = results.filter(r => r.success).length;
        logger.info('批量移动完成', { ip: req.ip, moved, total: items.length });
        res.json({ success: true, message: '批量移动完成', moved, results });
    } catch (error) {
        logger.error('批量移动失败', { ip: req.ip, error: error.message });
        res.json({ success: false, message: error.message });
    }
});


// 9. 预览接口：docx 转 HTML、epub 返回 mime
app.get('/api/cloud/preview', authenticateToken, async (req, res) => {
    try {
        const filePath = req.query.path;

        if (!filePath) return res.status(400).json({ success: false, message: '未提供路径' });
        if (!isValidPath(filePath)) return res.status(400).json({ success: false, message: '无效路径' });

        const fullPath = path.resolve(CLOUD_ROOT, filePath);
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
                logger.error('docx 转换失败', { ip: req.ip, error: err.message });
                return res.status(500).json({ success: false, message: 'DOCX 转换失败' });
            }
        }

        if (ext === 'epub') {
            const q = new URLSearchParams({ path: filePath, inline: '1' }).toString();
            return res.redirect(`/api/cloud/download?${q}`);
        }

        // 其他类型：重定向到 download endpoint 使用 inline=1
        const q = new URLSearchParams({ path: filePath, inline: '1' }).toString();
        return res.redirect(`/api/cloud/download?${q}`);
    } catch (err) {
        logger.error('预览失败', { ip: req.ip, error: err.message });
        if (!res.headersSent) return res.status(500).json({ success: false, message: err.message });
    }
});

// 从MP3/音频文件ID3标签提取专辑封面
app.get('/api/cloud/audio/metadata', authenticateToken, async (req, res) => {
    try {
        const filePath = req.query.path;

        if (!filePath) return res.status(400).json({ success: false, message: '未提供路径' });
        if (!isValidPath(filePath)) return res.status(400).json({ success: false, message: '无效路径' });

        const fullPath = path.resolve(CLOUD_ROOT, filePath);
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
        logger.error('音频元数据提取失败', { ip: req.ip, error: err.message });
        if (!res.headersSent) return res.status(500).json({ success: false, message: err.message });
    }
});

// 新增API：获取目录中的音频文件列表
app.post('/api/cloud/audio/playlist', authenticateToken, async (req, res) => {
    try {
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
        logger.error('音频播放列表获取失败', { ip: req.ip, error: error.message });
        res.json({ success: false, message: error.message });
    }
});

// 新增API：获取目录中的视频文件列表（用于前端构建播放列表）
app.post('/api/cloud/video/playlist', authenticateToken, async (req, res) => {
    try {
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
        logger.error('视频播放列表获取失败', { ip: req.ip, error: error.message });
        res.json({ success: false, message: error.message });
    }
});

// SPA 回退路由：为非 API 路由提供 index.html
// 使用专门的路由处理器，避免捕获 API 404
app.use('/api', (req, res) => {
    res.status(404).json({ success: false, message: 'API 路由不存在' });
});

app.get('*', (req, res) => {
    res.sendFile(path.join(PUBLIC_DIR, 'index.html'));
});

// ========== 首页背景图：启动时落地到本地 ==========
// 浏览器端 <canvas> 读取跨域图片像素会被标记为 tainted，getImageData 抛
// SecurityError；而声明 crossOrigin="anonymous" 又会被对方拒绝加载。。
// 因此这里只在本地不存在时下载一次并长期复用；若想换图，
// 删除 public/assets/bg/ 下的文件后重启即可。
const BG_DIR = path.join(PUBLIC_DIR, 'assets', 'bg');
const BG_FILE = path.join(BG_DIR, 'index-bg.webp');
const BG_URL = process.env.BG_URL || 'https://t.alcy.cc/pc/';

async function ensureBackgroundImage() {
    try {
        // 已存在且非空则跳过（默认不覆盖，避免每次启动都走网络）
        try {
            const st = await fs.stat(BG_FILE);
            if (st.size > 1024) {
                logger.info(`背景图已存在，跳过下载 (${Math.round(st.size / 1024)} KB)`);
                return;
            }
        } catch (_) { /* 不存在，继续下载 */ }

        await fs.mkdir(BG_DIR, { recursive: true });

        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 15000);

        const resp = await fetch(BG_URL, {
            signal: controller.signal,
            headers: { 'User-Agent': 'TorSt/1.0 (+background-fetch)' }
        });
        clearTimeout(timer);

        if (!resp.ok) {
            throw new Error(`HTTP ${resp.status}`);
        }

        const buf = Buffer.from(await resp.arrayBuffer());
        if (buf.length < 1024) {
            throw new Error(`文件过小 (${buf.length} bytes)，疑似异常响应`);
        }

        // 先写临时文件再重命名，避免下载中断留下半截文件
        const tmp = BG_FILE + '.tmp';
        await fs.writeFile(tmp, buf);
        await fs.rename(tmp, BG_FILE);

        logger.info(`背景图下载完成 (${Math.round(buf.length / 1024)} KB) -> ${BG_FILE}`);
    } catch (err) {
        // 失败不应阻断服务启动：前端会回退到默认色板
        logger.warn(`背景图下载失败，前端将使用默认配色: ${err.message}`);
    }
}

// 启动服务
// 允许通过环境变量 PORT 指定端口，便于开发/测试时使用非 80 端口运行（无需管理员权限）
const PORT = process.env.PORT
const server = app.listen(PORT, () => {
    logger.info(`HTTP服务已启动，访问 http://localhost:${PORT}`);
    logger.info(`网盘根目录: ${CLOUD_DIR}`);
    // 背景图在监听后异步准备，不阻塞服务可用性
    ensureBackgroundImage();
});
