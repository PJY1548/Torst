### 一个基于 Node.js + Express 的面向 Windows 的 Web 文件管理与系统控制服务端
### 现代化的 Web 界面（深色模式适配）用于文件管理、媒体播放、文档预览以及系统监控与控制

## ✨ 核心功能

### 📁 网盘文件管理
- **文件浏览**：目录树导航、文件列表、面包屑导航
- **文件操作**：上传、下载、删除、重命名、移动、创建文件夹
- **批量操作**：支持多文件批量移动
- **断点续传**：大文件分片上传，支持断点续传
- **路径安全**：防止目录遍历攻击，Windows 保留名/可执行文件拦截

### 🎬 媒体播放中心
- **视频播放**：基于 DPlayer，支持 MP4/WebM/MKV 等格式，HTTP Range 请求，视频流式传输
- **音频播放**：播放列表、ID3 标签读取、专辑封面显示、歌词支持
- **图片查看**：缩略图预览、全屏查看、EXIF 信息
- **文档预览**：
  - Office 文档：DOCX → HTML 转换
  - EPUB 电子书：EPUB.js 渲染
  - PDF：浏览器原生预览
  - 文本文件：语法高亮

### 🖥️ 系统监控与控制
- **实时状态**：CPU 使用率、内存使用率（30秒缓存更新）
- **系统控制**：关机、重启（需管理员权限，Windows 环境）
- **日志记录**：Winston 结构化日志，按天轮转，敏感信息脱敏

### 🔐 安全认证
- **JWT 认证**：HttpOnly Cookie + Authorization Header 双模式
- **密码加密**：bcryptjs 哈希存储
- **速率限制**：登录/上传/API 分级限流
- **安全头**：Helmet CSP、HSTS、XSS 防护
- **路径校验**：多层防御（is-path-inside + realpath + 驱动器检查）

## 🚀 快速开始

### 环境要求
- Node.js
- Windows 系统（系统控制功能依赖 `shutdown` 命令）
- 管理员权限

### 安装步骤

```bash
# 安装依赖
npm install
# 复制环境变量模板并配置
cp .env.example .env
```

服务启动后访问：`http://localhost:80`（或配置的 PORT）

## ⚙️ 配置说明 (`.env`)

| 变量名 | 必填 | 说明 | 示例 |
|--------|------|------|------|
| `NODE_ENV` | 否 | 运行环境 | `production` / `development` |
| `PORT` | 否 | 服务端口（需管理员权限绑定 80） | `80` / `3000` |
| `JWT_SECRET` | **是** | JWT 签名密钥（32字节十六进制） | `a1b2c3d4e5f6...` |
| `JWT_EXPIRY` | 否 | Token 过期时间 | `7d` / `24h` |
| `PASSWORD_HASH` | **是** | 登录密码的 bcrypt 哈希值 | `$2a$10$...` |
| `CLOUD_DIR` | **是** | 网盘根目录路径 | `C:\\Cloud`  |

### 生成配置值

```bash
# 生成 JWT_SECRET (32字节随机十六进制)
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"

# 生成 PASSWORD_HASH (将 '你的密码' 替换为实际密码)
node -e "console.log(require('bcryptjs').hashSync('你的密码', 10))"
```

> ⚠️ **重要**：首次运行前必须设置 `JWT_SECRET` 和 `PASSWORD_HASH`，否则服务将拒绝启动。

```bash
# 运行
node server.js
```

## 📚 API 接口文档

### 认证相关
| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/auth/login` | 登录，返回 JWT 并设置 HttpOnly Cookie |
| POST | `/api/auth/logout` | 登出，清除 Cookie |
| GET | `/api/auth/me` | 获取当前用户信息 |

### 系统状态
| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/status` | 获取 CPU/内存使用率（缓存 60 秒） |

### 系统控制（需认证）
| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/shutdown` | 执行关机命令 |
| POST | `/api/restart` | 执行重启命令 |

### 网盘操作（需认证）
| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/cloud/list` | 获取目录文件列表 |
| POST | `/api/cloud/mkdir` | 创建文件夹 |
| POST | `/api/cloud/upload` | 上传文件（multipart/form-data） |
| POST | `/api/cloud/download` | 下载文件（POST 方式） |
| GET | `/api/cloud/download` | 下载文件（GET 方式，支持直接链接） |
| GET | `/api/cloud/download/*` | 路径段方式下载 |
| POST | `/api/cloud/delete` | 删除文件/文件夹 |
| POST | `/api/cloud/rename` | 重命名文件/文件夹 |
| POST | `/api/cloud/move` | 批量移动文件/文件夹 |
| GET | `/api/cloud/preview` | 预览文件（docx/epub/其他） |
| GET | `/api/cloud/audio/metadata` | 获取音频 ID3 标签/封面 |
| POST | `/api/cloud/audio/playlist` | 获取目录音频播放列表 |
| POST | `/api/cloud/video/playlist` | 获取目录视频播放列表 |

### 请求示例

**登录**
```bash
curl -X POST http://localhost:80/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"password": "你的密码"}' \
  -c cookies.txt
```

**获取文件列表**
```bash
curl -X POST http://localhost:80/api/cloud/list \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -d '{"path": ""}'
```

**上传文件**
```bash
curl -X POST http://localhost:80/api/cloud/upload \
  -b cookies.txt \
  -F "file=@/path/to/file.pdf" \
  -F "path="
```

**下载文件（GET 直接链接）**
```bash
# 浏览器直接访问即可下载
http://localhost:80/api/cloud/download?path=documents/file.pdf

# 预览模式（视频/音频/图片/文档）
http://localhost:80/api/cloud/download?path=videos/movie.mp4&inline=1
```

## 🎨 前端页面

| 页面 | 路由 | 功能 |
|------|------|------|
| 主页/文件管理 | `/` / `index.html` | 网盘文件浏览、操作 |
| 视频播放 | `video.html` | DPlayer 视频播放器 |
| 音频播放 | `music.html` | 音频播放器、播放列表 |
| 图片查看 | `picture.html` | 图片预览、EXIF |
| 文档阅读 | `document.html` | DOCX/EPUB/PDF/文本预览 |

前端资源位于 `public/assets/`：
- `css/` - Tailwind、Font Awesome、DPlayer 样式
- `js/` - DPlayer、EPUB.js、JSZip
- `fonts/` - 字体文件

## 🔒 安全特性详解

### 认证与授权
- **HttpOnly Cookie**：防止 XSS 窃取 Token
- **SameSite=Strict**：防止 CSRF 攻击
- **Secure 标记**：HTTPS 环境下自动启用
- **JWT 过期**：默认 7 天，可配置

### 速率限制
| 接口类型 | 窗口 | 最大请求数 |
|----------|------|------------|
| 登录 | 1分钟 | 5次 |
| 上传 | 1分钟 | 10次 |
| 通用 API | 1分钟 | 60次 |

### 文件上传安全
- 文件大小限制：10GB 单文件
- 禁止 Windows 保留设备名（CON, PRN, AUX, NUL, COM1-9, LPT1-9）
- 禁止可执行文件扩展名（.exe, .bat, .ps1, .js 等 40+ 种）
- MIME 类型校验（仅警告不阻断）
- 文件名冲突自动重命名（Windows 风格 `文件 (1).ext`）

### 路径遍历防护（多层防御）
1. `path.normalize` 规范化
2. `is-path-inside` 库校验
3. `fs.realpathSync` 解析符号链接
4. 驱动器一致性检查
5. UNC 路径拦截
6. Windows 保留名二次校验

### 安全响应头
- Content-Security-Policy (CSP)
- Strict-Transport-Security (HSTS, 1年)
- X-Content-Type-Options: nosniff
- X-Frame-Options: DENY
- Referrer-Policy: strict-origin-when-cross-origin

## 📁 项目结构

```
Service/
├── package.json          # 依赖与脚本配置
├── server.js             # 主服务器入口（~1400行）
├── .env.example          # 环境变量模板
├── .env                  # 实际配置（需自行创建，勿提交）
├── public/               # 静态资源目录
│   ├── index.html        # 主页/文件管理
│   ├── video.html        # 视频播放页
│   ├── music.html        # 音频播放页
│   ├── picture.html      # 图片查看页
│   ├── document.html     # 文档阅读页
│   └── assets/           # 前端静态资源
│       ├── css/
│       ├── js/
│       └── fonts/
└── logs/                 # 日志目录（自动创建）
    ├── application-YYYY-MM-DD.log
    └── error-YYYY-MM-DD.log
```


## 🐳 部署建议

### 反向代理 (Nginx 示例)
```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
        
        # 大文件上传支持
        client_max_body_size 10G;
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
    }
}
```
### 使用ZeroTrust类型或Frp实现内网穿透

## ❓ 常见问题

### Q: 视频无法播放/拖动
**A**: 确保：
- 视频文件支持 HTTP Range 请求（本服务已支持）
- 浏览器支持视频编码格式（推荐 H.264/MP4）
- 反向代理未缓冲/修改 Range 头

### Q: 上传大文件失败
**A**: 检查：
- `client_max_body_size` (Nginx) / `limitRequestBody` (Apache)
- `multer` 的 `fileSize` 限制（默认 10GB）
- 磁盘空间是否充足

### Q: 登录后立即跳回登录页
**A**: 检查：
- `JWT_SECRET` 是否一致（重启后变化会导致 Token 失效）
- Cookie 是否被浏览器拦截（HTTPS 环境需 `Secure`，同站需 `SameSite`）
- 系统时间是否同步（JWT 过期验证依赖系统时间）

### Q: 文件名显示乱码
**A**: 服务已处理 `latin1` → `utf8` 转换。确保：
- 文件系统支持 UTF-8
- 前端页面 `<meta charset="utf-8">`
- 反向代理未修改编码头

## 📄 许可证

GNU License - 详见 [LICENSE](LICENSE) 文件

---

**⚠️ 免责声明**：本工具包含系统关机/重启功能，请在受控环境中使用，生产环境请务必配置强密码、启用 HTTPS、限制访问 IP，并定期备份重要数据。开发者使用Cloudflare Tunnel确保中间安全

## 📦 技术栈

| 类别 | 技术 |
|------|------|
| 运行时 | Node.js 18+ |
| 框架 | Express 4.x |
| 认证 | jsonwebtoken + bcryptjs + cookie-parser |
| 文件处理 | multer + fs-extra + mime-types |
| 文档解析 | mammoth (DOCX) + epub.js (EPUB) |
| 音频元数据 | music-metadata |
| 系统信息 | systeminformation |
| 日志 | winston + winston-daily-rotate-file |
| 安全 | helmet + express-rate-limit + is-path-inside |
| 前端资源 | Tailwind CSS + Font Awesome + DPlayer + EPUB.js + JSZip |
