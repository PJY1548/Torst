# Torst - 个人媒体服务器

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
![Node.js](https://img.shields.io/badge/Node.js-18%2B-green)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

> 一个基于 Node.js + Express 构建的现代化个人媒体服务器，支持文档、音乐、图片、视频的在线预览与播放。

![预览](https://github.com/PJY1548/Torst/blob/main/preview.png)

## ✨ 功能特性

### 📄 文档预览
- **EPUB 电子书阅读**
- **Office 文档**
### 🎵 音乐播放器
### 🖼 图片相册
### 🎬 视频播放器
- 基于 **DPlayer**


### 🎨 界面特性
- **响应式设计** - 完美适配桌面端、平板、手机
- **主题切换** - 浅色/深色/跟随系统
- **背景图代理** - 集成 [次元API](https://tc.alcy.cc/) 随机动漫壁纸
- **玻璃拟态 UI** - 毛玻璃导航栏、卡片、模态框

## 🏗 技术栈

| 层级 | 技术 |
|------|------|
| **运行时** | Node.js 18+ |
| **框架** | Express.js |
| **前端** | 原生 ES Modules + Tailwind CSS |
| **视频播放** | DPlayer + flv.js + hls.js |
| **电子书** | epub.js |
| **文档** | PDF.js、marked、highlight.js |
| **压缩** | JSZip |
| **图标** | Font Awesome 6 |
| **部署** | PM2 / Docker / 任意 Node.js 托管平台 |

## 🚀 快速开始
### 安装依赖
```bash
npm install
```
### 配置说明
```env
PORT=80
JWT_SECRET=node -e "console.log(require('crypto').randomBytes(32).toString('hex'))" 
JWT_EXPIRY=7d
PASSWORD_HASH=node -e "console.log(require('bcryptjs').hashSync('你的密码', 10))"
CLOUD_DIR=C:\\Cloud
```
### 背景与配色

#### 可通过删除或更改\public\assets\bg\index-bg.webp
#### 实现背景图片或配色的修改

### 媒体目录结构建议
```
media/
├── documents/    # 文档 (epub, pdf, docx...)
├── music/        # 音乐 (mp3, flac...)
├── pictures/     # 图片 (jpg, png...)
└── videos/       # 视频 (mp4, mkv...)
```

## 📁 项目结构
```
Torst/
├── server.js              # 入口文件
├── package.json
├── .env.example
├── .gitignore
├── License                # GPL-3.0 许可证
├── preview.png            # 项目预览图
├── public/                # 静态前端资源
│   ├── index.html         # 首页/导航
│   ├── document.html      # 文档阅读页
│   ├── music.html         # 音乐播放页
│   ├── picture.html       # 图片相册页
│   ├── video.html         # 视频播放页
│   └── assets/
│       ├── css/
│       │   ├── tailwind.min.css
│       │   ├── DPlayer.min.css
│       │   ├── font-awesome.min.css
│       │   └── theme.css
│       ├── js/
│       │   ├── DPlayer.min.js
│       │   ├── epub.min.js
│       │   ├── jszip.min.js
│       │   └── accent.js      # 主题/交互逻辑
│       ├── fonts/             # Font Awesome 字体
│       └── bg/                # 背景图缓存
└── logs/                      # 运行日志
```

## 🔌 API 接口

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/files` | 获取媒体文件列表（支持分类、分页、搜索） |
| GET | `/api/files/:path` | 获取单个文件信息/流式传输 |
| GET | `/api/thumbnail/:path` | 获取缩略图（图片/视频/文档） |
| GET | `/api/lyrics/:path` | 获取歌词文件内容 |
| GET | `/api/subtitle/:path` | 获取字幕文件内容 |
| GET | `/api/bg` | 获取随机背景图（代理次元API） |
| GET | `/api/bg?mobile=1` | 获取移动端背景图 |

## 🙏 致谢 / 第三方服务

| 服务 | 用途 | 链接 |
|------|------|------|
| **次元API** | 随机动漫背景图、每日一句 | [tc.alcy.cc](https://tc.alcy.cc/) |
| **Bing 每日一图** | 首页备选背景 | [bing.com](https://www.bing.com/) |
| **DPlayer** | 视频播放器核心 | [github.com/MoePlayer/DPlayer](https://github.com/MoePlayer/DPlayer) |
| **epub.js** | EPUB 电子书渲染 | [github.com/futurepress/epub.js](https://github.com/futurepress/epub.js) |
| **PDF.js** | PDF 预览 | [mozilla.github.io/pdf.js](https://mozilla.github.io/pdf.js/) |
| **Tailwind CSS** | 样式框架 | [tailwindcss.com](https://tailwindcss.com/) |
| **Font Awesome** | 图标库 | [fontawesome.com](https://fontawesome.com/) |
| **highlight.js** | 代码高亮 | [highlightjs.org](https://highlightjs.org/) |

## 📝 许可证

本项目采用 **GNU General Public License v3.0** 开源协议。

详见 [License](License) 文件。

---

⭐ 如果这个项目对你有帮助，请给个 Star 支持一下！