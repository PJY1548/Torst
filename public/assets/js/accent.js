/* ==========================================================================
   TorSt 动态取色 (Dynamic Accent Extraction)
   --------------------------------------------------------------------------
   用途：从首页背景图提取一组协调的主色，写入 CSS 变量并持久化到
        localStorage，供 5 个页面共享，使配色与背景天然的协调，
        避免"硬编码 AI 蓝"的廉价感。

   为什么在服务端落地图片：背景图原本托管在第三方（无 CORS 头），
   浏览器 canvas 读其像素会抛 SecurityError。服务端抓取到 public/ 后
   变成同源资源，才能自由取色。详见 server.js 的 ensureBackgroundImage()。

   用法（在 theme.css 之后、页面脚本之前引入）：
       <script src="/assets/js/accent.js"></script>

   暴露 API：
       window.TorStAccent.get()       -> 当前色板对象（可能为 null）
       window.TorStAccent.apply()     -> 重新应用（读缓存或重新提取）
       window.TorStAccent.refresh()   -> 强制重新提取
       window.TorStAccent.CACHE_KEY   -> localStorage 键名
   ========================================================================== */
(function (global) {
    'use strict';

    var CACHE_KEY = 'torst.accent';
    var CACHE_VERSION = 7;                  // 提取算法变更时递增，自动作废旧缓存
    var BG_URL = '/assets/bg/index-bg.webp';
    var SAMPLE = 96;                        // 缩略图采样边长

    /* ---------------------------------------------------------------------
       颜色工具
       --------------------------------------------------------------------- */

    function rgbToHsl(r, g, b) {
        r /= 255; g /= 255; b /= 255;
        var max = Math.max(r, g, b), min = Math.min(r, g, b);
        var h = 0, s = 0, l = (max + min) / 2;
        var d = max - min;
        if (d !== 0) {
            s = l > 0.5 ? d / (2 - max - min) : d / (max + min);
            if (max === r)      h = ((g - b) / d + (g < b ? 6 : 0));
            else if (max === g) h = ((b - r) / d + 2);
            else                h = ((r - g) / d + 4);
            h /= 6;
        }
        return { h: h * 360, s: s, l: l };
    }

    function hslToRgb(h, s, l) {
        h = ((h % 360) + 360) % 360 / 360;
        function hue2rgb(p, q, t) {
            if (t < 0) t += 1;
            if (t > 1) t -= 1;
            if (t < 1 / 6) return p + (q - p) * 6 * t;
            if (t < 1 / 2) return q;
            if (t < 2 / 3) return p + (q - p) * (2 / 3 - t) * 6;
            return p;
        }
        var r, g, b;
        if (s === 0) {
            r = g = b = l;
        } else {
            var q = l < 0.5 ? l * (1 + s) : l + s - l * s;
            var p = 2 * l - q;
            r = hue2rgb(p, q, h + 1 / 3);
            g = hue2rgb(p, q, h);
            b = hue2rgb(p, q, h - 1 / 3);
        }
        return {
            r: Math.round(r * 255),
            g: Math.round(g * 255),
            b: Math.round(b * 255)
        };
    }

    function toHex(c) {
        function h2(n) {
            var s = Math.max(0, Math.min(255, Math.round(n))).toString(16);
            return s.length === 1 ? '0' + s : s;
        }
        return '#' + h2(c.r) + h2(c.g) + h2(c.b);
    }

    function rgba(c, a) {
        return 'rgba(' + Math.round(c.r) + ', ' + Math.round(c.g) + ', ' + Math.round(c.b) + ', ' + a + ')';
    }

    // 相对亮度（WCAG），用于决定前景用白字还是黑字
    function luminance(c) {
        function ch(v) {
            v /= 255;
            return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4);
        }
        return 0.2126 * ch(c.r) + 0.7152 * ch(c.g) + 0.0722 * ch(c.b);
    }

    function contrastWithWhite(c) {
        return 1.05 / (luminance(c) + 0.05);
    }

    /* ---------------------------------------------------------------------
       从像素中提炼主色
       ---------------------------------------------------------------------
       直接求平均会得到灰扑扑的泥色，因此：
       1) 跳过过亮/过暗像素（背景图边缘常见大片黑边或高光）
       2) 跳过接近灰的像素（饱和度过低，取出来没有色彩倾向）
       3) 按色相分桶，取"出现最多且足够鲜艳"的桶作为主色相
       4) 用该桶的平均饱和度/明度重建一个可用的品牌色
       --------------------------------------------------------------------- */
    function extractPalette(pixels) {
        var buckets = {};                   // 色相桶: 30° 一格
        var fallback = { r: 0, g: 0, b: 0, n: 0 };

        for (var i = 0; i < pixels.length; i += 4) {
            var a = pixels[i + 3];
            if (a < 128) continue;          // 透明像素
            var r = pixels[i], g = pixels[i + 1], b = pixels[i + 2];

            fallback.r += r; fallback.g += g; fallback.b += b; fallback.n++;

            var hsl = rgbToHsl(r, g, b);

            // 过滤：太暗 / 太亮 / 太灰
            if (hsl.l < 0.12 || hsl.l > 0.92) continue;
            if (hsl.s < 0.15) continue;

            var key = Math.floor(hsl.h / 30) % 12;
            if (!buckets[key]) buckets[key] = { n: 0, h: 0, s: 0, l: 0, weight: 0 };
            var bk = buckets[key];
            bk.n++;
            bk.h += hsl.h;
            bk.s += hsl.s;
            bk.l += hsl.l;
            // 权重 = 像素数 × 平均饱和度。
            // 只用饱和度会让一小撮高饱和杂色（例如画面里的黄色西瓜、
            // 红色樱桃）压过真正主导画面的大面积色域，选出偏门色。
            // 乘上像素数后，"面积大且够彩"的区域才会胜出。
            bk.weight += hsl.s;
        }

        var keys = Object.keys(buckets);
        var chosen = null;

        if (keys.length) {
            keys.forEach(function (k) {
                var b = buckets[k];
                b.area = b.n;
                b.satAvg = b.n > 0 ? b.s / b.n : 0;
                b.ligAvg = b.n > 0 ? b.l / b.n : 0;
                b.hueAvg = b.h / b.n;
                // 基础分：面积(sqrt 缓和量级差) × 平均饱和度
                b.base = Math.sqrt(b.n) * Math.pow(b.satAvg, 1.5);
            });

            // 分两步选色，而不是给暖色乘一个惩罚系数。
            // 原因：插画里暖色（皮肤/毛发/木质）的面积常是冷色的几十倍，
            // 实测 2038 vs 57，乘 0.4 后暖色仍然胜出，压不住。
            //
            // 策略：
            //   1) 先只在"适合做品牌色"的色相里挑（青/蓝/绿/冷紫）；
            //   2) 若没有够分量的（不足总彩色像素 6%），
            //      再退回全局最高分，避免为一张几乎无冷色的图硬凑。
            var totalColored = keys.reduce(function (s, k) { return s + buckets[k].n; }, 0);

            function isUsableHue(h) {
                if (h >= 330 || h < 70) return false;    // 红 / 橙 / 黄（显土气）
                if (h >= 270 && h < 330) return false;   // 紫红 / 品红（显廉价）
                return true;                             // 黄绿 / 绿 / 青 / 蓝
            }

            var usable = keys.filter(function (k) {
                return isUsableHue(buckets[k].hueAvg) &&
                       buckets[k].n >= totalColored * 0.06;
            });

            var pool = usable.length ? usable : keys;
            pool.sort(function (x, y) { return buckets[y].base - buckets[x].base; });
            chosen = buckets[pool[0]];
        }

        var baseHue, baseSat, baseLig;

        if (chosen && chosen.n > 0) {
            baseHue = chosen.h / chosen.n;
            baseSat = chosen.satAvg;
            baseLig = chosen.ligAvg;
        } else if (fallback.n > 0) {
            // 整张图几乎没有彩色像素：退回平均色的色相（低饱和）
            var fr = fallback.r / fallback.n,
                fg = fallback.g / fallback.n,
                fb = fallback.b / fallback.n;
            var fh = rgbToHsl(fr, fg, fb);
            baseHue = fh.h;
            baseSat = Math.max(fh.s, 0.35);
            baseLig = fh.l;
        } else {
            // 极端兜底
            baseHue = 220; baseSat = 0.75; baseLig = 0.5;
        }

        // 规范化：把取到的色相做成"可用作按钮/强调色"的色值。
        // 关键点：饱和度只做温和抬升，不做大幅拉高。
        // 强行拉高会把柔和的插画底色变成艳俗的塑料色，这正是
        // "取色显廉价"的主因。
        var sat = Math.min(0.55, Math.max(0.34, baseSat + 0.08));
        // 明度压到中段，保证白字可读且不刺眼（亮色模式按钮底色）
        var lig = Math.min(0.50, Math.max(0.36, baseLig - 0.06));

        var primary = hslToRgb(baseHue, sat, lig);
        var hover   = hslToRgb(baseHue, Math.min(0.62, sat + 0.04), Math.max(0.26, lig - 0.07));
        var active  = hslToRgb(baseHue, Math.min(0.68, sat + 0.06), Math.max(0.19, lig - 0.13));
        var secondary = hslToRgb(baseHue + 22, Math.max(0.28, sat - 0.08), Math.min(0.62, lig + 0.08));

        // 深色模式下的主色：提亮降饱和，避免刺眼
        var darkPrimary = hslToRgb(baseHue, Math.min(0.52, sat), 0.70);
        var darkHover   = hslToRgb(baseHue, Math.min(0.58, sat), 0.78);

        return {
            v: CACHE_VERSION,
            hue: Math.round(baseHue),
            primary: toHex(primary),
            primaryHover: toHex(hover),
            primaryActive: toHex(active),
            secondary: toHex(secondary),
            darkPrimary: toHex(darkPrimary),
            darkHover: toHex(darkHover),
            // 前景色由对比度决定，保证按钮文字始终可读。
            // 深浅两套主色差别较大（深色主色更亮），因此分别判定。
            onPrimary: bestForeground(primary),
            onPrimaryDark: bestForeground(darkPrimary)
        };
    }

    // 在白/黑之间选择对比度更高的前景色
    function bestForeground(bg) {
        var lum = luminance(bg);
        // 与白的对比度 vs 与黑的对比度，取更优者
        var cWhite = 1.05 / (lum + 0.05);
        var cBlack = (lum + 0.05) / 0.05;
        return cWhite >= cBlack ? '#FFFFFF' : '#1D1D1F';
    }

    /* ---------------------------------------------------------------------
       应用色板到 CSS 变量
       --------------------------------------------------------------------- */
    function hexToRgb(hex) {
        var m = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
        return m ? { r: parseInt(m[1], 16), g: parseInt(m[2], 16), b: parseInt(m[3], 16) } : { r: 0, g: 0, b: 0 };
    }

    function applyPalette(p) {
        if (!p) return;
        var root = document.documentElement;
        var pr = hexToRgb(p.primary);
        var sr = hexToRgb(p.secondary);
        var dp = hexToRgb(p.darkPrimary);

        // 注意：不能用 root.style.setProperty('--primary', ...) 直接写亮色值。
        // 内联样式优先级高于 .theme-dark / .dark 规则，会导致深色模式
        // 仍显示亮色主色。因此深浅两套色分别写入独立变量，
        // 由 theme.css 按当前主题选择（见 .theme-dark/.dark 中的 var() 回退）。
        root.style.setProperty('--primary-light', p.primary);
        root.style.setProperty('--primary-light-hover', p.primaryHover);
        root.style.setProperty('--primary-light-active', p.primaryActive);
        root.style.setProperty('--primary-light-soft', rgba(pr, 0.10));
        root.style.setProperty('--primary-light-soft-strong', rgba(pr, 0.18));

        root.style.setProperty('--primary-dark', p.darkPrimary);
        root.style.setProperty('--primary-dark-hover', p.darkHover);
        root.style.setProperty('--primary-dark-active', p.darkHover);
        root.style.setProperty('--primary-dark-soft', rgba(dp, 0.15));
        root.style.setProperty('--primary-dark-soft-strong', rgba(dp, 0.24));

        // 次级色在深浅下差异不大，直接应用
        root.style.setProperty('--secondary', p.secondary);
        root.style.setProperty('--secondary-soft', rgba(sr, 0.10));

        // 供 CSS 以 rgba(var(--primary-rgb), a) 派生淡染色，
        // 这样文件图标底色会跟随取到的主色，而不是写死的蓝。
        root.style.setProperty('--primary-rgb',
            Math.round(pr.r) + ', ' + Math.round(pr.g) + ', ' + Math.round(pr.b));

        // 前景色分深浅两套：深色主色更亮，可能需要深色文字
        root.style.setProperty('--text-on-primary-light', p.onPrimary);
        root.style.setProperty('--text-on-primary-dark', p.onPrimaryDark || '#FFFFFF');

        // 标记已取色，供 CSS 做渐进增强
        root.setAttribute('data-accent', 'ready');
    }

    /* ---------------------------------------------------------------------
       缓存
       --------------------------------------------------------------------- */
    function readCache() {
        try {
            var raw = localStorage.getItem(CACHE_KEY);
            if (!raw) return null;
            var p = JSON.parse(raw);
            if (!p || p.v !== CACHE_VERSION) return null;   // 版本不符则作废
            return p;
        } catch (e) { return null; }
    }

    function writeCache(p) {
        try { localStorage.setItem(CACHE_KEY, JSON.stringify(p)); } catch (e) { /* 隐私模式等 */ }
    }

    /* ---------------------------------------------------------------------
       取色主流程
       --------------------------------------------------------------------- */
    var current = null;

    function extractFromImage() {
        return new Promise(function (resolve, reject) {
            var img = new Image();
            // 同源资源，不需要 crossOrigin；显式声明也无害
            img.decoding = 'async';
            img.onload = function () {
                try {
                    var c = document.createElement('canvas');
                    c.width = SAMPLE;
                    c.height = SAMPLE;
                    var ctx = c.getContext('2d', { willReadFrequently: true });
                    ctx.drawImage(img, 0, 0, SAMPLE, SAMPLE);
                    var data = ctx.getImageData(0, 0, SAMPLE, SAMPLE).data;
                    resolve(extractPalette(data));
                } catch (e) {
                    reject(e);
                }
            };
            img.onerror = function () { reject(new Error('背景图加载失败')); };
            img.src = BG_URL;
        });
    }

    function apply() {
        var cached = readCache();
        if (cached) {
            current = cached;
            applyPalette(cached);
            return Promise.resolve(cached);
        }
        return extractFromImage().then(function (p) {
            current = p;
            writeCache(p);
            applyPalette(p);
            return p;
        }).catch(function (err) {
            // 失败静默回退到 theme.css 的默认色板，不影响页面可用性
            if (global.console && console.warn) {
                console.warn('[TorSt] 动态取色失败，使用默认色板:', err.message);
            }
            return null;
        });
    }

    function refresh() {
        try { localStorage.removeItem(CACHE_KEY); } catch (e) {}
        current = null;
        return apply();
    }

    global.TorStAccent = {
        apply: apply,
        refresh: refresh,
        get: function () { return current; },
        CACHE_KEY: CACHE_KEY,
        _extract: extractPalette,       // 暴露给测试
        _rgbToHsl: rgbToHsl,
        _hslToRgb: hslToRgb
    };

    // 尽早应用缓存色，避免首屏闪烁；无缓存时异步提取
    apply();
})(window);
