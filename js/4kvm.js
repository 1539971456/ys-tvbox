/*
====================================================================
 4K影视 (4kvm) —— 安忆TVBOX / catvod JsSpider 模块格式 JS 源
====================================================================
 站点   : https://www.4kvm.top      备用: https://4kvm.site
 用法   : sites 里这样配(api 直接指向本文件, 必须以 .js 结尾):
   {
     "key": "4kvm",
     "name": "🔞4K影视",
     "type": 3,
     "api": "https://raw.giteeusercontent.com/he-sucai/ysapi/raw/master/js/4kvm.js",
     "searchable": 1,
     "quickSearch": 1,
     "filterable": 1,
     "timeout": 60
   }

 本文件是 ES 模块(export default), 对应 App 里
 com.github.tvbox.osc.util.js.JsSpider 的加载方式:
   api 以 .js 结尾 -> JsLoader -> JsSpider -> evaluateModule -> spider.default
   因此必须导出 init/home/homeVod/category/detail/play/search 这几个方法。

 播放地址签名(原站 WASM 还原, 已逐字节验证):
   blockA = XOR( 密钥补零至64字节 , 0x36 )
   blockB = XOR( 密钥补零至64字节 , 0x5C )
   h1     = SHA256( blockA + "{dataid}:{时间戳}:{密钥}" )
   s      = SHA256( blockB + h1 ) 十六进制前 32 位
   k      = play_key 为空或 '0' 时 '0', 否则 base64( XOR(play_key, "nbmovie2024secretkey") )
   /video/play?p={dataid}&v={密钥}&q=1080&s={s}&t={时间戳}&k={k}
 时间戳按页内 <meta id="nb-st"> 校正为服务器时间; 令牌(userlink)只在 /play 页下发且一次一换,
 故每次播放前重新取页面。
====================================================================
*/

var K4_HOSTS = ['https://www.4kvm.top', 'https://4kvm.site'];
var K4_ROOT = 'https://www.4kvm.top';
var K4_UA = 'Mozilla/5.0 (Linux; Android 13; V2309A Build/TP1A.220624.014; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/116.0.0.0 Mobile Safari/537.36';
var K4_SECRET = 'nbmovie2024secretkey';
var K4_TOKEN = '';
var K4_TOKEN_TIME = 0;
var K4_OFFSET = 0;

/* ================================================== HTTP
   App(JsSpider) 全局提供同步 req(url, options) -> {content, headers}
   net.js: req = (url, options) => http(url, {async:false, ...options})            */
function k4Req(url, headers) {
    var opt = { headers: headers || { 'User-Agent': K4_UA } };
    var g = (typeof globalThis !== 'undefined') ? globalThis : null;
    var f = null;
    if (typeof req === 'function') f = req;
    else if (g && typeof g.req === 'function') f = g.req;
    else if (typeof request === 'function') f = request;
    if (!f) return '';
    var r = null;
    try { r = f(url, opt); } catch (e) { return ''; }
    if (r === null || r === undefined) return '';
    if (typeof r === 'string') return r;
    if (typeof r === 'object') {
        if (typeof r.content === 'string') return r.content;
        if (typeof r.body === 'string') return r.body;
        if (r.content !== undefined && r.content !== null) return '' + r.content;
    }
    return '' + r;
}

function k4Get(url, referer) {
    return k4Req(url, {
        'User-Agent': K4_UA,
        'Accept': 'text/html,application/xhtml+xml,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        'Referer': referer || (K4_ROOT + '/')
    });
}

function k4GetJson(url, referer) {
    return k4Req(url, {
        'User-Agent': K4_UA,
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        'X-Requested-With': 'XMLHttpRequest',
        'Referer': referer || (K4_ROOT + '/')
    });
}

/* ================================================== 编码 / 哈希 */
function k4Utf8(s) {
    var out = [], i, c, c2, cp;
    for (i = 0; i < s.length; i++) {
        c = s.charCodeAt(i);
        if (c < 0x80) out.push(c);
        else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 63));
        else if (c >= 0xd800 && c <= 0xdbff) {
            c2 = s.charCodeAt(++i);
            cp = 0x10000 + ((c - 0xd800) << 10) + (c2 - 0xdc00);
            out.push(0xf0 | (cp >> 18), 0x80 | ((cp >> 12) & 63), 0x80 | ((cp >> 6) & 63), 0x80 | (cp & 63));
        } else out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
    }
    return out;
}

function k4B64(bytes) {
    var CH = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    var out = '', i, b0, b1, b2;
    for (i = 0; i < bytes.length; i += 3) {
        b0 = bytes[i]; b1 = bytes[i + 1]; b2 = bytes[i + 2];
        out += CH.charAt(b0 >> 2);
        out += CH.charAt(((b0 & 3) << 4) | ((b1 === undefined ? 0 : b1) >> 4));
        out += (b1 === undefined) ? '=' : CH.charAt(((b1 & 15) << 2) | ((b2 === undefined ? 0 : b2) >> 6));
        out += (b2 === undefined) ? '=' : CH.charAt(b2 & 63);
    }
    return out;
}

function k4Sha256(bytes) {
    var K = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
             0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
             0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
             0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
             0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
             0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
             0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
             0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];
    var H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    var l = bytes.length, i, total = (((l + 9 + 63) >> 6) << 6);
    var m = [], w = [], a, b, c, d, e, f, g, h, S0, S1, ch, mj, t1, t2, off;
    for (i = 0; i < total; i++) m[i] = 0;
    for (i = 0; i < l; i++) m[i] = bytes[i] & 255;
    m[l] = 0x80;
    var bits = l * 8, hi = Math.floor(bits / 4294967296), lo = bits >>> 0;
    m[total - 8] = (hi >>> 24) & 255; m[total - 7] = (hi >>> 16) & 255;
    m[total - 6] = (hi >>> 8) & 255;  m[total - 5] = hi & 255;
    m[total - 4] = (lo >>> 24) & 255; m[total - 3] = (lo >>> 16) & 255;
    m[total - 2] = (lo >>> 8) & 255;  m[total - 1] = lo & 255;

    function rotr(x, n) { return ((x >>> n) | (x << (32 - n))) >>> 0; }

    for (off = 0; off < total; off += 64) {
        for (i = 0; i < 16; i++) {
            w[i] = ((m[off + i * 4] << 24) | (m[off + i * 4 + 1] << 16) |
                    (m[off + i * 4 + 2] << 8) | m[off + i * 4 + 3]) >>> 0;
        }
        for (i = 16; i < 64; i++) {
            S0 = (rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3)) >>> 0;
            S1 = (rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10)) >>> 0;
            w[i] = (w[i - 16] + S0 + w[i - 7] + S1) >>> 0;
        }
        a = H[0]; b = H[1]; c = H[2]; d = H[3]; e = H[4]; f = H[5]; g = H[6]; h = H[7];
        for (i = 0; i < 64; i++) {
            S1 = (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) >>> 0;
            ch = ((e & f) ^ ((~e >>> 0) & g)) >>> 0;
            t1 = (h + S1 + ch + K[i] + w[i]) >>> 0;
            S0 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) >>> 0;
            mj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
            t2 = (S0 + mj) >>> 0;
            h = g; g = f; f = e; e = (d + t1) >>> 0;
            d = c; c = b; b = a; a = (t1 + t2) >>> 0;
        }
        H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b) >>> 0; H[2] = (H[2] + c) >>> 0; H[3] = (H[3] + d) >>> 0;
        H[4] = (H[4] + e) >>> 0; H[5] = (H[5] + f) >>> 0; H[6] = (H[6] + g) >>> 0; H[7] = (H[7] + h) >>> 0;
    }
    var out = [];
    for (i = 0; i < 8; i++) out.push((H[i] >>> 24) & 255, (H[i] >>> 16) & 255, (H[i] >>> 8) & 255, H[i] & 255);
    return out;
}

function k4Hex(bytes) {
    var s = '', i, h;
    for (i = 0; i < bytes.length; i++) { h = bytes[i].toString(16); s += (h.length < 2 ? '0' + h : h); }
    return s;
}

function k4Xor(bytes, key) {
    var out = [], i;
    for (i = 0; i < bytes.length; i++) out.push((bytes[i] ^ key[i % key.length]) & 255);
    return out;
}

function k4Cat(a, b) {
    var out = [], i;
    for (i = 0; i < a.length; i++) out.push(a[i]);
    for (i = 0; i < b.length; i++) out.push(b[i]);
    return out;
}

/* ================================================== 签名 / 令牌 */
function k4Now() { return (new Date()).getTime() + K4_OFFSET; }

function k4PlayPath(dataid, skey, quality, playKey) {
    var padBytes = k4Utf8(skey), pad = [], blockA = [], blockB = [], i;
    for (i = 0; i < 64; i++) pad.push(i < padBytes.length ? padBytes[i] : 0);
    for (i = 0; i < 64; i++) { blockA.push(pad[i] ^ 0x36); blockB.push(pad[i] ^ 0x5C); }
    var ts = k4Now();
    var h1 = k4Sha256(k4Cat(blockA, k4Utf8(dataid + ':' + ts + ':' + skey)));
    var s = k4Hex(k4Sha256(k4Cat(blockB, h1))).substr(0, 32);
    var k = '0';
    if (playKey && playKey !== '0') k = k4B64(k4Xor(k4Utf8(playKey), k4Utf8(K4_SECRET)));
    return '/video/play?p=' + dataid + '&v=' + skey + '&q=' + (quality || '1080') +
           '&s=' + s + '&t=' + ts + '&k=' + k;
}

function k4SyncToken(html, force) {
    if (!html) return K4_TOKEN;
    var t = /id="nb-st"\s+content="(\d+)"/.exec(html);
    if (t) K4_OFFSET = parseInt(t[1], 10) - (new Date()).getTime() + 400;
    var now = (new Date()).getTime();
    if (force || !K4_TOKEN || now - K4_TOKEN_TIME > 6 * 3600 * 1000) {
        var m = /userlink:'([^']*)'/.exec(html);
        if (m && m[1]) { K4_TOKEN = m[1]; K4_TOKEN_TIME = now; }
    }
    return K4_TOKEN;
}

/* ================================================== 解析 */
function k4Fix(u) { return (u || '').replace(/&amp;/g, '&'); }

function k4Items(html) {
    var out = [], seen = {}, i;
    if (!html) return out;
    var parts = ('' + html).split('<a href="/play/');
    for (i = 1; i < parts.length; i++) {
        var seg = parts[i].split('</a>')[0];
        var vid = parts[i].split('"')[0];
        if (!vid || seen[vid]) continue;
        seen[vid] = 1;
        var pic = /data-src="([^"]+)"/.exec(seg);
        if (!pic) pic = /<img[^>]+src="(https?:\/\/[^"]+)"/.exec(seg);
        var name = /alt="([^"]*)"/.exec(seg);
        if (!name) name = /<h3[^>]*>\s*([^<]+?)\s*<\/h3>/.exec(seg);
        var year = /bg-black\/70[^>]*>\s*([^<]{2,12}?)\s*<\/div>/.exec(seg);
        var qual = /bg-accent\/80[^>]*>\s*([^<]{1,8}?)\s*<\/div>/.exec(seg);
        var rem = [];
        if (year) rem.push(year[1]);
        if (qual) rem.push(qual[1]);
        out.push({
            vod_id: vid,
            vod_name: name ? name[1].replace(/^\s+|\s+$/g, '') : vid,
            vod_pic: k4Fix(pic ? pic[1] : ''),
            vod_remarks: rem.join(' ')
        });
    }
    return out;
}

function k4Episodes(html) {
    var lines = {}, order = [], m, names = [], nmre = /lineName:\s*'([^']*)'/g, nm;
    var re = /<a href="\/play\/([^"]+)"([^>]*)>([\s\S]*?)<\/a>/g;
    while ((m = re.exec(html))) {
        var attrs = m[2], body = m[3];
        var dm = /dataid="(\d+)"/.exec(attrs);
        if (!dm) continue;
        var lm = /data-line="(\d+)"/.exec(attrs);
        var em = /data-episode="(\d+)"/.exec(attrs);
        var idx = lm ? parseInt(lm[1], 10) : 1;
        if (!lines[idx]) { lines[idx] = []; order.push(idx); }
        lines[idx].push({
            num: em ? parseInt(em[1], 10) : lines[idx].length + 1,
            key: m[1], dataid: dm[1],
            vip: body.indexOf('vip-icon') >= 0
        });
    }
    while ((nm = nmre.exec(html))) names.push(nm[1]);
    var out = [], i, j;
    order.sort(function (a, b) { return a - b; });
    for (i = 0; i < order.length; i++) {
        var eps = lines[order[i]].sort(function (a, b) { return a.num - b.num; });
        out.push({ name: names[order[i] - 1] || ('线路' + order[i]), eps: eps });
    }
    return out;
}

function k4Vod(html, vid) {
    var title = /<title>([^<]*)<\/title>/.exec(html);
    var name = title ? title[1].split(' - ')[0] : vid;
    var poster = /data-poster="([^"]+)"/.exec(html);
    var info = {}, m;
    var re = /col-span-1 text-gray-500">([^<]+)<\/div>\s*<div class="col-span-2 text-gray-300">([\s\S]*?)<\/div>/g;
    while ((m = re.exec(html))) {
        info[m[1]] = m[2].replace(/<[^>]+>/g, '').replace(/\s+/g, ' ').replace(/^\s+|\s+$/g, '');
    }
    var desc = /剧情简介[\s\S]{0,200}?<p[^>]*>([\s\S]*?)<\/p>/.exec(html);
    var score = /ri-star-fill"\/><\/svg>\s*([\d.]+)/.exec(html);
    var area = /ri-map-pin-line"\/><\/svg>\s*([^<]+?)\s*<\/span>/.exec(html);
    var content = [];
    if (desc) content.push(desc[1].replace(/<[^>]+>/g, '').replace(/^\s+|\s+$/g, ''));
    if (info['导演']) content.push('导演: ' + info['导演']);
    if (info['主演']) content.push('主演: ' + info['主演']);
    if (score) content.push('评分: ' + score[1]);
    if (info['又名']) content.push('又名: ' + info['又名']);

    var groups = k4Episodes(html), froms = [], urls = [], i, j;
    if (groups.length) {
        for (i = 0; i < groups.length; i++) {
            froms.push(groups[i].name);
            var arr = [];
            for (j = 0; j < groups[i].eps.length; j++) {
                var e = groups[i].eps[j];
                arr.push('第' + e.num + '集' + (e.vip ? '[VIP]' : '') + '$' + e.key + '|' + e.dataid);
            }
            urls.push(arr.join('#'));
        }
    } else {
        var dm2 = /dataid="(\d+)"/.exec(html);
        froms.push('4K影视');
        urls.push('播放$' + vid + '|' + (dm2 ? dm2[1] : ''));
    }
    return {
        vod_id: vid,
        vod_name: name,
        vod_pic: k4Fix(poster ? poster[1] : ''),
        type_name: (info['类型'] || '') + (area ? ' ' + area[1] : ''),
        vod_year: (info['上映'] || '').substr(0, 4),
        vod_area: info['地区'] || (area ? area[1] : ''),
        vod_actor: info['主演'] || '',
        vod_director: info['导演'] || '',
        vod_remarks: info['片长'] || '',
        vod_content: content.join('\n'),
        vod_play_from: froms.join('$$$'),
        vod_play_url: urls.join('$$$')
    };
}

/* 取真实 m3u8, id 形如 "密钥|dataid" */
function k4Play(id) {
    var skey = id, dataid = '', p = ('' + id).indexOf('|');
    if (p > 0) { skey = ('' + id).substring(0, p); dataid = ('' + id).substring(p + 1); }
    if (!dataid) return { url: '', msg: '播放参数缺失' };
    var playUrl = '', msg = '', txt, data, d, urls, i, u, attempt, page, path;
    for (attempt = 0; attempt < 2; attempt++) {
        page = k4Get(K4_ROOT + '/play/' + skey, K4_ROOT + '/');
        k4SyncToken(page, true);                       // 令牌一次一换, 每次重取
        path = k4PlayPath(dataid, skey, '1080', K4_TOKEN || '0');
        txt = k4GetJson(K4_ROOT + path, K4_ROOT + '/play/' + skey);
        data = {};
        try { data = JSON.parse(txt); } catch (e) { data = {}; }
        if (!data || !data.code) {
            msg = txt ? ('' + txt).replace(/^\s+|\s+$/g, '').substr(0, 120) : '';
        }
        d = (data && data.data) || {};
        urls = d.quality_urls || [];
        for (i = 0; i < urls.length; i++) {
            u = urls[i] && urls[i].url;
            if (u && u !== '1' && u.indexOf('http') === 0) { playUrl = u; break; }
        }
        if (playUrl) { msg = ''; break; }
        if (data && data.message) msg = data.message;
        if (attempt === 0 && (!page || ('' + msg).indexOf('令牌') >= 0 || !data.code)) continue;
        break;
    }
    return { url: playUrl, msg: playUrl ? '' : (msg || '获取播放地址失败') };
}

/* ================================================== 分类与筛选 */
var K4_TYPES = [['', '全部'], ['1', '剧情'], ['2', '悬疑'], ['3', '恐怖'], ['4', '惊悚'], ['5', '喜剧'],
    ['6', '爱情'], ['9', '犯罪'], ['10', '动作'], ['11', '动画'], ['12', '奇幻'], ['13', '音乐'],
    ['14', '科幻'], ['15', '历史'], ['16', '战争'], ['18', '冒险'], ['19', '家庭'], ['20', '纪录'],
    ['23', '西部'], ['24', '电视电影'], ['26', '真人秀'], ['27', '古装'], ['28', '传记'], ['29', '同性'],
    ['30', '运动'], ['31', '武侠'], ['32', '歌舞'], ['33', '纪录片'], ['34', '灾难'], ['35', '短片']];
var K4_AREAS = [['', '全部'], ['52', '中国大陆'], ['7', '中国'], ['14', '中国香港'], ['21', '中国台湾'],
    ['5', '美国'], ['11', '日本'], ['12', '韩国'], ['30', '英国'], ['6', '法国'], ['18', '德国'],
    ['19', '意大利'], ['22', '澳大利亚'], ['32', '加拿大'], ['33', '泰国'], ['34', '印度'],
    ['16', '俄罗斯'], ['17', '波兰'], ['24', '西班牙'], ['81', '阿根廷'], ['86', '墨西哥'],
    ['87', '比利时'], ['88', '瑞士'], ['94', '新西兰'], ['96', '巴西'], ['97', '印度尼西亚'],
    ['98', '南非'], ['78', '其他']];
var K4_YEARS = (function () {
    var a = [['', '全部']], y;
    for (y = 2027; y >= 1950; y--) a.push(['' + y, '' + y]);
    return a;
})();

function k4Values(pairs) {
    var out = [], i;
    for (i = 0; i < pairs.length; i++) out.push({ n: pairs[i][1], v: pairs[i][0] });
    return out;
}

function k4Filters() {
    var f = {}, ids = ['0', '1', '2', '3', '4'], i;
    for (i = 0; i < ids.length; i++) {
        f[ids[i]] = [
            { key: 'types', name: '类型', value: k4Values(K4_TYPES) },
            { key: 'areas', name: '地区', value: k4Values(K4_AREAS) },
            { key: 'years', name: '年份', value: k4Values(K4_YEARS) }
        ];
    }
    return f;
}

/* ================================================== 模块导出 */
export default {
    init: function (cfg) {
        try {
            var c = cfg;
            if (typeof c === 'string' && c.indexOf('{') === 0) c = JSON.parse(c);
            if (c && c.ext && typeof c.ext === 'string' && c.ext.indexOf('http') === 0) c = { host: c.ext };
            if (c && c.host) {
                K4_ROOT = ('' + c.host).replace(/\/+$/, '');
                K4_HOSTS = [K4_ROOT].concat(K4_HOSTS);
            }
        } catch (e) { }
        return true;
    },

    home: function (filter) {
        var classes = [
            { type_id: '0', type_name: '全部' },
            { type_id: '1', type_name: '电影' },
            { type_id: '2', type_name: '电视剧' },
            { type_id: '3', type_name: '动漫' },
            { type_id: '4', type_name: '综艺' }
        ];
        return JSON.stringify({ class: classes, filters: k4Filters() });
    },

    homeVod: function () {
        return JSON.stringify({ list: k4Items(k4Get(K4_ROOT + '/')) });
    },

    category: function (tid, pg, filter, extend) {
        var ext = extend || {}, q = [];
        if (tid && tid !== '0') q.push('classify=' + tid);
        if (ext.types) q.push('types=' + ext.types);
        if (ext.areas) q.push('areas=' + ext.areas);
        if (ext.years) q.push('years=' + ext.years);
        if (parseInt(pg, 10) > 1) q.push('page=' + pg);
        var url = K4_ROOT + '/filter' + (q.length ? '?' + q.join('&') : '');
        var list = k4Items(k4Get(url));
        return JSON.stringify({ list: list, page: parseInt(pg, 10) || 1, pagecount: 9999, limit: list.length, total: 9999 });
    },

    detail: function (id) {
        var vid = ('' + id).replace(/^.*\/play\//, '').split('?')[0];
        var html = k4Get(K4_ROOT + '/play/' + vid, K4_ROOT + '/');
        if (!html) return JSON.stringify({ list: [] });
        k4SyncToken(html, false);
        return JSON.stringify({ list: [k4Vod(html, vid)] });
    },

    search: function (wd, quick) {
        var url = K4_ROOT + '/search?q=' + encodeURIComponent(wd);
        return JSON.stringify({ list: k4Items(k4Get(url)) });
    },

    play: function (flag, id, flags) {
        var r = k4Play(id);
        // 注意: 本 App(PlayFragment) 播放时执行的是 playUrl(...) + url(...),
        // 即 "playUrl" 与 "url" 会被拼接, 所以直链只能放在 url 字段, 不能两个都填!
        return JSON.stringify({
            parse: 0,
            jx: 0,
            url: r.url,
            msg: r.url ? '' : r.msg,
            header: JSON.stringify({ 'User-Agent': K4_UA, 'Referer': K4_ROOT + '/' })
        });
    }
};
