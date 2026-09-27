# -*- coding: utf-8 -*-
"""
4K影视 (4kvm) TVBox Python 爬虫
==================================================
站点   : https://www.4kvm.top     备用: https://4kvm.site
格式   : TVBox / 影视 通用 Python 源 (Spider 类)
说明   : 本脚本已完整还原站点播放地址签名算法(原站为 WASM 加密),
         无需任何第三方签名服务即可直接取到 m3u8 播放地址。

播放地址签名算法(已逐字节验证):
    blockA = XOR( secret_key 补零到 64 字节 , 0x36 )
    blockB = XOR( secret_key 补零到 64 字节 , 0x5C )
    h1     = SHA256( blockA + "{dataid}:{timestamp}:{secret_key}" )
    s      = SHA256( blockB + h1 ).hexdigest()[:32]
    k      = base64( XOR( play_key , "nbmovie2024secretkey" ) )   # play_key 为空或 '0' 时为 '0'
    url    = /video/play?p={dataid}&v={secret_key}&q=1080&s={s}&t={timestamp}&k={k}

时间戳使用站点服务器时间(页内 <meta id="nb-st">)与本地时钟的差值校正,
避免盒子时间不准导致 401。
"""

import base64
import hashlib
import json
import re
import time

import requests

# ------------------------------------------------------------------ 常量
HOSTS = ["https://www.4kvm.top", "https://4kvm.site"]
UA = ("Mozilla/5.0 (Linux; Android 13; V2309A Build/TP1A.220624.014; wv) "
      "AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/116.0.0.0 "
      "Mobile Safari/537.36")
SECRET = "nbmovie2024secretkey"
CDN_FALLBACK = {"oss.douyinbit.com": "myoss.douyinbit.top"}

CLASSES = [
    {"type_id": "0", "type_name": "全部"},
    {"type_id": "1", "type_name": "电影"},
    {"type_id": "2", "type_name": "电视剧"},
    {"type_id": "3", "type_name": "动漫"},
    {"type_id": "4", "type_name": "综艺"},
]

TYPES = [("", "全部"), ("1", "剧情"), ("2", "悬疑"), ("3", "恐怖"), ("4", "惊悚"), ("5", "喜剧"),
         ("6", "爱情"), ("9", "犯罪"), ("10", "动作"), ("11", "动画"), ("12", "奇幻"), ("13", "音乐"),
         ("14", "科幻"), ("15", "历史"), ("16", "战争"), ("18", "冒险"), ("19", "家庭"), ("20", "纪录"),
         ("23", "西部"), ("24", "电视电影"), ("26", "真人秀"), ("27", "古装"), ("28", "传记"),
         ("29", "同性"), ("30", "运动"), ("31", "武侠"), ("32", "歌舞"), ("33", "纪录片"),
         ("34", "灾难"), ("35", "短片")]

AREAS = [("", "全部"), ("52", "中国大陆"), ("7", "中国"), ("14", "中国香港"), ("21", "中国台湾"),
         ("5", "美国"), ("11", "日本"), ("12", "韩国"), ("30", "英国"), ("6", "法国"), ("18", "德国"),
         ("19", "意大利"), ("22", "澳大利亚"), ("32", "加拿大"), ("33", "泰国"), ("34", "印度"),
         ("16", "俄罗斯"), ("17", "波兰"), ("24", "西班牙"), ("81", "阿根廷"), ("82", "冰岛"),
         ("84", "爱尔兰"), ("86", "墨西哥"), ("87", "比利时"), ("88", "瑞士"), ("90", "Philippines"),
         ("92", "匈牙利"), ("93", "西德"), ("94", "新西兰"), ("95", "哥伦比亚"), ("96", "巴西"),
         ("97", "印度尼西亚"), ("98", "南非"), ("78", "其他")]

YEARS = [("", "全部"), ("78", "2027"), ("1", "2026"), ("3", "2025"), ("4", "2024"), ("56", "2023"),
         ("13", "2022"), ("2", "2021"), ("6", "2020"), ("8", "2019"), ("9", "2018"), ("12", "2017"),
         ("11", "2016"), ("14", "2015"), ("15", "2014"), ("22", "2013"), ("10", "2012"), ("17", "2011"),
         ("25", "2010"), ("20", "2009"), ("23", "2008"), ("30", "2007"), ("31", "2006"), ("7", "2005"),
         ("24", "2004"), ("28", "2003"), ("19", "2002"), ("29", "2001"), ("43", "2000"),
         ("45", "1999"), ("33", "1998"), ("34", "1997"), ("37", "1996"), ("21", "1995"), ("27", "1994"),
         ("26", "1993"), ("35", "1992"), ("18", "1991"), ("42", "1990"), ("44", "1989"), ("60", "1988"),
         ("32", "1986"), ("40", "1985"), ("36", "1982"), ("39", "1980"), ("48", "1977"), ("57", "1975"),
         ("54", "1972"), ("41", "1969"), ("75", "1960"), ("47", "1955"), ("72", "1952"), ("70", "1949"),
         ("64", "1948"), ("55", "1931")]


def _v(items):
    return [{"n": n, "v": i} for i, n in items]


FILTERS = {
    tid: [
        {"key": "types", "name": "类型", "value": _v(TYPES)},
        {"key": "areas", "name": "地区", "value": _v(AREAS)},
        {"key": "years", "name": "年份", "value": _v(YEARS)},
    ]
    for tid in ["0", "1", "2", "3", "4"]
}


# ------------------------------------------------------------------ 工具
def _xor(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def _pad64(s: str) -> bytes:
    b = bytearray(64)
    raw = s.encode("utf-8")
    b[: min(len(raw), 64)] = raw[:64]
    return bytes(b)


def _hmac_none(s: str) -> str:  # 站内 JS 用的 31 进制 hash, 登录用
    h = 0
    for ch in s:
        h = (h * 31 + ord(ch)) & 0xFFFFFFFF
    return "%x" % h


# ------------------------------------------------------------------ 爬虫
class Spider(object):
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": UA,
            "Accept-Language": "zh-CN,zh;q=0.9",
        })
        self.host = HOSTS[0]
        self._token = "0"          # 访客访问令牌(页内 userlink)
        self._token_time = 0
        self._offset = 0           # 服务器时间偏移(毫秒)
        self._user = ""
        self._pass = ""

    # -------------------------------------------------- 网络
    def _get(self, url, referer=None, accept="text/html,application/xhtml+xml,*/*;q=0.8", timeout=15):
        """返回响应文本; 非 2xx 也返回正文(接口用 401/403 状态码携带提示信息)"""
        headers = {"Accept": accept}
        if referer:
            headers["Referer"] = referer
        for i in range(2):
            try:
                r = self.session.get(url, headers=headers, timeout=timeout)
                if r.status_code < 500:
                    return r.text
            except Exception:  # noqa  连接失败时切备用域名
                if i == 0 and self.host in url:
                    for h in HOSTS:
                        if h != self.host:
                            url = url.replace(self.host, h)
                            self.host = h
                            break
        return ""

    def _api(self, path, referer=None):
        return self._get(self.host + path,
                         referer=referer or (self.host + "/"),
                         accept="application/json, text/plain, */*")

    # -------------------------------------------------- 签名
    def _now(self):
        return int(time.time() * 1000) + self._offset

    def _play_url(self, dataid, secret_key, quality="1080", play_key="0"):
        key = SECRET.encode("utf-8")
        pad = _pad64(secret_key)
        block_a = bytes(b ^ 0x36 for b in pad)
        block_b = bytes(b ^ 0x5C for b in pad)
        ts = self._now()
        h1 = hashlib.sha256(block_a + ("%s:%d:%s" % (dataid, ts, secret_key)).encode("utf-8")).digest()
        s = hashlib.sha256(block_b + h1).hexdigest()[:32]
        if play_key in ("", "0"):
            k = "0"
        else:
            k = base64.b64encode(_xor(play_key.encode("utf-8"), key)).decode("ascii")
        return "/video/play?p=%s&v=%s&q=%s&s=%s&t=%d&k=%s" % (
            dataid, secret_key, quality, s, ts, k)

    # -------------------------------------------------- 页面解析
    @staticmethod
    def _fix_pic(url):
        if not url:
            return ""
        return url.replace("&amp;", "&")

    def _items(self, html):
        """列表页/搜索结果页 -> vod 列表"""
        out = []
        seen = set()
        for chunk in html.split('<a href="/play/')[1:]:
            seg = chunk.split("</a>")[0]
            vid = chunk.split('"', 1)[0]
            if not vid or vid in seen:
                continue
            seen.add(vid)
            pic = re.search(r'data-src="([^"]+)"', seg)
            if not pic:
                pic = re.search(r'<img[^>]+src="(https?://[^"]+)"', seg)
            name = re.search(r'alt="([^"]*)"', seg)
            if not name:
                name = re.search(r"<h3[^>]*>\s*([^<]+?)\s*</h3>", seg)
            year = re.search(r"bg-black/70[^>]*>\s*([^<]{2,12}?)\s*</div>", seg)
            qual = re.search(r"bg-accent/80[^>]*>\s*([^<]{1,8}?)\s*</div>", seg)
            rem = " ".join([x for x in [(year.group(1) if year else ""),
                                        (qual.group(1) if qual else "")] if x])
            out.append({
                "vod_id": vid,
                "vod_name": (name.group(1).strip() if name else vid),
                "vod_pic": self._fix_pic(pic.group(1) if pic else ""),
                "vod_remarks": rem,
            })
        return out

    @staticmethod
    def _info_map(html):
        d = {}
        for m in re.finditer(r'col-span-1 text-gray-500">([^<]+)</div>\s*'
                             r'<div class="col-span-2 text-gray-300">(.*?)</div>', html, re.S):
            d[m.group(1).strip()] = re.sub(r"\s+", " ", m.group(2)).strip()
        return d

    def _episodes(self, html):
        """详情页 -> {线路序号: [(集名, 密钥, dataid, 是否VIP)]}"""
        lines = {}
        for m in re.finditer(r'<a href="/play/([^"]+)"([^>]*)>(.*?)</a>', html, re.S):
            attrs, body = m.group(2), m.group(3)
            dm = re.search(r'dataid="(\d+)"', attrs)
            if not dm:
                continue
            ln = re.search(r'data-line="(\d+)"', attrs)
            ep = re.search(r'data-episode="(\d+)"', attrs)
            idx = int(ln.group(1)) if ln else 1
            num = int(ep.group(1)) if ep else (len(lines.get(idx, [])) + 1)
            vip = "vip-icon" in body
            lines.setdefault(idx, []).append((num, m.group(1), dm.group(1), vip))
        # 线路名(页内 episodeManager 配置)
        names = re.findall(r"lineName:\s*'([^']*)'", html)
        out = []
        for idx in sorted(lines.keys()):
            eps = sorted(lines[idx], key=lambda x: x[0])
            name = names[idx - 1] if idx - 1 < len(names) and names[idx - 1] else ("线路%d" % idx)
            out.append((name, eps))
        return out

    def _time_offset(self, html):
        m = re.search(r'id="nb-st"\s+content="(\d+)"', html)
        if m:
            try:
                self._offset = int(m.group(1)) - int(time.time() * 1000) + 400  # +请求耗时补偿
            except Exception:
                self._offset = 0

    def _guest_token(self, html, force=False):
        if not force and self._token not in ("", "0") and time.time() - self._token_time < 6 * 3600:
            return self._token
        m = re.search(r"userlink:'([^']*)'", html)
        if m:
            self._token = m.group(1) or "0"
            self._token_time = time.time()
        return self._token

    # -------------------------------------------------- 登录(可选)
    def _login(self):
        if not (self._user and self._pass):
            return False
        nonce = ""
        try:
            j = json.loads(self._api("/api/login/nonce"))
            nonce = (j.get("data") or {}).get("nonce", "")
        except Exception:
            return False
        ts = self._now()
        sign = _hmac_none("nbmv_login_v1|%d|%s|%s|%s" % (ts, self._user.strip().lower(), self._pass, nonce))
        try:
            r = self.session.post(self.host + "/api/login",
                                  json={"username": self._user, "password": self._pass,
                                        "client_ts": ts, "client_nonce": nonce, "client_sign": sign},
                                  headers={"Content-Type": "application/json"}, timeout=15)
            return (r.json() or {}).get("code") == 200
        except Exception:
            return False

    # -------------------------------------------------- TVBox 接口
    def init(self, extend=""):
        ext = extend
        if isinstance(ext, dict):
            cfg = ext
        else:
            cfg = {}
            s = (extend or "").strip()
            if s.startswith("{"):
                try:
                    cfg = json.loads(s)
                except Exception:
                    cfg = {}
            elif ":" in s and "//" not in s:
                u, _, p = s.partition(":")
                cfg = {"user": u, "pass": p}
        if cfg.get("host"):
            self.host = cfg["host"].rstrip("/")
            HOSTS.insert(0, self.host)
        self._user = cfg.get("user") or cfg.get("username") or ""
        self._pass = cfg.get("pass") or cfg.get("password") or ""
        if self._user and self._pass:
            self._login()

    def homeContent(self, filter=False):
        return {"class": CLASSES, "filters": FILTERS}

    def homeVideoContent(self):
        html = self._get(self.host + "/")
        return {"list": self._items(html)}

    def categoryContent(self, tid, pg, filter=False, extend=None):
        ext = extend or {}
        try:
            page = int(pg)
        except Exception:
            page = 1
        params = []
        if str(tid) not in ("", "0", "None"):
            params.append("classify=%s" % tid)
        for key in ("types", "areas", "years"):
            val = ext.get(key)
            if val:
                params.append("%s=%s" % (key, val))
        if page > 1:
            params.append("page=%d" % page)
        url = self.host + "/filter" + ("?" + "&".join(params) if params else "")
        html = self._get(url)
        lst = self._items(html)
        return {"list": lst, "page": page, "pagecount": 9999, "limit": len(lst), "total": 9999}

    def detailContent(self, ids):
        vid = ids[0] if isinstance(ids, (list, tuple)) else str(ids)
        if vid.startswith("http"):
            vid = vid.rstrip("/").split("/")[-1].split("?")[0]
        html = self._get(self.host + "/play/" + vid, referer=self.host + "/")
        if not html:
            return {"list": []}
        self._time_offset(html)
        self._guest_token(html)
        title = re.search(r"<title>([^<]*)</title>", html)
        name = (title.group(1) if title else vid).split(" - ")[0].strip()
        poster = re.search(r'data-poster="([^"]+)"', html)
        if not poster:
            poster = re.search(r'<meta property="og:image" content="([^"]+)"', html)
        info = self._info_map(html)
        desc = re.search(r'剧情简介[\s\S]{0,200}?<p[^>]*>(.*?)</p>', html)
        score = re.search(r'ri-star-fill"/></svg>\s*([\d.]+)', html)
        area_chip = re.search(r'ri-map-pin-line"/></svg>\s*([^<]+?)\s*</span>', html)
        content = []
        if desc:
            content.append(re.sub(r"<[^>]+>", "", desc.group(1)).strip())
        if info.get("导演"):
            content.append("导演: " + info["导演"])
        if info.get("主演"):
            content.append("主演: " + info["主演"])
        if score:
            content.append("评分: " + score.group(1))
        if info.get("又名"):
            content.append("又名: " + info["又名"])

        lines = self._episodes(html)
        froms, urls = [], []
        if lines:
            for idx, (lname, eps) in enumerate(lines):
                froms.append(lname)
                urls.append("#".join([
                    "%s%s$%s|%s" % ("第%d集" % n if n else "播放",
                                    "[VIP]" if vip else "", skey, dataid)
                    for (n, skey, dataid, vip) in eps]))
        else:
            # 单片(电影) 无选集: 用页面自身
            skey = vid
            dataid = re.search(r'dataid="(\d+)"', html)
            froms.append("4K影视")
            urls.append("播放$%s|%s" % (skey, dataid.group(1) if dataid else ""))
        vod = {
            "vod_id": vid,
            "vod_name": name,
            "vod_pic": self._fix_pic(poster.group(1) if poster else ""),
            "type_name": (info.get("类型") or "") + (" " + area_chip.group(1) if area_chip else ""),
            "vod_year": (info.get("上映") or "")[:4],
            "vod_area": info.get("地区") or (area_chip.group(1) if area_chip else ""),
            "vod_actor": info.get("主演") or "",
            "vod_director": info.get("导演") or "",
            "vod_remarks": info.get("片长") or "",
            "vod_content": "\n".join(content),
            "vod_play_from": "$$$".join(froms),
            "vod_play_url": "$$$".join(urls),
        }
        return {"list": [vod]}

    def searchContent(self, key, quick=False):
        html = self._get(self.host + "/search?q=" + requests.utils.quote(key))
        return {"list": self._items(html)}

    def _cdn_ok(self, url, timeout=4):
        try:
            r = self.session.get(url, headers={"Range": "bytes=0-1", "Accept": "*/*"},
                                 timeout=timeout, stream=True)
            ok = r.status_code in (200, 206)
            r.close()
            return ok
        except Exception:
            return False

    def playerContent(self, flag, vid, vip_flags=None):
        try:
            skey, _, dataid = str(vid).partition("|")
            if not dataid:
                dataid, skey = skey, ""
            play, msg = "", ""
            # 站点令牌一次一换, 播放前重新取页面拿最新令牌(与原站浏览器行为一致)
            for attempt in (0, 1):
                page = self._get(self.host + "/play/" + skey, referer=self.host + "/")
                if page:
                    self._time_offset(page)
                    self._guest_token(page, force=True)
                token = self._token or "0"
                path = self._play_url(dataid, skey, "1080", token)
                txt = self._api(path, referer=self.host + "/play/" + skey)
                data = {}
                try:
                    data = json.loads(txt)
                except Exception:
                    data = {}
                if not data and txt:
                    msg = txt.strip()[:120]          # 接口异常时是纯文本提示
                d = data.get("data") or {}
                for q in (d.get("quality_urls") or []):
                    u = (q or {}).get("url") or ""
                    if u and u != "1" and u.startswith("http"):
                        play = u
                        break
                if play:
                    msg = ""
                    break
                if data:
                    msg = data.get("message") or msg
                if attempt == 0 and ("令牌" in (msg or "") or not data):
                    continue                          # 换新令牌重试一次
                break
            if play and CDN_FALLBACK:
                for bad, good in CDN_FALLBACK.items():
                    if bad in play and not self._cdn_ok(play):
                        alt = play.replace(bad, good)
                        if self._cdn_ok(alt):
                            play = alt
                        break
            return {
                "parse": 0,
                "playUrl": play,
                "url": play,
                "msg": "" if play else (msg or "获取播放地址失败"),
                "header": json.dumps({"User-Agent": UA, "Referer": self.host + "/"},
                                     ensure_ascii=False),
            }
        except Exception as e:  # noqa
            return {"parse": 0, "playUrl": "", "url": "", "msg": "解析异常: %s" % e,
                    "header": ""}


# ------------------------------------------------------------------ 本地自测
if __name__ == "__main__":
    s = Spider()
    s.init("")
    print("== home ==")
    hv = s.homeVideoContent()
    print("  条数:", len(hv["list"]), hv["list"][:2])
    print("== category 电影 p1 ==")
    c = s.categoryContent("1", 1, False, {})
    print("  条数:", len(c["list"]), c["list"][:2])
    print("== category 电影 p2 ==")
    c2 = s.categoryContent("1", 2, False, {})
    print("  条数:", len(c2["list"]), "首条:", c2["list"][0]["vod_name"] if c2["list"] else "-")
    print("== search 复仇者 ==")
    sr = s.searchContent("复仇者")
    print("  条数:", len(sr["list"]), sr["list"][:2])
    if sr["list"]:
        vid = sr["list"][0]["vod_id"]
        print("== detail", vid, "==")
        d = s.detailContent([vid])
        v = d["list"][0]
        print("  名称:", v["vod_name"], "| 年份:", v["vod_year"], "| 地区:", v["vod_area"])
        print("  线路:", v["vod_play_from"])
        print("  选集:", v["vod_play_url"][:200])
        print("  简介:", v["vod_content"][:80].replace("\n", " / "))
        print("== play ==")
        first = v["vod_play_url"].split("$$$")[0].split("#")[0].split("$")[-1]
        p = s.playerContent("", first, None)
        print("  playUrl:", p["playUrl"][:120])
        print("  msg:", p["msg"])
