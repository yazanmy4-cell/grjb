# -*- coding: utf-8 -*-
import os, time, base64, random, json, codecs, signal, threading, requests, hmac, hashlib, re, sys, struct, socket, urllib3, string, uuid
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from flask import Flask, request, jsonify

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

ex = False

JOBS = {}
JOBS_LOCK = threading.Lock()

rl = {
    "BD": "bn", "IND": "hi", "PK": "ur", "SG": "en", "ID": "id",
    "ME": "ar", "VN": "vi", "TW": "zh", "CIS": "ru", "TH": "th",
    "EU": "en", "US": "en", "SAC": "es", "LK": "en", "BR": "pt"
}


def gen_pw():
    suffix = ''.join(random.choices(string.ascii_letters + string.digits, k=20))
    return f"{suffix}"


def gn(prefix):
    suffix = ''.join(random.choices(string.ascii_letters, k=5))
    return f"{prefix}-{suffix}"


def _enc(h):
    d = bytes.fromhex(h)
    n = 16 - len(d) % 16
    d = d + bytes([n]) * n
    c = Cipher(algorithms.AES(bytes([89,103,38,116,99,37,68,69,117,104,54,37,90,99,94,56])),
               modes.CBC(bytes([54,111,121,90,68,114,50,50,69,51,121,99,104,106,77,37])),
               backend=default_backend()).encryptor()
    return (c.update(d) + c.finalize()).hex()


def _pk(d):
    n = 16 - len(d) % 16
    return d + bytes([n]) * n


def _vi(n):
    r = []
    while True:
        b = n & 0x7F; n >>= 7
        if n: b |= 0x80
        r.append(b)
        if not n: break
    return bytes(r)


def _pf(k, v):
    if isinstance(v, bool): return _vi((k << 3) | 0) + _vi(1 if v else 0)
    if isinstance(v, int): return _vi((k << 3) | 0) + _vi(v)
    if isinstance(v, str):
        e = v.encode(); return _vi((k << 3) | 2) + _vi(len(e)) + e
    if isinstance(v, (bytes, bytearray)):
        e = bytes(v); return _vi((k << 3) | 2) + _vi(len(e)) + e
    return b""


def _bp(f): return b"".join(_pf(k, v) for k, v in f.items())


def _rv(b, o):
    v = 0; s = 0
    while o < len(b):
        x = b[o]; o += 1; v |= (x & 0x7f) << s
        if not (x & 0x80): break
        s += 7
    return v, o


def _parse(b):
    o = 0; out = {}
    while o < len(b):
        t, o = _rv(b, o); f, w = t >> 3, t & 7
        if w == 0: v, o = _rv(b, o)
        elif w == 2:
            l, o = _rv(b, o); v = b[o:o+l]; o += l
        elif w == 5: v = b[o:o+4]; o += 4
        elif w == 1: v = b[o:o+8]; o += 8
        else: break
        out.setdefault(f, []).append(v)
    return out


def _gv(f, n):
    v = f.get(n)
    if v is None: return None
    if isinstance(v, list): v = v[0]
    return v


def _dec(rb):
    if not rb: return None
    body = rb
    if len(rb) > 64:
        try:
            if 8 in _parse(rb): body = rb
            elif 8 in _parse(rb[64:]): body = rb[64:]
            else: body = rb[64:]
        except: body = rb[64:]
    try: f = _parse(body)
    except: return None
    jb = _gv(f, 8); ub = _gv(f, 10); ts = _gv(f, 21); kb = _gv(f, 22); ib = _gv(f, 23); acct = _gv(f, 1)
    if not isinstance(kb, bytes) or not isinstance(ib, bytes): return None
    tx = lambda v: v.decode("utf-8","ignore") if isinstance(v, bytes) else (str(v) if v is not None else "")
    return {"jwt": tx(jb), "url": tx(ub), "ts": ts if isinstance(ts, int) else None,
            "key": kb, "iv": ib, "account_uid": acct if isinstance(acct, int) else None}


def _hdr(jwt=None):
    return {"User-Agent": "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
            "Accept": "*/*", "Accept-Encoding": "identity",
            "X-GA-SV": str(int(time.time())),
            "Authorization": "Bearer " + jwt if jwt else "Bearer",
            "X-GA": "v1 1", "ReleaseVersion": "OB55",
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Unity-Version": "2018.4.12f1",
            "Host": "loginbp.ppmainecoonghj.com"}


def _fields(at, oid, lang):
    return {3: time.strftime("%Y-%m-%d %H:%M:%S"), 4: "free fire", 5: 1, 7: "YAKOUB",
            8: "Android OS 9 / API-28 (PPR1.180720.122/6736742)", 9: "Handheld",
            10: "WIFI", 11: "WIFI", 12: 1257, 13: 480, 14: "240",
            15: "x86-64 | 2000 | 6", 16: 7965, 17: "Adreno (TM) 540",
            18: "OpenGL ES 3.2", 19: "Google|e6200d04-93a3-4514-9341-d379f92c92c2",
            20: "14.242.36.36", 21: lang or "en", 22: oid, 23: "4", 24: "Handheld",
            25: "infinix x6891", 29: at, 30: 1, 41: "WIFI", 42: "WIFI",
            57: "7428b253defc164018c604a1ebbfebdf", 60: 128886, 61: 113471, 62: 7998,
            64: 120040, 65: 128886, 66: 120040, 67: 128886, 73: 2,
            74: "/data/app/com.dts.freefireth/lib/arm64", 76: 1, 78: 3, 79: 2,
            81: "64", 83: "2019121229", 86: "OpenGLES2", 87: 4095, 88: 4,
            90: "City", 91: "ME", 92: 20583, 93: "android",
            94: "KqsHTxlzSl3i59tPt7bT3bNzIDdkBgGk3cO/WZnqY5h3i+mCiEozhU9+75L4xBzZExI/HsQIq8bS8vk7KzjerfDAftCvpq+MzU9ZBwlWJWqfcJOP",
            95: 111107, 96: '{"cur_rate":null,"support_etc2":false}', 97: 1, 98: 1,
            99: "4", 100: "4", 104: 83371, 105: 1,
            106: "https://dl.gmc.freefiremobile.com/live/ABHotUpdates/|https://core-gmc.freefiremobile.com/live/ABHotUpdates/|211c933168f55902c7dfbfd8c4e2957d",
            107: "c8e41b7a93f02d56e1a94c7b8203f5d1"}


def _login(at, oid, lang):
    try:
        pl = bytes.fromhex(_enc(_bp(_fields(at, oid, lang)).hex()))
        r = requests.post("https://loginbp.ppmainecoonghj.com/MajorLogin",
                          headers=_hdr(), data=pl, verify=False, timeout=15)
        if r.status_code != 200: return None
        a = _dec(r.content)
        if not a or not a["jwt"]: return None
        base = a["url"] or "https://clientbp.ppmainecoonghj.com"
        if not base.startswith("http"): base = "https://" + base
        base = base.rstrip("/")
        ld = None
        for h in [base, "https://clientbp.ppmainecoonghj.com"]:
            try:
                rr = requests.post(h + "/GetLoginData", headers=_hdr(a["jwt"]),
                                   data=pl, verify=False, timeout=15)
                if rr.status_code == 200 and rr.content:
                    ld = rr.content; base = h; break
            except Exception: continue
        if not ld: return None
        return {**a, "url": base, "login_data": ld, "payload": pl}
    except Exception: return None


def _bld(uid, jwt, ts, key, iv, mode="online"):
    ah = f"{int(uid):x}"
    if len(ah) > 16: return None
    ah = ah.zfill(16)
    enc = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).encryptor()
    enc = (enc.update(_pk(jwt.encode())) + enc.finalize()).hex()
    th = f"{int(ts):x}"
    if len(th) % 2: th = "0" + th
    tsz = f"{len(enc)//2:02x}"
    pd = "00000" if mode == "chat" else "0000000000000"
    return f"9015{ah}{th}{pd}{tsz}{enc}"


def _sock_tune(s):
    s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    try:
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 30)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
    except Exception: pass


def _sess(host, port, state, uid, jwt, ts, key, iv, mode, tag):
    s = None; start = time.time()
    try:
        s = socket.create_connection((host, int(port)), timeout=15)
        s.settimeout(20); _sock_tune(s)
        ah = _bld(uid, jwt, ts, key, iv, mode)
        if not ah: return 0
        s.sendall(bytes.fromhex(ah))
        state["ready"] = True
        if tag == "ChaT": state["online"] = True
        else: state["online2"] = True
        last = time.time(); s.settimeout(3.0)
        while True:
            now = time.time()
            if now - last > 60.0: return now - start
            if now - last > 15.0:
                try:
                    s.sendall(bytes.fromhex(_bld(uid, jwt, ts, key, iv, mode))); last = time.time()
                except Exception: return time.time() - start
            try:
                data = s.recv(9999)
                if not data: return time.time() - start
                last = time.time()
            except socket.timeout: continue
            except (ConnectionResetError, ConnectionAbortedError, OSError): return time.time() - start
    except Exception: return time.time() - start
    finally:
        if tag == "ChaT": state["online"] = False
        else: state["online2"] = False
        state["ready"] = False
        try:
            if s: s.close()
        except: pass


def _chat(host, port, state, uid, jwt, ts, key, iv):
    while not ex:
        _sess(host, port, state, uid, jwt, ts, key, iv, "online", "ChaT")
        time.sleep(1.0)


def _online(host2, port2, state, uid, jwt, ts, key, iv):
    while not ex:
        _sess(host2, port2, state, uid, jwt, ts, key, iv, "chat", "OnLinE")
        time.sleep(1.0)


def _start(uid, ip, port, ip2, port2, jwt, ts, key, iv, state, stop):
    def _sp():
        t1 = threading.Thread(target=_chat, args=(ip, port, state, uid, jwt, ts, key, iv), daemon=True)
        t2 = threading.Thread(target=_online, args=(ip2, port2, state, uid, jwt, ts, key, iv), daemon=True)
        t1.start()
        t0 = time.time()
        while not state.get("ready") and time.time() - t0 < 20:
            if stop[0]: return None, None
            time.sleep(0.1)
        time.sleep(0.5); t2.start()
        return t1, t2
    t1, t2 = _sp()
    if not t1: return
    while not stop[0]:
        if not t1.is_alive() or not t2.is_alive():
            state["ready"] = False; state["online"] = False; state["online2"] = False
            t1, t2 = _sp()
            if not t1: return
        time.sleep(2)


def xY4KOUB(region, prefix, base_pw, stop):
    for att in range(5):
        if stop[0]: return None
        try:
            s = requests.Session()
            pw = base_pw if base_pw else gen_pw()

            pr = json.dumps({"app_id": 100067, "client_type": 2, "password": pw, "source": 2},
                            separators=(",", ":"))
            sig = hmac.new("2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3".encode(),
                           pr.encode(), hashlib.sha256).hexdigest()
            hr = {"User-Agent": "GarenaMSDK/4.0.44(ASUS ;Android 13;en;%s;app 1.132.1 2019121229;)" % region,
                  "Accept": "application/json", "Authorization": "Signature %s" % sig,
                  "Content-Type": "application/json; charset=utf-8",
                  "Host": "100067.connect.garena.com"}
            rr = s.post("https://100067.connect.garena.com/api/v2/oauth/guest:register",
                        headers=hr, data=pr, timeout=12, verify=False)
            if rr.status_code != 200:
                if rr.status_code == 429: time.sleep(2 ** att)
                continue
            rj = rr.json()
            if rj.get("code") != 0: continue
            uid = rj["data"]["uid"]

            pt = json.dumps({"client_id": 100067,
                             "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
                             "client_type": 2,
                             "device_id": "02-%s" % hashlib.md5(str(uid).encode()).hexdigest()[:36],
                             "password": pw, "response_type": "token", "uid": uid},
                            separators=(",", ":"))
            ht = {"User-Agent": "GarenaMSDK/4.0.44(ASUS ;Android 13;en;%s;app 1.132.1 2019121229;)" % region,
                  "Accept": "application/json", "Content-Type": "application/json; charset=utf-8",
                  "Host": "100067.connect.garena.com"}
            rt = s.post("https://100067.connect.garena.com/api/v2/oauth/guest/token:grant",
                        headers=ht, data=pt, timeout=12, verify=False)
            if rt.status_code != 200: continue
            tj = rt.json()
            if tj.get("code") != 0: continue
            at = tj["data"]["access_token"]; oid = tj["data"]["open_id"]

            ks = [0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30,0x31,0x37,
                  0x30,0x30,0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30]
            fld = codecs.decode("".join(chr(ord(oid[i]) ^ ks[i % len(ks)]) for i in range(len(oid)))
                                .encode("unicode_escape").decode("utf-8"), "unicode_escape").encode("latin1")

            name = gn(prefix)

            lang = rl.get(region.upper(), "en")
            pd = _bp({1: name, 2: at, 3: oid, 5: 102000007, 6: 4, 7: 1, 13: 1, 14: fld,
                      15: lang, 16: 1, 17: 1, 20: "1.132.6", 21: 1,
                      22: bytes.fromhex('474752450101010067020000a6a42db7bc5516876af3d1ba4adc337bac558af092eb3757d59d65c9323bba42c6593a48b74f33b2b5b3dc45cbd7ac02040db58f394045be4835213e12c35e5566445a5224f39d205fcf91c0e6bec797e7b3968ac00e90d7500b5865828a9d6f2091c3070f5319a130748e407ed57e6638974670ac045631b3d08c310cf1256cebcf1aed2d97d177534603d1c95d9c5d698340e797e72aa7ecc67a33122e48b0dfda050a1649586aca5e979be1fd9d99f48cd8cf59630e0ff60f67d4ed2ec4e5e7475970449a6c06329009ee0ce2567892587675781a31e4bb2774403b2f78e9811df2cb397fa602572266747704c6258077910902eb7420bcb4ab743d1610cddba9019e7867aaad3aa7ba9b04968064a409b66733f9f78c566a25ff478cba37a2ffe23203d4b05bceef826f174b0be7912d19432cc759325251fa094d70693fb672d6f9e799284081b3adb541dd8f27ef80dcf1e7f0ff30f2fd976659457ce41e175a2d6301b777981ccc16b9a8247abaab8de0867836c27de0146fe4d0e1fd39b86ba51f0b58601cfcbd7f6f3451fe4184b26ed44ac2f6f7bb4ce5d9a80f88c2cbfe7553e5ab97c8b028ae16b4f70f037753b8c229a6e5e9038fcbb9b4c2abb954894f8f2faf177bfdaab3b0ed537156633621d16b62d58ba4ebe518997c33e2304976ba6af9df7e7e34302c7910ae559c7e3d20a30d71c14f85c0e86f26291bbf18c2d9dfe9a908592eea4523e6c1e5d9bb5abfbebfccd5c4e136f9be777723e932b06c029df5125191000c90fde62a8e5f8fceb28648f0c69ec3037d09302b2ade908a20dbd42761ca449b2743fc362649e16235769d9fbd7f87cd64972b58d69c0441abb5d22ddc6ed059f7ac1bdbfaef8c60e64631809c5e08c7cb4074c8ce6170d94b411604986be4ae163a')})
            ep = bytes.fromhex(_enc(pd.hex()))
            s.post("https://loginbp.ppmainecoonghj.com/MajorRegister", headers=_hdr(), data=ep, verify=False, timeout=12)

            lr = _login(at, oid, lang)
            if not lr or not lr.get("jwt") or not lr.get("ts"): continue
            gl = _parse(lr["login_data"])
            fa = _gv(gl, 14); ia = _gv(gl, 32)
            if not fa or not ia: continue
            try:
                fa = fa.decode() if isinstance(fa, bytes) else fa
                ia = ia.decode() if isinstance(ia, bytes) else ia
                ip, port = fa.split(":"); ip2, port2 = ia.split(":")
            except: continue
            aid = lr.get("account_uid") or 0
            st = {"online": False, "online2": False, "ready": False}
            sd = [False]
            th = threading.Thread(target=_start, args=(aid, ip, port, ip2, port2, lr["jwt"], lr["ts"], lr["key"], lr["iv"], st, sd), daemon=True)
            th.start()
            t0 = time.time()
            while not st.get("ready") and time.time() - t0 < 25:
                if stop[0]: sd[0] = True; return None
                time.sleep(0.1)
            if not st.get("ready"): sd[0] = True; continue
            return {"name": name, "uid": uid, "password": pw, "access_token": at,
                    "status": "ok", "account_id": str(aid), "state": st, "stop": sd,
                    "region": region}
        except Exception: pass
        time.sleep(0.3)
    return None


def wk(job_id, region, prefix, target, stop):
    while not ex:
        with JOBS_LOCK:
            job = JOBS.get(job_id)
            if not job or job["status"] == "stopped": break
            if job["count"] >= target:
                job["status"] = "done"
                break
        acc = xY4KOUB(region, prefix, "", stop)
        if acc:
            with JOBS_LOCK:
                job = JOBS.get(job_id)
                if job:
                    job["count"] += 1
                    job["results"].append({
                        "uid": acc["uid"],
                        "password": acc["password"],
                        "name": acc["name"],
                        "account_id": acc["account_id"],
                        "region": acc["region"],
                        "online": acc["state"].get("online", False),
                        "online2": acc["state"].get("online2", False),
                    })
                    job["last_update"] = time.time()
                    if job["count"] >= target:
                        job["status"] = "done"
        else:
            with JOBS_LOCK:
                job = JOBS.get(job_id)
                if job:
                    job["failed"] += 1
                    job["last_update"] = time.time()
        time.sleep(random.uniform(0.1, 0.3))


@app.route("/gen", methods=["POST", "GET"])
def gen():
    if request.method == "GET":
        name = request.args.get("name", "name")
        region = request.args.get("region", "ME")
        count = request.args.get("count", "1")
    else:
        data = request.get_json(silent=True) or {}
        name = data.get("name", "name")
        region = data.get("region", "ME")
        count = data.get("count", 1)

    name = str(name).strip() or "name"
    region = str(region).upper().strip() or "ME"
    try:
        count = int(count)
    except (ValueError, TypeError):
        return jsonify({"error": "count must be an integer"}), 400
    if count < 1:
        return jsonify({"error": "count must be >= 1"}), 400

    workers = min(66, count)
    job_id = uuid.uuid4().hex[:12]
    stop = [False]
    with JOBS_LOCK:
        JOBS[job_id] = {
            "id": job_id,
            "name": name,
            "region": region,
            "target": count,
            "count": 0,
            "failed": 0,
            "status": "running",
            "started_at": time.time(),
            "last_update": time.time(),
            "results": [],
            "stop": stop,
        }
    for _ in range(workers):
        t = threading.Thread(target=wk, args=(job_id, region, name, count, stop), daemon=True)
        t.start()

    print(f"[GEN] Job {job_id} | name={name} region={region} count={count}", flush=True)

    return jsonify({
        "job_id": job_id,
        "name": name,
        "region": region,
        "count": count,
        "workers": workers,
        "status": "started"
    }), 202


@app.route("/job/<job_id>", methods=["GET"])
def job_status(job_id):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            return jsonify({"error": "job not found"}), 404
        return jsonify({
            "id": job["id"],
            "name": job["name"],
            "region": job["region"],
            "target": job["target"],
            "count": job["count"],
            "failed": job["failed"],
            "status": job["status"],
            "elapsed": round(time.time() - job["started_at"], 2),
            "results": job["results"],
        })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, threaded=True, debug=False)