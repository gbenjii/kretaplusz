"""KRÉTA Plusz – Flask backend.

Indítás:
    pip install -r requirements.txt
    python app.py
Aztán: http://localhost:3000

A belépés a KRÉTA Plusz saját űrlapján történik. A szerver a háttérben végigmegy
a KRÉTA belépési folyamatán (OAuth2 + PKCE), a jelszót nem tárolja, csak a
tokent, memóriában, a szerver leállásáig.
"""
import base64
import hashlib
import json
import os
import re
import secrets
import time
from html.parser import HTMLParser
from urllib.parse import parse_qs, quote, urljoin, urlparse

import requests
from flask import Flask, jsonify, make_response, request, send_from_directory

app = Flask(__name__, static_folder="public", static_url_path="")

IDP = "https://idp.e-kreta.hu"
# FIGYELEM: ezeket az értékeket nem tudtam élőben ellenőrizni. Ha a belépés
# nem megy, a terminálban a [KRÉTA] sorok megmutatják, melyik lépés bukik, és
# környezeti változóval felülírhatod őket (a Refilc / Firka kódjában a pontos értékek).
CLIENT_ID = os.environ.get("KRETA_CLIENT_ID", "kreta-ellenorzo-student-mobile-ios")
UA = os.environ.get("KRETA_UA", "hu.ekreta.student/2.0.0/Android/0/0")
BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
AUTHORIZE = os.environ.get("KRETA_AUTHORIZE", f"{IDP}/connect/authorize")
REDIRECT_URI = os.environ.get("KRETA_REDIRECT_URI", "https://mobil.e-kreta.hu/ellenorzo-student/prod/oauthredirect")
SCOPE = os.environ.get("KRETA_SCOPE", "openid email offline_access kreta-ellenorzo-webapi.public")

ENDPOINTS = {
    "tanulo": "Sajat/TanuloAdatlap",
    "jegyek": "Sajat/Ertekelesek",
    "orarend": "Sajat/OrarendElemek",
    "mulasztasok": "Sajat/Mulasztasok",
    "hazi": "Sajat/HaziFeladatok",
    "szamonkeres": "Sajat/BejelentettSzamonkeresek",
    "feljegyzesek": "Sajat/Feljegyzesek",
}

sessions = {}  # sid -> {token, inst, at, exp, refresh}
pending = {}   # pid -> {verifier, state}  (kézi, tartalék belépéshez)


# ---------- PKCE segédek ----------
def b64url(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def new_pkce():
    verifier = b64url(secrets.token_bytes(48))
    challenge = b64url(hashlib.sha256(verifier.encode()).digest())
    return verifier, challenge, b64url(secrets.token_bytes(12))


def authorize_url(challenge, state):
    return (
        f"{AUTHORIZE}?response_type=code&client_id={CLIENT_ID}"
        f"&redirect_uri={quote(REDIRECT_URI, safe='')}&scope={quote(SCOPE)}"
        f"&code_challenge={challenge}&code_challenge_method=S256&state={state}&prompt=login"
    )


def jwt_claims(token):
    try:
        p = token.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
    except Exception:
        return {}


# ---------- A KRÉTA belépő oldalának automatikus kitöltése ----------
class FormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms, self.cur = [], None

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        if tag == "form":
            self.cur = {"action": d.get("action", ""), "fields": {}}
            self.forms.append(self.cur)
        elif tag in ("input", "select") and self.cur is not None and d.get("name"):
            self.cur["fields"][d["name"]] = d.get("value") or ""

    def handle_endtag(self, tag):
        if tag == "form":
            self.cur = None


def follow(s, url, trace, method="GET", data=None):
    """Átirányításokat követ kézzel. Visszaad: (válasz, kód). Ha a kód megjött, a kód nem None."""
    for _ in range(12):
        r = s.request(method, url, data=data, allow_redirects=False, timeout=20)
        trace.append(f"{method} {urlparse(url).netloc}{urlparse(url).path} -> {r.status_code}")
        loc = r.headers.get("Location")
        if loc:
            loc = urljoin(url, loc)
            code = (parse_qs(urlparse(loc).query).get("code") or [None])[0]
            if code:
                return r, code
            url, method, data = loc, "GET", None
            continue
        return r, None
    return None, None


def scripted_login(user, pw, inst):
    """Végigmegy a KRÉTA belépésén. Visszaad: (code, verifier, nyom, hiba)."""
    verifier, challenge, state = new_pkce()
    s = requests.Session()
    s.headers["User-Agent"] = BROWSER_UA
    trace = []
    try:
        r, code = follow(s, authorize_url(challenge, state), trace)
        if code:
            return code, verifier, trace, None
        if r is None:
            return None, verifier, trace, "Túl sok átirányítás"
        forms = FormParser()
        forms.feed(r.text)
        form = next((f for f in forms.forms if any(re.search("pass", k, re.I) for k in f["fields"])), None)
        if not form:
            return None, verifier, trace, "Nem találtam belépő űrlapot a KRÉTA oldalán"
        fields = dict(form["fields"])
        for k in list(fields):
            if re.fullmatch(r"user.?name|login.?name", k, re.I):
                fields[k] = user
            elif re.search("pass", k, re.I):
                fields[k] = pw
            elif re.search("institute", k, re.I):
                fields[k] = inst
        fields.setdefault("UserName", user)
        fields.setdefault("Password", pw)
        fields.setdefault("InstituteCode", inst)
        trace.append("űrlap mezői: " + ", ".join(sorted(fields)))
        post_url = urljoin(r.url, form["action"] or r.url)
        r2, code = follow(s, post_url, trace, "POST", fields)
        if code:
            return code, verifier, trace, None
        hint = "Hibás név, jelszó vagy iskolakód, vagy a KRÉTA captchát kér"
        return None, verifier, trace, hint
    except requests.RequestException as e:
        return None, verifier, trace, f"Hálózati hiba: {e}"


def exchange_code(code, verifier):
    r = requests.post(
        f"{IDP}/connect/token",
        headers={"User-Agent": UA},
        data={
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": verifier,
            "redirect_uri": REDIRECT_URI,
            "client_id": CLIENT_ID,
        },
        timeout=20,
    )
    try:
        j = r.json()
    except ValueError:
        j = {}
    return r, j


def start_session(j, inst):
    sid = secrets.token_hex(24)
    sessions[sid] = {
        "token": j["access_token"],
        "inst": inst,
        "at": time.time(),
        "exp": j.get("expires_in", 3000),
        "refresh": j.get("refresh_token"),
    }
    resp = make_response(jsonify(ok=True))
    resp.set_cookie("sid", sid, httponly=True, samesite="Strict", path="/")
    return resp


def refresh_session(s):
    if not s.get("refresh"):
        return False
    try:
        r = requests.post(
            f"{IDP}/connect/token",
            headers={"User-Agent": UA},
            data={"grant_type": "refresh_token", "refresh_token": s["refresh"], "client_id": CLIENT_ID},
            timeout=15,
        )
        j = r.json()
    except (requests.RequestException, ValueError):
        return False
    if not r.ok or "access_token" not in j:
        return False
    s.update(token=j["access_token"], at=time.time(), exp=j.get("expires_in", 3000), refresh=j.get("refresh_token", s["refresh"]))
    return True


# ---------- Útvonalak ----------
@app.get("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.post("/api/login")
def login():
    data = request.get_json(silent=True) or {}
    user, pw, inst = (data.get("user") or "").strip(), data.get("pass") or "", (data.get("inst") or "").strip()
    if not (user and pw and inst):
        return jsonify(error="Hiányzó adat"), 400

    # 1) a mai módszer: a KRÉTA belépő oldalának automatikus kitöltése
    code, verifier, trace, err = scripted_login(user, pw, inst)
    if code:
        try:
            r, j = exchange_code(code, verifier)
            if r.ok and "access_token" in j:
                inst_claim = jwt_claims(j["access_token"]).get("kreta:institute_code") or inst
                return start_session(j, inst_claim)
            print(f"[KRÉTA] kódbeváltás: {r.status_code} {str(j)[:300]}")
            err = f"A kód beváltása nem sikerült ({r.status_code})"
        except requests.RequestException as e:
            err = f"Hálózati hiba: {e}"
    print("[KRÉTA] belépés nyoma:\n  " + "\n  ".join(trace) + f"\n  hiba: {err}")

    # 2) tartalék: a régi, közvetlen jelszavas módszer
    try:
        r = requests.post(
            f"{IDP}/connect/token",
            headers={"User-Agent": UA},
            data={"userName": user, "password": pw, "institute_code": inst, "grant_type": "password", "client_id": CLIENT_ID},
            timeout=15,
        )
        j = r.json() if r.content else {}
        if r.ok and "access_token" in j:
            return start_session(j, inst)
    except (requests.RequestException, ValueError):
        pass
    return jsonify(error="Sikertelen belépés. Ellenőrizd a nevet, jelszót és az iskolakódot.", detail=err), 401


@app.get("/api/auth/start")
def auth_start():
    verifier, challenge, state = new_pkce()
    pid = secrets.token_hex(16)
    pending[pid] = {"verifier": verifier}
    resp = make_response(jsonify(url=authorize_url(challenge, state)))
    resp.set_cookie("pid", pid, httponly=True, samesite="Strict", path="/")
    return resp


@app.post("/api/auth/finish")
def auth_finish():
    data = request.get_json(silent=True) or {}
    p = pending.pop(request.cookies.get("pid", ""), None)
    if not p:
        return jsonify(error="Előbb kattints a belépés gombra."), 400
    raw = (data.get("url") or "").strip()
    code = (parse_qs(urlparse(raw).query).get("code") or [""])[0]
    if not code and "?" not in raw and "/" not in raw and len(raw) >= 20:
        code = raw
    if not code:
        return jsonify(error="Nem találtam kódot a címben. A cím végén ?code=... kell legyen."), 400
    try:
        r, j = exchange_code(code, p["verifier"])
    except requests.RequestException as e:
        return jsonify(error="A KRÉTA nem elérhető", detail=str(e)), 502
    if not r.ok or "access_token" not in j:
        print(f"[KRÉTA] kódbeváltás: {r.status_code} {str(j)[:300]}")
        return jsonify(error="A kód beváltása nem sikerült", detail=j.get("error_description") or j.get("error") or r.status_code), 401
    inst = jwt_claims(j["access_token"]).get("kreta:institute_code") or (data.get("inst") or "").strip()
    if not inst:
        return jsonify(error="Az iskolakód nem derült ki, add meg az OM-azonosítót."), 400
    return start_session(j, inst)


@app.post("/api/logout")
def logout():
    sessions.pop(request.cookies.get("sid", ""), None)
    resp = make_response(jsonify(ok=True))
    resp.delete_cookie("sid", path="/")
    return resp


@app.get("/api/<what>")
def proxy(what):
    s = sessions.get(request.cookies.get("sid", ""))
    if not s:
        return jsonify(error="Lejárt munkamenet"), 401
    if time.time() - s["at"] > s["exp"] - 30 and not refresh_session(s):
        return jsonify(error="Lejárt munkamenet"), 401
    ep = ENDPOINTS.get(what)
    if not ep:
        return jsonify(error="Ismeretlen végpont"), 404
    url = f"https://{s['inst']}.e-kreta.hu/ellenorzo/V3/{ep}"
    try:
        for attempt in (1, 2):
            r = requests.get(url, params=request.args,
                             headers={"Authorization": f"Bearer {s['token']}", "User-Agent": UA}, timeout=15)
            if r.status_code == 401 and attempt == 1 and refresh_session(s):
                continue
            break
    except requests.RequestException as e:
        print(f"[KRÉTA] {what}: hálózati hiba: {e}")
        return jsonify(error="A KRÉTA nem elérhető", detail=str(e)), 502
    if not r.ok:
        print(f"[KRÉTA] {what}: {r.status_code} {url} -> {r.text[:300]}")
        return jsonify(error=f"A KRÉTA {r.status_code} hibát adott ({what})", detail=r.text[:300]), r.status_code
    return app.response_class(r.text or "[]", status=200, mimetype="application/json")


if __name__ == "__main__":
    # Csak a saját gépedről érhető el. Ne tedd ki az internetre.
    app.run(host="127.0.0.1", port=3000, debug=False)
