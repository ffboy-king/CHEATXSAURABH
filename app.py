from flask import Flask, request, jsonify, Response
import requests
import jwt
import urllib3
import json
from collections import OrderedDict
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import ReqCLan_pb2
import QuitClanReq_pb2
import MajorLoginReq_pb2
import MajorLoginRes_pb2
import os , shutil
import data_pb2
import uid_generator_pb2
import binascii

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
app.config["JSON_AS_ASCII"] = False

OB = "OB54"

API_INFO = {
    "developer": "R O H I T",
    "telegram": "@FFclient",
    "api_name": "FF GUILD JOIN/LEAVE API",
    "version": OB}

KEY = bytes([89,103,38,116,99,37,68,69,117,104,54,37,90,99,94,56])
IV  = bytes([54,111,121,90,68,114,50,50,69,51,121,99,104,106,77,37])

GAME_HEADERS = {
    "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9)",
    "Connection": "Keep-Alive",
    "Accept-Encoding": "gzip",
    "Content-Type": "application/octet-stream",
    "X-Unity-Version": "2018.4.11f1",
    "X-GA": "v1 1",
    "ReleaseVersion": OB,
    "Expect": "100-continue"}

LOGIN_HEADERS = GAME_HEADERS.copy()

REGION_SERVER_MAP = {
    "IND": "https://client.ind.freefiremobile.com",
    "ME":  "https://clientbp.ggpolarbear.com",
    "VN":  "https://clientbp.ggpolarbear.com",
    "BD":  "https://clientbp.ggpolarbear.com",
    "PK":  "https://clientbp.ggpolarbear.com",
    "SG":  "https://clientbp.ggpolarbear.com",
    "BR":  "https://client.us.freefiremobile.com",
    "NA":  "https://client.us.freefiremobile.com",
    "ID":  "https://clientbp.ggpolarbear.com",
    "RU":  "https://clientbp.ggpolarbear.com",
    "TH":  "https://clientbp.ggpolarbear.com",}

DEFAULT_SERVER_URL = "https://client.ind.freefiremobile.com"
LOGIN_URL = "https://loginbp.ggpolarbear.com/MajorLogin"

def clear_pycache(root_dir):
    """Automatic Delete the __pycache__"""
    for dirpath, dirnames, filenames in os.walk(root_dir, topdown=False):

        if os.path.basename(dirpath) == "__pycache__":
            try:
                shutil.rmtree(dirpath)
            except Exception:
                pass

clear_pycache(os.getcwd())

def create_info_protobuf(uid):
    message = uid_generator_pb2.uid_generator()
    message.saturn_ = int(uid)
    message.garena = 1
    return message.SerializeToString()

def encrypt_payload(data):
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    return cipher.encrypt(pad(data, AES.block_size))

def decode_jwt(token):
    try:
        decoded = jwt.decode(token, options={"verify_signature": False})
        account_id = str(decoded.get("account_id"))
        nickname = decoded.get("nickname")
        lock_region = decoded.get("lock_region")
        return account_id, nickname, lock_region
    except Exception:
        return None, None, None

def get_player_info(target_uid, token, server_name=None):
    try:
        if not server_name:
            server_name = decode_jwt(token)[2]
        protobuf_data = create_info_protobuf(target_uid)
        encrypted_data = encrypt_payload(protobuf_data)
        endpoint = get_server_url(server_name) + "/GetPlayerPersonalShow"
        headers = GAME_HEADERS.copy()
        headers["Authorization"] = f"Bearer {token}"
        response = requests.post(endpoint, data=encrypted_data, headers=headers, verify=False)
        if response.status_code != 200:
            return None
        info = data_pb2.AccountPersonalShowInfo()
        info.ParseFromString(response.content)
        return info
    except Exception:
        return None

def extract_player_info(info_data):
    if not info_data:
        return None
    basic = info_data.basic_info
    return {
        "uid": basic.account_id,
        "nickname": basic.nickname,
        "level": basic.level,
        "region": basic.region,
        "likes": basic.liked,
        "release_version": basic.release_version}

def get_server_url(region):
    return REGION_SERVER_MAP.get(region, DEFAULT_SERVER_URL)

def perform_major_login(access_token, open_id):
    try:
        major = MajorLoginReq_pb2.MajorLogin()
        major.event_time = "2025-03-23 12:00:00"
        major.game_name = "free fire"
        major.platform_id = 1
        major.client_version = "1.129.15"
        major.system_software = "Android OS 9 / API-28"
        major.system_hardware = "Handheld"
        major.telecom_operator = "Verizon"
        major.network_type = "WIFI"
        major.screen_width = 1920
        major.screen_height = 1080
        major.screen_dpi = "280"
        major.processor_details = "ARM64 FP ASIMD AES VMH | 2865 | 4"
        major.memory = 3003
        major.gpu_renderer = "Adreno (TM) 640"
        major.gpu_version = "OpenGL ES 3.1 v1.46"
        major.unique_device_id = "Google|34a7dcdf"
        major.client_ip = ""
        major.language = "en"
        major.open_id = open_id
        major.open_id_type = "4"
        major.device_type = "Handheld"
        major.memory_available.version = 55
        major.memory_available.hidden_value = 81
        major.access_token = access_token
        major.platform_sdk_id = 1
        major.network_operator_a = "Verizon"
        major.network_type_a = "WIFI"
        major.login_by = 3
        major.origin_platform_type = "4"
        major.primary_platform_type = "4"
        encrypted = encrypt_payload(major.SerializeToString())
        r = requests.post(LOGIN_URL, headers=LOGIN_HEADERS, data=encrypted, verify=False, timeout=10)
        print("MajorLogin status:", r.status_code)
        if r.status_code == 200 and len(r.content) > 5:
            msg = MajorLoginRes_pb2.MajorLoginRes()
            msg.ParseFromString(r.content)
            if msg.token:
                print("JWT generated successfully")
                return msg.token
    except Exception as e:
        print("Login attempt failed:", e)
    return None

def guest_login(uid, password):
    payload = {
        "uid": uid,
        "password": password,
        "response_type": "token",
        "client_type": "2",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id": "100067"}
    headers = {"User-Agent": "GarenaMSDK/4.0.19P9"}
    try:
        r = requests.post(
            "https://100067.connect.garena.com/oauth/guest/token/grant",
            data=payload,
            headers=headers,
            verify=False,
            timeout=10)
        data = r.json()
        return data.get("access_token"), data.get("open_id")
    except Exception as e:
        print("Guest login error:", e)
        return None, None

def access_token_to_jwt(access_token):
    try:
        inspect_url = f"https://100067.connect.garena.com/oauth/token/inspect?token={access_token}"
        r = requests.get(inspect_url, timeout=10)
        if r.status_code != 200:
            return None,None,None,None
        data = r.json()
        open_id = data.get("open_id")
        if not open_id:
            return None,None,None,None
        for pt in [2,3,4,6,8]:
            major = MajorLoginReq_pb2.MajorLogin()
            major.event_time="2025-03-23 12:00:00"
            major.game_name="free fire"
            major.platform_id=1
            major.client_version="1.129.15"
            major.system_software="Android OS 9"
            major.system_hardware="Handheld"
            major.telecom_operator="Verizon"
            major.network_type="WIFI"
            major.screen_width=1920
            major.screen_height=1080
            major.screen_dpi="280"
            major.processor_details="ARM64"
            major.memory=3003
            major.gpu_renderer="Adreno"
            major.gpu_version="OpenGL"
            major.unique_device_id="Google|34a7dcdf"
            major.language="en"
            major.open_id=open_id
            major.open_id_type="4"
            major.device_type="Handheld"
            major.memory_available.version=55
            major.memory_available.hidden_value=81
            major.access_token=access_token
            major.platform_sdk_id=1
            major.login_by=3
            major.origin_platform_type=str(pt)
            major.primary_platform_type=str(pt)
            encrypted = encrypt_payload(major.SerializeToString())
            r2 = requests.post(
                LOGIN_URL,
                headers=LOGIN_HEADERS,
                data=encrypted,
                verify=False,
                timeout=10)
            if r2.status_code==200 and len(r2.content)>5:
                msg = MajorLoginRes_pb2.MajorLoginRes()
                msg.ParseFromString(r2.content)
                if msg.token:
                    jwt_token = msg.token
                    uid,name,region = decode_jwt(jwt_token)
                    return jwt_token,uid,name,region
        return None,None,None,None
    except Exception:
        return None,None,None,None

def request_clan(jwt_token, clan_id, region):
    server_url = get_server_url(region)
    msg = ReqCLan_pb2.MyMessage()
    msg.field_1 = int(clan_id)
    payload = encrypt_payload(msg.SerializeToString())
    headers = GAME_HEADERS.copy()
    headers["Authorization"] = f"Bearer {jwt_token}"
    url = f"{server_url}/RequestJoinClan"
    r = requests.post(url, headers=headers, data=payload, verify=False)
    return r.status_code, r.text

def quit_clan(jwt_token, clan_id, region):
    server_url = get_server_url(region)
    msg = QuitClanReq_pb2.QuitClanReq()
    msg.field_1 = int(clan_id)
    payload = encrypt_payload(msg.SerializeToString())
    headers = GAME_HEADERS.copy()
    headers["Authorization"] = f"Bearer {jwt_token}"
    url = f"{server_url}/QuitClan"
    r = requests.post(url, headers=headers, data=payload, verify=False)
    return r.status_code, r.text

def resolve_login(jwt_token=None, uid=None, password=None, access_token=None):
    if jwt_token:
        uid, name, region = decode_jwt(jwt_token)
        if uid:
            return jwt_token, uid, name, region, "JWT"
        else:
            return None, None, None, None, "Invalid JWT"
    if access_token:
        jwt_token, uid, name, region = access_token_to_jwt(access_token)
        if jwt_token:
            return jwt_token, uid, name, region, "ACCESS_TOKEN"
        else:
            return None, None, None, None, "Access token conversion failed"
    if uid and password:
        acc_token, open_id = guest_login(uid, password)
        if not acc_token:
            return None, None, None, None, "Guest login failed"
        jwt_token = perform_major_login(acc_token, open_id)
        if not jwt_token:
            return None, None, None, None, "Major login failed"
        uid, name, region = decode_jwt(jwt_token)
        return jwt_token, uid, name, region, "UID_PASS"
    return None, None, None, None, "No login credentials provided"

@app.route("/")
def home():
    html=f"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Free Fire Clan API</title>
<style>
body{{margin:0;padding:0;font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;background:#fff;color:#111}}
header{{text-align:center;padding:2rem}}
h1{{color:#ffcc00;margin-bottom:.2rem}}
p{{color:#555;margin-top:0}}
main{{max-width:800px;margin:auto;padding:2rem}}
section{{margin-bottom:2rem}}
h2{{border-bottom:1px solid #e0e0e0;padding-bottom:.5rem;margin-bottom:1rem}}
.card{{background:#fff;border:1px solid #e5e5e5;border-radius:8px;padding:.8rem 1rem;margin-bottom:1rem;display:grid;grid-template-columns:1fr auto;align-items:center}}
.card code{{color:#008000;font-family:monospace;word-break:break-all}}
button.copy-btn{{background:#ffcc00;border:none;padding:.35rem .7rem;border-radius:6px;cursor:pointer;font-weight:bold}}
button.copy-btn:hover{{background:#e6b800}}
.tooltip{{position:absolute;background:#222;color:#fff;padding:.3rem .6rem;border-radius:4px;font-size:.8rem;opacity:0;pointer-events:none;transition:opacity .2s}}
</style>
</head>
<body>

<header>
<h1>Free Fire Clan API v{OB}</h1>
<p>Developer: R O H I T | Telegram:
<a href="https://t.me/FFclient" style="color:#ffcc00">@FFclient</a></p>
</header>

<main>

<section>
<h2>JOIN Commands</h2>
{generate_card("/request_clan?clan_id=123&jwt=JWT")}
{generate_card("/request_clan?clan_id=123&uid=123&pass=PASS")}
{generate_card("/request_clan_access?clan_id=123&access_token=TOKEN")}
</section>

<section>
<h2>QUIT Commands</h2>
{generate_card("/quit_clan?clan_id=123&jwt=JWT")}
{generate_card("/quit_clan?clan_id=123&uid=123&pass=PASS")}
{generate_card("/quit_clan_access?clan_id=123&access_token=TOKEN")}
</section>

</main>

<div class="tooltip" id="tooltip">Copied!</div>

<script>
function copyText(t,b){{
 if(navigator.clipboard){{
  navigator.clipboard.writeText(t).catch(()=>fallbackCopy(t))
 }}else{{fallbackCopy(t)}}
 let e=document.getElementById('tooltip'),r=b.getBoundingClientRect()
 e.style.opacity=1
 e.style.left=r.left+'px'
 e.style.top=(r.top-30)+'px'
 setTimeout(()=>{{e.style.opacity=0}},900)
}}

function fallbackCopy(t){{
 let i=document.createElement("textarea")
 i.value=t
 document.body.appendChild(i)
 i.select()
 document.execCommand("copy")
 document.body.removeChild(i)
}}
</script>

</body>
</html>
"""
    return Response(html,mimetype="text/html")

def generate_card(endpoint):
    return f'''
<div class="card">
<code>{endpoint}</code>
<button class="copy-btn" onclick="copyText(`{endpoint}`,this)">Copy</button>
</div>
'''

def wants_html():return"text/html"in request.headers.get("Accept","")

def render_page(title,data,success):
    import json
    c="#22c55e"if success else"#ef4444";s="SUCCESS"if success else"FAILED";j=json.dumps(data,indent=2,ensure_ascii=False)
    html=f"""<!DOCTYPE html><html><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>{title}</title>
<style>
body{{margin:0;font-family:Segoe UI;background:#fff;color:#111}}header{{text-align:center;padding:2rem}}h1{{color:#ffcc00}}
main{{max-width:800px;margin:auto;padding:2rem}}.status{{font-weight:bold;color:{c};margin-bottom:1rem;font-size:18px}}
.card{{background:#fff;border:1px solid #e5e5e5;border-radius:8px;padding:1rem}}
pre{{background:#111;color:#0f0;padding:1rem;border-radius:6px;overflow:auto}}
button{{background:#ffcc00;border:0;padding:.4rem .8rem;border-radius:6px;font-weight:bold;cursor:pointer;margin-top:.6rem}}
.tooltip{{position:absolute;background:#222;color:#fff;padding:.3rem .6rem;border-radius:4px;font-size:.8rem;opacity:0;transition:.2s}}
</style></head>
<body>
<header><h1>Free Fire Clan API v{API_INFO["version"]}</h1>
<p>{API_INFO["developer"]} | <a href="{API_INFO["telegram"]}" style=color:#ffcc00>Telegram</a></p></header>

<main>
<div class=status>{s}</div>
<div class=card><pre id=json>{j}</pre><button onclick=copyJSON()>Copy Response</button></div>
</main>

<div class=tooltip id=tip>Copied!</div>

<script>
function copyJSON(){{
let t=document.getElementById("json").innerText
if(navigator.clipboard)navigator.clipboard.writeText(t).catch(()=>f(t));else f(t)
let e=document.getElementById("tip");e.style.opacity=1;setTimeout(()=>{{e.style.opacity=0}},900)
}}
function f(t){{let i=document.createElement("textarea");i.value=t;document.body.appendChild(i);i.select();document.execCommand("copy");document.body.removeChild(i)}}
</script>

</body></html>"""
    return Response(html,mimetype="text/html")

@app.route("/request_clan")
def api_request():
    clan_id=request.args.get("clan_id")
    jwt_token=request.args.get("jwt")
    uid=request.args.get("uid")
    password=request.args.get("pass")
    if not clan_id:
        data={"success":False,"error":"clan_id required"}
        return render_page("Join Clan",data,False) if wants_html() else jsonify(data)
    final_jwt,uid,name,region,method=resolve_login(jwt_token=jwt_token,uid=uid,password=password)
    if not final_jwt:
        data={"success":False,"error":method}
        return render_page("Join Clan",data,False) if wants_html() else jsonify(data)
    player_info=get_player_info(uid,final_jwt,region)
    player=extract_player_info(player_info) if player_info else None
    if player:
        name=player["nickname"]
    code,text=request_clan(final_jwt,clan_id,region)
    success=(code==200)
    data={
        "success":success,
        "action":"Join Clan",
        "clan_id":clan_id,
        "uid":uid,
        "name":name,
        "region":region,
        "login_method":method,
        "developer":API_INFO["developer"],
        "telegram":API_INFO["telegram"],
        "api_version":API_INFO["version"],
        "reason":text}
    return render_page("Join Clan",data,success) if wants_html() else jsonify(data)

@app.route("/quit_clan")
def api_quit():
    clan_id=request.args.get("clan_id")
    jwt_token=request.args.get("jwt")
    uid=request.args.get("uid")
    password=request.args.get("pass")
    if not clan_id:
        data={"success":False,"error":"clan_id required"}
        return render_page("Quit Clan",data,False) if wants_html() else jsonify(data)
    final_jwt,uid,name,region,method=resolve_login(jwt_token=jwt_token,uid=uid,password=password)
    if not final_jwt:
        data={"success":False,"error":method}
        return render_page("Quit Clan",data,False) if wants_html() else jsonify(data)
    player_info=get_player_info(uid,final_jwt,region)
    player=extract_player_info(player_info) if player_info else None
    if player:
        name=player["nickname"]
    code,text=quit_clan(final_jwt,clan_id,region)
    success=(code==200)
    data={
        "success":success,
        "action":"Quit Clan",
        "clan_id":clan_id,
        "uid":uid,
        "name":name,
        "region":region,
        "login_method":method,
        "developer":API_INFO["developer"],
        "telegram":API_INFO["telegram"],
        "api_version":API_INFO["version"],
        "reason":text}
    return render_page("Quit Clan",data,success) if wants_html() else jsonify(data)

@app.route("/request_clan_access")
def api_request_access():
    clan_id=request.args.get("clan_id")
    access_token=request.args.get("access_token")
    if not clan_id:
        data={"success":False,"error":"clan_id required"}
        return render_page("Join Clan (Access)",data,False) if wants_html() else jsonify(data)
    if not access_token:
        data={"success":False,"error":"access_token required"}
        return render_page("Join Clan (Access)",data,False) if wants_html() else jsonify(data)
    final_jwt,uid,name,region,method=resolve_login(access_token=access_token)
    if not final_jwt:
        data={"success":False,"error":method}
        return render_page("Join Clan (Access)",data,False) if wants_html() else jsonify(data)
    player_info=get_player_info(uid,final_jwt,region)
    player=extract_player_info(player_info) if player_info else None
    if player:
        name=player["nickname"]
    code,text=request_clan(final_jwt,clan_id,region)
    success=(code==200)
    data={
        "success":success,
        "action":"Join Clan",
        "clan_id":clan_id,
        "uid":uid,
        "name":name,
        "region":region,
        "login_method":method,
        "developer":API_INFO["developer"],
        "telegram":API_INFO["telegram"],
        "api_version":API_INFO["version"],
        "reason":text}
    return render_page("Join Clan (Access)",data,success) if wants_html() else jsonify(data)

@app.route("/quit_clan_access")
def api_quit_access():
    clan_id=request.args.get("clan_id")
    access_token=request.args.get("access_token")
    if not clan_id:
        data={"success":False,"error":"clan_id required"}
        return render_page("Quit Clan (Access)",data,False) if wants_html() else jsonify(data)
    if not access_token:
        data={"success":False,"error":"access_token required"}
        return render_page("Quit Clan (Access)",data,False) if wants_html() else jsonify(data)
    final_jwt,uid,name,region,method=resolve_login(access_token=access_token)
    if not final_jwt:
        data={"success":False,"error":method}
        return render_page("Quit Clan (Access)",data,False) if wants_html() else jsonify(data)
    player_info=get_player_info(uid,final_jwt,region)
    player=extract_player_info(player_info) if player_info else None
    if player:
        name=player["nickname"]
    code,text=quit_clan(final_jwt,clan_id,region)
    success=(code==200)
    data={
        "success":success,
        "action":"Quit Clan",
        "clan_id":clan_id,
        "uid":uid,
        "name":name,
        "region":region,
        "login_method":method,
        "developer":API_INFO["developer"],
        "telegram":API_INFO["telegram"],
        "api_version":API_INFO["version"],
        "reason":text}
    return render_page("Quit Clan (Access)",data,success) if wants_html() else jsonify(data)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)