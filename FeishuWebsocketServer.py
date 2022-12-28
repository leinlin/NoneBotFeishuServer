import base64
import hashlib
import json
import os
import threading
from typing import Optional
from queue import Queue

import requests
from Cryptodome.Cipher import AES
from flask import Flask, request, jsonify
import logging
import websockets
import asyncio
from pydantic import BaseModel

app = Flask(__name__)


class AESCipher(object):
    def __init__(self, key):
        self.block_size = AES.block_size
        self.key = hashlib.sha256(AESCipher.str_to_bytes(key)).digest()

    @staticmethod
    def str_to_bytes(data):
        u_type = type(b"".decode("utf8"))
        if isinstance(data, u_type):
            return data.encode("utf8")
        return data

    @staticmethod
    def _unpad(s):
        return s[: -ord(s[len(s) - 1:])]

    def decrypt(self, enc):
        iv = enc[: AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:]))

    def decrypt_string(self, enc):
        enc = base64.b64decode(enc)
        return self.decrypt(enc).decode("utf8")


class BotConfig(BaseModel):
    """
    飞书适配器机器人配置类

    :配置项:

      - ``app_id``: 飞书开放平台后台“凭证与基础信息”处给出的 App ID
      - ``app_secret``: 飞书开放平台后台“凭证与基础信息”处给出的 App Secret
      - ``encrypt_key``: 飞书开放平台后台“事件订阅”处设置的 Encrypt Key
      - ``verification_token``: 飞书开放平台后台“事件订阅”处设置的 Verification Token
      - ``is_lark``: 是否使用 Lark（飞书海外版），默认为 false

    """

    app_id: str
    app_secret: str
    encrypt_key: Optional[str] = None
    verification_token: str
    is_lark: bool = False
    ws_url: str = ""


class Obj(dict):
    def __init__(self, d):
        for a, b in d.items():
            if isinstance(b, (list, tuple)):
                setattr(self, a, [Obj(x) if isinstance(x, dict) else x for x in b])
            else:
                setattr(self, a, Obj(b) if isinstance(b, dict) else b)


def dict_2_obj(d: dict):
    return Obj(d)

loop = asyncio.new_event_loop()
asyncio.set_event_loop(loop)

class WSServer:

    def __init__(self):
        self.http_websocket = None
        self.cmdQueue = Queue()
        self.feishu_bots: dict[str, Obj] = {}
        self.http_websockets: dict = {}

    async def send(self, url_rule, msg):
        if url_rule in self.http_websockets:
            return await self.http_websockets[url_rule].send(msg)

    async def handle(self, websocket, path):
        while True:
            try:
                recv_msg = await websocket.recv()
                print("i received %s" % recv_msg)
                json_dict: dict = json.loads(recv_msg)
                app_id = json_dict.get("app_id")
                url_rule = f'/{app_id}'
                self.http_websockets[url_rule] = websocket
                if not self.feishu_bots.__contains__(url_rule):
                    print(f"create new rule:{url_rule}")
                    self.feishu_bots[url_rule] = dict_2_obj(json_dict)
                    decorator = app.route(url_rule, methods=['POST'], endpoint=app_id)
                    def h_decorator():
                        def h():
                            return self.main()

                        return h

                    decorator(h_decorator())
            except websockets.ConnectionClosed:
                self.http_websockets[url_rule] = None
                print('ConnectionClosed')
                break
            await asyncio.sleep(1)

    @staticmethod
    def _decrypt_data(encrypt_key, data):
        encrypt_data = data.get("encrypt")
        if encrypt_key == "" and encrypt_data is None:
            # data haven't been encrypted
            return data
        if encrypt_key == "":
            raise Exception("ENCRYPT_KEY is necessary")
        cipher = AESCipher(encrypt_key)
        encodeData = cipher.decrypt_string(encrypt_data)
        return encodeData

    def main(self):
        rule = request.url_rule.rule
        bot_config = self.feishu_bots[rule]

        dict_data = json.loads(request.data)
        json_data = WSServer._decrypt_data(bot_config.encrypt_key, dict_data)
        data = json.loads(json_data)

        challenge = data.get("challenge")
        if challenge:
            return jsonify({"challenge": challenge}), 200

        schema = data.get("schema")
        if not schema:
            return "Missing `schema` in POST body, only accept event of version 2.0", 400

        headers = data.get("header")
        if headers:
            token = headers.get("token")
        else:
            app.logger.warning("Missing `header` in POST body")
            return "Missing `header` in POST body", 400

        if not token:
            app.logger.warning("Missing `verification token` in POST body")
            return "Missing `verification token` in POST body", 400
        else:
            if token != bot_config.verification_token:
                app.logger.warning("Verification token check failed")
                return "Verification token check failed", 403


        loop.run_until_complete(self.send(rule, json_data))
        return "OK", 200

    def run(self, port):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        ser = websockets.serve(self.handle, "0.0.0.0", port, ping_interval=600, ping_timeout=600, close_timeout=600)
        loop.run_until_complete(ser)
        loop.run_forever()


def doLoop():
    ws = WSServer()
    ws.run("8765")


t = threading.Thread(target=doLoop)
t.start()

if __name__ == '__main__':
    app.run("0.0.0.0", 8081)
