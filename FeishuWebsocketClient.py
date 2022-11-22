import asyncio
import logging

import websockets

max_retry = 10
reconnect_time = 0

loop = asyncio.new_event_loop()
asyncio.set_event_loop(loop)

async def async_processing():
    async with websockets.connect("your web sockect ip") as websocket:
        await websocket.send('{"app_id":"xxx","app_secret":"xxx","verification_token":"xxx","encrypt_key":"xxx","is_lark":false, "ws_url":"xxxx"}')
        while True:
            try:
                message = await websocket.recv()
                print(message)

            except websockets.ConnectionClosed:
                print('ConnectionClosed')
                break

            await asyncio.sleep(1)

print("test")
loop.run_until_complete(asyncio.wait([
   async_processing()
]))

