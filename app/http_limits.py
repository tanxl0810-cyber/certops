"""Bound request bytes before JSON parsing, including streamed request bodies."""
from starlette.responses import JSONResponse


class RequestBodyLimit:
    def __init__(self, app, max_bytes=400000):
        self.app, self.max_bytes = app, max_bytes

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            return await self.app(scope, receive, send)
        for name, value in scope.get('headers', []):
            if name.lower() != b'content-length':
                continue
            try:
                length = int(value)
                if length < 0:
                    raise ValueError()
            except ValueError:
                return await JSONResponse({'detail': '请求长度不正确'}, status_code=400)(scope, receive, send)
            if length > self.max_bytes:
                return await JSONResponse({'detail': '请求超过大小限制'}, status_code=413)(scope, receive, send)
        body = bytearray()
        while True:
            message = await receive()
            if message['type'] == 'http.disconnect':
                return
            chunk = message.get('body', b'')
            if len(body) + len(chunk) > self.max_bytes:
                return await JSONResponse({'detail': '请求超过大小限制'}, status_code=413)(scope, receive, send)
            body.extend(chunk)
            if not message.get('more_body', False):
                break
        delivered = False

        async def replay():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {'type': 'http.request', 'body': bytes(body), 'more_body': False}
            return await receive()

        return await self.app(scope, replay, send)
