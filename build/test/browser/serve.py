"""Serve a mirrored LuCI page with a stub RPC backend.

Lets headless Chrome render /tmp/hpx/push/mirror/page.html the way the router
would, so the page's JavaScript can be observed working (or not).
"""
import json, sys, os, mimetypes
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = sys.argv[1]
PORT = int(sys.argv[2])
ACTION = sys.argv[3] if len(sys.argv) > 3 else None

mimetypes.add_type('text/javascript', '.js')
mimetypes.add_type('text/css', '.css')


def rpc_reply(msg):
    method = msg.get('method') if isinstance(msg, dict) else None
    result = {}
    if method == 'file.list':
        result = {'entries': []}
    return {'jsonrpc': '2.0', 'id': msg.get('id', 1) if isinstance(msg, dict) else 1,
            'result': result}


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype='application/json'):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        n = int(self.headers.get('Content-Length') or 0)
        raw = self.rfile.read(n) if n else b''
        if self.path.endswith('/action'):
            if ACTION:
                with open(ACTION) as f:
                    return self._send(200, f.read())
            return self._send(200, json.dumps({'results': {}}))
        try:
            payload = json.loads(raw or b'{}')
        except Exception:
            payload = {}
        if isinstance(payload, list):
            return self._send(200, json.dumps([rpc_reply(m) for m in payload]))
        return self._send(200, json.dumps(rpc_reply(payload)))

    def do_GET(self):
        path = self.path.split('?')[0]
        if path.startswith('/ubus'):
            return self._send(200, json.dumps({'results': {}}))
        if path.endswith('/action'):
            if ACTION:
                with open(ACTION) as f:
                    return self._send(200, f.read())
            return self._send(200, json.dumps({'results': {}}))
        if path == '/':
            path = '/page.html'
        fp = os.path.normpath(os.path.join(ROOT, path.lstrip('/')))
        if not fp.startswith(ROOT) or not os.path.isfile(fp):
            return self._send(404, 'not found', 'text/plain')
        ctype, _ = mimetypes.guess_type(fp)
        with open(fp, 'rb') as f:
            self._send(200, f.read(), ctype or 'application/octet-stream')


ThreadingHTTPServer(('127.0.0.1', PORT), H).serve_forever()
