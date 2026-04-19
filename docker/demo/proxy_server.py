#!/usr/bin/env python3
import argparse
import asyncio
import base64
import binascii
import ssl


async def relay(reader, writer):
    try:
        while True:
            chunk = await reader.read(65536)
            if not chunk:
                break
            writer.write(chunk)
            await writer.drain()
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


def parse_headers(lines):
    headers = {}
    for raw in lines:
        if ":" not in raw:
            continue
        name, value = raw.split(":", 1)
        headers[name.strip().lower()] = value.strip()
    return headers


def check_basic_auth(header_value, username, password):
    if not header_value or not header_value.startswith("Basic "):
        return False
    try:
        decoded = base64.b64decode(header_value[6:], validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        return False
    return decoded == f"{username}:{password}"


async def handle_client(reader, writer, username, password):
    try:
        request_line = await reader.readline()
        if not request_line:
            return

        request_line = request_line.decode("utf-8", errors="replace").strip()
        header_lines = []
        while True:
            line = await reader.readline()
            if not line or line in (b"\r\n", b"\n"):
                break
            header_lines.append(line.decode("utf-8", errors="replace").strip())

        headers = parse_headers(header_lines)

        if username is not None:
            if not check_basic_auth(headers.get("proxy-authorization"), username, password):
                writer.write(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                    b"Proxy-Authenticate: Basic realm=\"childflow-demo\"\r\n"
                    b"Content-Length: 0\r\n\r\n"
                )
                await writer.drain()
                return

        parts = request_line.split()
        if len(parts) != 3 or parts[0].upper() != "CONNECT":
            writer.write(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
            await writer.drain()
            return

        target_host, target_port_text = parts[1].rsplit(":", 1)
        target_host = target_host.strip("[]")
        target_port = int(target_port_text)

        upstream_reader, upstream_writer = await asyncio.open_connection(target_host, target_port)
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()

        await asyncio.gather(
            relay(reader, upstream_writer),
            relay(upstream_reader, writer),
        )
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--tls-cert")
    parser.add_argument("--tls-key")
    parser.add_argument("--user")
    parser.add_argument("--password")
    args = parser.parse_args()

    if (args.user is None) != (args.password is None):
        raise SystemExit("--user and --password must be provided together")

    ssl_context = None
    if args.tls_cert and args.tls_key:
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(args.tls_cert, args.tls_key)

    server = await asyncio.start_server(
        lambda reader, writer: handle_client(reader, writer, args.user, args.password),
        host=args.host,
        port=args.port,
        ssl=ssl_context,
    )
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
