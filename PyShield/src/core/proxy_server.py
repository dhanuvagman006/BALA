"""
HTTP Proxy Server for PyShield
Intercepts browser traffic and applies firewall rules
"""

from __future__ import annotations

import asyncio
import aiohttp
import socket
import threading
import time
from typing import Optional, Dict, Any
from urllib.parse import urlparse
from dataclasses import dataclass

from core.config import PyShieldConfig
from core.logging_system import LoggerFactory


@dataclass
class ProxyRequest:
    method: str
    url: str
    headers: Dict[str, str]
    client_ip: str
    timestamp: float
    blocked: bool = False
    block_reason: str = ""


class HTTPProxyServer:
    """HTTP proxy server that intercepts browser traffic"""
    
    def __init__(self, cfg: PyShieldConfig, pyshield_instance):
        self.cfg = cfg
        self.pyshield = pyshield_instance
        self.logger = LoggerFactory.get_logger("pyshield.proxy")
        self.proxy_port = getattr(cfg.dashboard, 'proxy_port', 8888)
        self.server = None
        self.running = False
        self.request_history = []
        self.max_history = 1000
        
    async def handle_request(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Handle incoming proxy requests"""
        client_addr = writer.get_extra_info('peername')
        client_ip = client_addr[0] if client_addr else 'unknown'
        
        try:
            # Read the HTTP request
            request_line = await reader.readline()
            if not request_line:
                return
                
            request_line = request_line.decode('utf-8').strip()
            if not request_line:
                return
                
            # Parse request line
            parts = request_line.split(' ')
            if len(parts) < 3:
                return
                
            method, url, version = parts[0], parts[1], parts[2]
            
            # Read headers
            headers = {}
            while True:
                header_line = await reader.readline()
                if not header_line or header_line == b'\r\n':
                    break
                header_line = header_line.decode('utf-8').strip()
                if ':' in header_line:
                    key, value = header_line.split(':', 1)
                    headers[key.strip()] = value.strip()
            
            # Create proxy request record
            proxy_req = ProxyRequest(
                method=method,
                url=url,
                headers=headers,
                client_ip=client_ip,
                timestamp=time.time()
            )
            
            # Apply firewall rules
            blocked, reason = await self.check_firewall_rules(proxy_req)
            proxy_req.blocked = blocked
            proxy_req.block_reason = reason
            
            # Add to history
            self.request_history.append(proxy_req)
            if len(self.request_history) > self.max_history:
                self.request_history.pop(0)
            
            if blocked:
                # Send blocked response
                await self.send_blocked_response(writer, reason)
                self.logger.warning(f"Blocked request to {url} from {client_ip}: {reason}")
            else:
                # Forward the request
                await self.forward_request(reader, writer, method, url, headers)
                self.logger.info(f"Forwarded request to {url} from {client_ip}")
                
        except Exception as e:
            self.logger.error(f"Error handling proxy request from {client_ip}: {e}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass
    
    async def check_firewall_rules(self, request: ProxyRequest) -> tuple[bool, str]:
        """Check if request should be blocked by firewall rules"""
        
        # Check DDoS protection
        if hasattr(self.pyshield, 'ddos_protector') and self.pyshield.ddos_protector:
            ddos = self.pyshield.ddos_protector
            if ddos.cfg.enabled:
                if ddos.is_banned(request.client_ip):
                    return True, "IP banned due to DDoS protection"
                
                exceeded_count = ddos.register_request(request.client_ip)
                if exceeded_count:
                    return True, f"Rate limit exceeded: {exceeded_count} requests"
        
        # Check URL blocking
        if hasattr(self.pyshield, 'url_blocker') and self.pyshield.url_blocker:
            url_blocker = self.pyshield.url_blocker
            if url_blocker.cfg.enabled and url_blocker.is_malicious(request.url):
                self.pyshield.on_url_block(request.url)
                return True, "Malicious URL blocked"
        
        # Check geo-blocking
        if hasattr(self.pyshield, 'geo_blocker') and self.pyshield.geo_blocker:
            geo_blocker = self.pyshield.geo_blocker
            if geo_blocker.cfg.enabled:
                is_blocked = geo_blocker.is_blocked(request.client_ip)
                if is_blocked:
                    return True, "Geographic location blocked"
        
        return False, ""
    
    async def send_blocked_response(self, writer: asyncio.StreamWriter, reason: str) -> None:
        """Send a blocked response to client"""
        response = f"""HTTP/1.1 403 Forbidden\r
Content-Type: text/html\r
Content-Length: {len(reason) + 100}\r
Connection: close\r
\r
<html><body><h1>403 Forbidden</h1><p>PyShield Firewall: {reason}</p></body></html>"""
        
        writer.write(response.encode())
        await writer.drain()
    
    async def forward_request(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, 
                            method: str, url: str, headers: Dict[str, str]) -> None:
        """Forward request to destination server"""
        try:
            # Parse URL
            if url.startswith('http://') or url.startswith('https://'):
                parsed = urlparse(url)
                host = parsed.hostname
                port = parsed.port or (443 if parsed.scheme == 'https' else 80)
                path = parsed.path + ('?' + parsed.query if parsed.query else '')
            else:
                # Handle CONNECT method for HTTPS
                if method == 'CONNECT':
                    host, port = url.split(':')
                    port = int(port)
                else:
                    host = headers.get('Host', '').split(':')[0]
                    port = 80
                    path = url
            
            if method == 'CONNECT':
                # Handle HTTPS tunnel
                await self.handle_connect(reader, writer, host, int(port))
            else:
                # Handle HTTP request
                await self.handle_http(reader, writer, method, host, port, path, headers)
                
        except Exception as e:
            self.logger.error(f"Error forwarding request: {e}")
            await self.send_error_response(writer, "502 Bad Gateway")
    
    async def handle_connect(self, client_reader: asyncio.StreamReader, 
                           client_writer: asyncio.StreamWriter, host: str, port: int) -> None:
        """Handle HTTPS CONNECT tunnel"""
        try:
            # Connect to destination
            dest_reader, dest_writer = await asyncio.open_connection(host, port)
            
            # Send connection established
            response = "HTTP/1.1 200 Connection Established\r\n\r\n"
            client_writer.write(response.encode())
            await client_writer.drain()
            
            # Start bidirectional data transfer
            await asyncio.gather(
                self.transfer_data(client_reader, dest_writer),
                self.transfer_data(dest_reader, client_writer),
                return_exceptions=True
            )
            
        except Exception as e:
            self.logger.error(f"Error in CONNECT tunnel to {host}:{port}: {e}")
        finally:
            try:
                if 'dest_writer' in locals():
                    dest_writer.close()
                    await dest_writer.wait_closed()
            except:
                pass
    
    async def handle_http(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter,
                         method: str, host: str, port: int, path: str, headers: Dict[str, str]) -> None:
        """Handle HTTP request"""
        try:
            # Connect to destination
            dest_reader, dest_writer = await asyncio.open_connection(host, port)
            
            # Forward request
            request_line = f"{method} {path} HTTP/1.1\r\n"
            dest_writer.write(request_line.encode())
            
            # Forward headers
            for key, value in headers.items():
                if key.lower() not in ['proxy-connection']:
                    header_line = f"{key}: {value}\r\n"
                    dest_writer.write(header_line.encode())
            
            dest_writer.write(b"\r\n")
            
            # Forward body if present
            if method in ['POST', 'PUT', 'PATCH']:
                content_length = headers.get('Content-Length', '0')
                if content_length.isdigit() and int(content_length) > 0:
                    body = await client_reader.read(int(content_length))
                    dest_writer.write(body)
            
            await dest_writer.drain()
            
            # Forward response back to client
            while True:
                data = await dest_reader.read(8192)
                if not data:
                    break
                client_writer.write(data)
                await client_writer.drain()
                
        except Exception as e:
            self.logger.error(f"Error in HTTP request to {host}:{port}: {e}")
            await self.send_error_response(client_writer, "502 Bad Gateway")
        finally:
            try:
                if 'dest_writer' in locals():
                    dest_writer.close()
                    await dest_writer.wait_closed()
            except:
                pass
    
    async def transfer_data(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Transfer data between reader and writer"""
        try:
            while True:
                data = await reader.read(8192)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        except:
            pass
    
    async def send_error_response(self, writer: asyncio.StreamWriter, error: str) -> None:
        """Send error response"""
        response = f"HTTP/1.1 {error}\r\nConnection: close\r\n\r\n"
        writer.write(response.encode())
        await writer.drain()
    
    async def start(self) -> None:
        """Start the proxy server"""
        if self.running:
            return
            
        try:
            self.server = await asyncio.start_server(
                self.handle_request,
                '127.0.0.1',
                self.proxy_port
            )
            self.running = True
            self.logger.info(f"HTTP Proxy server started on 127.0.0.1:{self.proxy_port}")
            self.logger.info(f"Configure your browser to use proxy: 127.0.0.1:{self.proxy_port}")
            
        except Exception as e:
            self.logger.error(f"Failed to start proxy server: {e}")
            raise
    
    async def stop(self) -> None:
        """Stop the proxy server"""
        if not self.running or not self.server:
            return
            
        self.running = False
        self.server.close()
        await self.server.wait_closed()
        self.logger.info("HTTP Proxy server stopped")
    
    def get_request_history(self, limit: int = 100) -> list[Dict[str, Any]]:
        """Get recent proxy requests for dashboard"""
        recent_requests = self.request_history[-limit:] if self.request_history else []
        return [
            {
                "method": req.method,
                "url": req.url,
                "client_ip": req.client_ip,
                "timestamp": req.timestamp,
                "blocked": req.blocked,
                "block_reason": req.block_reason,
                "domain": urlparse(req.url).netloc if req.url.startswith(('http://', 'https://')) else req.url
            }
            for req in recent_requests
        ]