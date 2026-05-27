"""
ADB Proxy Server — transparent TCP proxy with ADB protocol interception.

Protocol:
  Client→Server: XXXX<command>  (XXXX = 4 ASCII hex digits = command length)
  Server→Client: OKAY<hex4><data>  or  FAIL<hex4><error>
  
  Shell v2 output protocol (after transport select + shell command OKAY):
    [1 byte ID][4 bytes LE uint32 length][data bytes]
    ID=1: stdout, ID=2: stderr, ID=3: exit code
    
  Stdout data comes in multiple chunks, each wrapped as [01][len4][data].
"""

import asyncio
import logging
import re
import struct
from typing import Optional, Callable, Awaitable

log = logging.getLogger(__name__)

InterceptCallback = Callable[['AdbIntercept'], Awaitable[None]]

PNG_HEADER = b'\x89PNG\r\n\x1a\n'
PNG_IEND = b'IEND\xaeB`\x82'

CMD_FRAME_RE = re.compile(rb'^([0-9a-fA-F]{4})(.+)', re.DOTALL)
SHELL_V2_RE = re.compile(rb'shell,v2,[^,]*,raw:(.*)', re.DOTALL)
SHELL_V1_RE = re.compile(rb'shell:(.*)')


class AdbIntercept:
    def __init__(self, kind: str, request: str = "", data: bytes = b"",
                 device_serial: str = ""):
        self.kind = kind
        self.request = request
        self.data = data
        self.device_serial = device_serial

    def __repr__(self):
        return (f"AdbIntercept(kind={self.kind}, request={self.request!r}, "
                f"data_len={len(self.data)}, device={self.device_serial!r})")


class StreamScanner:
    """
    Scans bidirectional ADB stream for commands and screenshots.
    
    C→S: parses XXXX<cmd> frames, detects shell commands.
    S→C: when awaiting screenshot, extracts stdout data from shell_v2 frames,
         accumulates clean PNG bytes, searches for header+IEND.
    """

    def __init__(self, device_serial: str = ""):
        self.device_serial = device_serial
        self._c2s_buf = b""
        self._s2c_buf = b""
        self._awaiting_screenshot = False
        self._clean_stdout = b""   # Extracted stdout data (no framing)
        self._current_command = ""
        self._shell_active = False

    def feed_c2s(self, data: bytes) -> list[AdbIntercept]:
        self._c2s_buf += data
        intercepts = []

        while True:
            m = CMD_FRAME_RE.match(self._c2s_buf)
            if not m:
                if len(self._c2s_buf) < 4:
                    break
                maybe_len_str = self._c2s_buf[:4]
                try:
                    cmd_len = int(maybe_len_str, 16)
                    if len(self._c2s_buf) >= 4 + cmd_len:
                        cmd_bytes = self._c2s_buf[4:4 + cmd_len]
                        self._c2s_buf = self._c2s_buf[4 + cmd_len:]
                        intercepts += self._parse_command(cmd_bytes)
                        continue
                except (ValueError, IndexError):
                    pass
                break

            cmd_len = int(m.group(1), 16)
            if len(self._c2s_buf) < 4 + cmd_len:
                break

            cmd_bytes = self._c2s_buf[4:4 + cmd_len]
            self._c2s_buf = self._c2s_buf[4 + cmd_len:]
            intercepts += self._parse_command(cmd_bytes)

        return intercepts

    def _parse_command(self, cmd_bytes: bytes) -> list[AdbIntercept]:
        intercepts = []

        m = SHELL_V2_RE.match(cmd_bytes)
        if m:
            raw_cmd = m.group(1).decode('utf-8', errors='replace').strip()
            self._current_command = raw_cmd
            self._shell_active = True
            if raw_cmd.startswith('screencap'):
                self._awaiting_screenshot = True
                self._clean_stdout = b""
            intercepts.append(AdbIntercept(
                "command", request=raw_cmd, device_serial=self.device_serial
            ))
            return intercepts

        m = SHELL_V1_RE.match(cmd_bytes)
        if m:
            cmd = m.group(1).decode('utf-8', errors='replace').strip()
            self._current_command = cmd
            self._shell_active = True
            if cmd.startswith('screencap'):
                self._awaiting_screenshot = True
                self._clean_stdout = b""
            intercepts.append(AdbIntercept(
                "command", request=cmd, device_serial=self.device_serial
            ))
            return intercepts

        return intercepts

    def feed_s2c(self, data: bytes) -> list[AdbIntercept]:
        """Process server→client data. Parses shell_v2 frames for screenshot capture."""
        self._s2c_buf += data
        intercepts = []

        if self._awaiting_screenshot:
            # Parse shell_v2 frames from the buffer
            while True:
                frame = self._try_parse_shell_v2_frame()
                if frame is None:
                    break

                frame_id, frame_data = frame
                if frame_id == 1:  # stdout
                    self._clean_stdout += frame_data
                    # Search for complete PNG in accumulated stdout
                    png = self._extract_png(self._clean_stdout)
                    if png:
                        intercepts.append(AdbIntercept(
                            "screenshot",
                            request=self._current_command,
                            data=png,
                            device_serial=self.device_serial
                        ))
                        self._awaiting_screenshot = False
                        self._clean_stdout = b""
                        self._shell_active = False
                        break

                elif frame_id == 3:  # exit code
                    self._awaiting_screenshot = False
                    self._clean_stdout = b""
                    self._shell_active = False
                    break

        # Cleanup buffer
        if len(self._s2c_buf) > 2 * 1024 * 1024:  # 2MB
            self._s2c_buf = self._s2c_buf[-512 * 1024:]

        return intercepts

    def _try_parse_shell_v2_frame(self) -> Optional[tuple[int, bytes]]:
        """
        Try to parse next protocol element from the S→C buffer.
        Returns (id, data) for shell_v2 frames, or None.
        
        Handles:
          - "OKAY" + 8 binary bytes (transport response): skips 12 bytes
          - "OKAY" alone (4 bytes, shell command ack): skips 4 bytes  
          - [ID][4-byte LE len][data]: shell_v2 frame
        """
        if len(self._s2c_buf) < 4:
            return None

        # Handle OKAY responses
        if self._s2c_buf[:4] == b'OKAY':
            # Check if next 4 bytes look like ASCII hex (server response protocol)
            # Transport OKAY: OKAY + 8 binary bytes (not hex-encoded)
            # Shell OKAY: just OKAY (4 bytes), shell_v2 frames follow
            # Server response: OKAY + 4 hex digits + data
            
            if len(self._s2c_buf) >= 8:
                next4 = self._s2c_buf[4:8]
                # Try to interpret as hex length
                try:
                    hex_str = next4.decode('ascii')
                    data_len = int(hex_str, 16)
                    skip = 8 + data_len
                    if len(self._s2c_buf) >= skip:
                        self._s2c_buf = self._s2c_buf[skip:]
                        return self._try_parse_shell_v2_frame()
                except (ValueError, UnicodeDecodeError):
                    pass
                
                # Try as transport response: OKAY + 8 binary bytes
                # The 8 bytes after OKAY are the transport connection response
                skip = 12  # OKAY(4) + binary_response(8)
                if len(self._s2c_buf) >= skip:
                    self._s2c_buf = self._s2c_buf[skip:]
                    return self._try_parse_shell_v2_frame()
            
            # Plain OKAY (4 bytes) — shell command ack
            self._s2c_buf = self._s2c_buf[4:]
            return self._try_parse_shell_v2_frame()

        # Shell_v2 frame: [1 byte ID][4 bytes LE uint32 length][data]
        if len(self._s2c_buf) < 5:
            return None

        frame_id = self._s2c_buf[0]
        if frame_id not in (1, 2, 3):
            # Unknown byte — skip and retry
            self._s2c_buf = self._s2c_buf[1:]
            return self._try_parse_shell_v2_frame()

        data_len = struct.unpack('<I', self._s2c_buf[1:5])[0]
        
        # Sanity check
        if data_len > 10 * 1024 * 1024:  # > 10MB is suspicious
            self._s2c_buf = self._s2c_buf[1:]  # Skip bad ID byte
            return self._try_parse_shell_v2_frame()

        total_frame_len = 5 + data_len
        if len(self._s2c_buf) < total_frame_len:
            return None

        frame_data = self._s2c_buf[5:total_frame_len]
        self._s2c_buf = self._s2c_buf[total_frame_len:]

        return (frame_id, frame_data)

    def _extract_png(self, data: bytes) -> Optional[bytes]:
        """Search for a complete PNG in the data buffer."""
        idx = data.find(PNG_HEADER)
        if idx < 0:
            return None
        iend_idx = data.find(PNG_IEND, idx)
        if iend_idx < 0:
            return None
        return data[idx:iend_idx + 8]

    def reset(self):
        self._awaiting_screenshot = False
        self._clean_stdout = b""
        self._current_command = ""
        self._c2s_buf = b""
        self._s2c_buf = b""
        self._shell_active = False


class AdbProxyServer:
    """Async transparent ADB proxy with protocol-aware interception."""

    def __init__(
        self,
        listen_host: str = "127.0.0.1",
        listen_port: int = 5038,
        target_host: str = "127.0.0.1",
        target_port: int = 5037,
        on_intercept: Optional[InterceptCallback] = None,
        intercept_screenshots: bool = True,
        intercept_commands: bool = True,
        exclude_commands: Optional[list[str]] = None,
        max_screenshot_bytes: int = 4 * 1024 * 1024,
        shared_state: Optional[dict] = None,
    ):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.target_host = target_host
        self.target_port = target_port
        self.on_intercept = on_intercept
        self.intercept_screenshots = intercept_screenshots
        self.intercept_commands = intercept_commands
        self.exclude_commands = set(c.lower() for c in (exclude_commands or []))
        self.max_screenshot_bytes = max_screenshot_bytes
        self.shared_state = shared_state or {}
        self._server: Optional[asyncio.AbstractServer] = None

    async def start(self):
        self._server = await asyncio.start_server(
            self._handle_client,
            self.listen_host,
            self.listen_port,
        )
        addr = self._server.sockets[0].getsockname()
        log.info(f"ADB proxy listening on {addr[0]}:{addr[1]}")
        log.info(f"Forwarding -> {self.target_host}:{self.target_port}")

    async def stop(self):
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            log.info("ADB proxy stopped")

    async def _handle_client(self, client_reader, client_writer):
        client_addr = client_writer.get_extra_info('peername')
        log.debug(f"Client connected: {client_addr}")

        try:
            server_reader, server_writer = await asyncio.open_connection(
                self.target_host, self.target_port
            )
        except Exception as e:
            log.error(f"Failed to connect to ADB server: {e}")
            client_writer.close()
            return

        scanner = StreamScanner()

        async def forward(src, dst, direction: str):
            try:
                while True:
                    data = await src.read(65536)
                    if not data:
                        break

                    if direction == "c2s" and self.intercept_commands:
                        for ic in scanner.feed_c2s(data):
                            if not self._is_excluded(ic.request):
                                await self._notify(ic)
                    elif direction == "s2c" and self.intercept_screenshots:
                        for ic in scanner.feed_s2c(data):
                            await self._notify(ic)

                    dst.write(data)
                    await dst.drain()
            except Exception as e:
                log.debug(f"{direction} closed: {e}")
            finally:
                dst.close()

        task_c2s = asyncio.create_task(forward(client_reader, server_writer, "c2s"))
        task_s2c = asyncio.create_task(forward(server_reader, client_writer, "s2c"))

        try:
            await asyncio.gather(task_c2s, task_s2c)
        except asyncio.CancelledError:
            pass
        finally:
            for t in [task_c2s, task_s2c]:
                if not t.done():
                    t.cancel()
            log.debug(f"Client disconnected: {client_addr}")

    async def _notify(self, intercept: AdbIntercept):
        if not self.on_intercept:
            return
        try:
            await self.on_intercept(intercept)
        except Exception as e:
            log.error(f"Intercept callback error: {e}")

    def _is_excluded(self, request: str) -> bool:
        req_lower = request.lower()
        for excluded in self.exclude_commands:
            if req_lower.startswith(excluded):
                return True
        return False
