"""
ADB Proxy Server — transparent TCP proxy with ADB protocol interception.

Protocol:
  Client→Server: XXXX<command>  (XXXX = 4 ASCII hex digits = command length)
  Server→Client: OKAY<hex4><data>  or  FAIL<hex4><error>
  
  Shell v2 output protocol (after transport select + shell command OKAY):
    [1 byte ID][4 bytes LE uint32 length][data bytes]
    ID=1: stdout, ID=2: stderr, ID=3: exit code
    
  Stdout data comes in multiple chunks, each wrapped as [01][len4][data].

Sync protocol (after transport + sync: command):
    [4 bytes ID][4 bytes LE uint32 length][length bytes of data]
    SEND/SEN2: data = "path,mode"     — file send request
    DATA:       data = file chunk     — file data block
    DONE:       data = 4-byte mtime   — file transfer complete
    QUIT:       data = empty          — end sync session
"""

import asyncio
import logging
import re
import struct
import time
from dataclasses import dataclass, field
from typing import Optional, Callable, Awaitable

log = logging.getLogger(__name__)

InterceptCallback = Callable[['AdbIntercept'], Awaitable[None]]

PNG_HEADER = b'\x89PNG\r\n\x1a\n'
PNG_IEND = b'IEND\xaeB`\x82'

CMD_FRAME_RE = re.compile(rb'^([0-9a-fA-F]{4})(.+)', re.DOTALL)
SHELL_V2_RE = re.compile(rb'shell,v2,[^,]*,raw:(.*)', re.DOTALL)
SHELL_V1_RE = re.compile(rb'shell:(.*)')
SYNC_CMD_RE = re.compile(rb'^sync:')

# Sync protocol packet IDs (LE uint32 on wire, appear as ASCII)
SYNC_IDS = {b'SEND', b'SEN2', b'DATA', b'DONE', b'QUIT',
            b'OKAY', b'FAIL', b'STAT', b'LIST', b'RECV',
            b'REC2', b'LIS2', b'STA2'}


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


@dataclass
class SyncFileCapture:
    """Tracks an in-progress file transfer via sync protocol."""
    path: str
    mode: int
    data: bytearray = field(default_factory=bytearray)
    complete: bool = False

    def add_chunk(self, chunk: bytes):
        self.data.extend(chunk)


class StreamScanner:
    """
    Scans bidirectional ADB stream for commands, screenshots, APK transfers,
    and logcat output.

    C→S: parses XXXX<cmd> frames, detects shell/sync commands.
         When in sync mode, parses SEND/DATA/DONE for APK capture.
    S→C: when awaiting screenshot, extracts PNG from shell_v2 stdout frames.
         When awaiting logcat, accumulates stdout text.
    """

    def __init__(self,
                 device_serial: str = "",
                 capture_apks: bool = True,
                 max_apk_bytes: int = 100 * 1024 * 1024,
                 capture_logcat: bool = False,
                 logcat_lines_per_message: int = 50,
                 logcat_max_total_lines: int = 500):
        self.device_serial = device_serial
        self.capture_apks = capture_apks
        self.max_apk_bytes = max_apk_bytes
        self.capture_logcat = capture_logcat
        self.logcat_lines_per_message = logcat_lines_per_message
        self.logcat_max_total_lines = logcat_max_total_lines

        self._c2s_buf = b""
        self._s2c_buf = b""
        self._awaiting_screenshot = False
        self._awaiting_logcat = False
        self._clean_stdout = b""
        self._current_command = ""
        self._shell_active = False

        # Sync protocol state
        self._sync_mode = False
        self._sync_capture: Optional[SyncFileCapture] = None

        # Logcat state
        self._logcat_lines_sent = 0
        self._logcat_text_buf = ""

    def feed_c2s(self, data: bytes) -> list[AdbIntercept]:
        self._c2s_buf += data
        intercepts = []

        # If in sync mode, parse sync packets before ADB frames
        if self._sync_mode:
            intercepts += self._parse_sync_packets()

        # Parse regular ADB frames
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

        # Check for sync command (enters sync protocol mode)
        if SYNC_CMD_RE.match(cmd_bytes):
            self._sync_mode = True
            log.debug("Entering sync mode")
            intercepts.append(AdbIntercept(
                "command", request="sync:", device_serial=self.device_serial
            ))
            return intercepts

        m = SHELL_V2_RE.match(cmd_bytes)
        if m:
            raw_cmd = m.group(1).decode('utf-8', errors='replace').strip()
            self._current_command = raw_cmd
            self._shell_active = True
            if raw_cmd.startswith('screencap'):
                self._awaiting_screenshot = True
                self._clean_stdout = b""
            elif self.capture_logcat and raw_cmd.startswith('logcat'):
                self._awaiting_logcat = True
                self._clean_stdout = b""
                self._logcat_lines_sent = 0
                self._logcat_text_buf = ""
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
            elif self.capture_logcat and cmd.startswith('logcat'):
                self._awaiting_logcat = True
                self._clean_stdout = b""
                self._logcat_lines_sent = 0
                self._logcat_text_buf = ""
            intercepts.append(AdbIntercept(
                "command", request=cmd, device_serial=self.device_serial
            ))
            return intercepts

        return intercepts

    # ── Sync protocol parsing ──────────────────────────────────────────

    def _parse_sync_packets(self) -> list[AdbIntercept]:
        """Parse sync protocol packets from c2s buffer.
        Modifies self._c2s_buf in place, removing consumed bytes."""
        intercepts = []
        buf = self._c2s_buf

        while len(buf) >= 8:
            sync_id = buf[:4]
            if sync_id not in SYNC_IDS:
                break

            data_len = struct.unpack('<I', buf[4:8])[0]

            # DONE and QUIT are fixed 8-byte packets (no trailing data)
            if sync_id in (b'DONE', b'QUIT'):
                total_len = 8
                data = b''
                if sync_id == b'QUIT':
                    self._sync_mode = False
                    log.debug("Sync mode ended (QUIT)")
                    self._finalize_sync_capture(intercepts)
                elif sync_id == b'DONE':
                    # data_len is the mtime for DONE
                    self._finalize_sync_capture(intercepts)

                buf = buf[total_len:]
                continue

            # For SEND/DATA/OKAY/FAIL: data_len is the actual data length
            # Sanity check
            if data_len > 200 * 1024 * 1024:  # > 200 MB is suspicious
                log.warning("Sync packet with huge length %d, skipping byte", data_len)
                buf = buf[1:]
                continue

            total_len = 8 + data_len
            if len(buf) < total_len:
                break

            data = buf[8:total_len]

            if sync_id in (b'SEND', b'SEN2'):
                # Parse "path,mode" format
                path_mode = data.decode('utf-8', errors='replace')
                # Mode is last comma-separated field
                if ',' in path_mode:
                    *path_parts, mode_str = path_mode.rsplit(',', 1)
                    path = ','.join(path_parts)
                else:
                    path = path_mode
                    mode_str = '0644'

                try:
                    mode = int(mode_str)
                except ValueError:
                    mode = 0o644

                # Check if we should capture this file
                if self.capture_apks and path.lower().endswith('.apk'):
                    self._sync_capture = SyncFileCapture(path=path, mode=mode)
                    log.info("Capturing APK: %s", path)
                else:
                    self._sync_capture = None

            elif sync_id == b'DATA':
                if self._sync_capture:
                    if len(self._sync_capture.data) + len(data) > self.max_apk_bytes:
                        log.warning("APK exceeds max size %d, dropping capture",
                                    self.max_apk_bytes)
                        self._sync_capture = None
                    else:
                        self._sync_capture.add_chunk(data)

            # OKAY/FAIL/STAT/LIST/RECV — not used for capture, just skip

            buf = buf[total_len:]

        self._c2s_buf = buf
        return intercepts

    def _finalize_sync_capture(self, intercepts: list[AdbIntercept]):
        """Complete any pending APK capture and emit an intercept."""
        if self._sync_capture and len(self._sync_capture.data) > 0:
            log.info("APK captured: %s (%d bytes)",
                     self._sync_capture.path, len(self._sync_capture.data))
            intercepts.append(AdbIntercept(
                kind="apk_file",
                request=self._sync_capture.path,
                data=bytes(self._sync_capture.data),
                device_serial=self.device_serial,
            ))
        self._sync_capture = None

    # ── Server→Client processing ───────────────────────────────────────

    def feed_s2c(self, data: bytes) -> list[AdbIntercept]:
        """Process server→client data. Parses shell_v2 frames for screenshot
        and logcat capture."""
        self._s2c_buf += data
        intercepts = []

        # Process shell_v2 frames for screenshot/logcat
        while True:
            frame = self._try_parse_shell_v2_frame()
            if frame is None:
                break

            frame_id, frame_data = frame
            if frame_id == 1:  # stdout
                self._clean_stdout += frame_data

                if self._awaiting_screenshot:
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

                elif self._awaiting_logcat:
                    intercepts += self._process_logcat_chunk(frame_data)

            elif frame_id == 3:  # exit code
                if self._awaiting_screenshot:
                    self._awaiting_screenshot = False
                    self._clean_stdout = b""
                    self._shell_active = False
                elif self._awaiting_logcat:
                    # Flush remaining logcat text
                    remaining = self._extract_logcat_lines()
                    if remaining:
                        intercepts.append(AdbIntercept(
                            "logcat_output",
                            request=self._current_command,
                            data=remaining.encode('utf-8'),
                            device_serial=self.device_serial,
                        ))
                    self._awaiting_logcat = False
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

    # ── Logcat output capture ──────────────────────────────────────────

    def _process_logcat_chunk(self, frame_data: bytes) -> list[AdbIntercept]:
        """Process a chunk of logcat stdout data. Returns intercepts for
        completed line batches."""
        intercepts = []

        # Decode new data and append to buffer
        text = frame_data.decode('utf-8', errors='replace')
        self._logcat_text_buf += text

        # Extract complete lines and send in batches
        while True:
            lines, incomplete = self._extract_logcat_batch()
            if not lines:
                break

            self._logcat_lines_sent += len(lines)
            if self._logcat_lines_sent > self.logcat_max_total_lines:
                self._awaiting_logcat = False
                lines.append(f"... (truncated at {self.logcat_max_total_lines} lines)")
                self._clean_stdout = b""
                self._shell_active = False

            batch_text = '\n'.join(lines)
            intercepts.append(AdbIntercept(
                "logcat_output",
                request=self._current_command,
                data=batch_text.encode('utf-8'),
                device_serial=self.device_serial,
            ))

        return intercepts

    def _extract_logcat_batch(self) -> tuple[list[str], str]:
        """Extract up to logcat_lines_per_message complete lines from buffer.
        Returns (lines, remaining_incomplete_string)."""
        if '\n' not in self._logcat_text_buf:
            return [], self._logcat_text_buf

        all_lines = self._logcat_text_buf.split('\n')
        # Last element is incomplete (no trailing newline)
        incomplete = all_lines[-1]
        complete_lines = all_lines[:-1]

        if len(complete_lines) >= self.logcat_lines_per_message:
            batch = complete_lines[:self.logcat_lines_per_message]
            remaining = '\n'.join(complete_lines[self.logcat_lines_per_message:] + [incomplete])
            self._logcat_text_buf = remaining if remaining else incomplete
            return batch, incomplete
        else:
            # Not enough lines yet, keep buffering
            return [], self._logcat_text_buf

    def _extract_logcat_lines(self) -> str:
        """Return all buffered logcat text (for final flush on exit)."""
        text = self._logcat_text_buf.strip()
        self._logcat_text_buf = ""
        return text

    # ── Reset ──────────────────────────────────────────────────────────

    def reset(self):
        self._awaiting_screenshot = False
        self._awaiting_logcat = False
        self._clean_stdout = b""
        self._current_command = ""
        self._c2s_buf = b""
        self._s2c_buf = b""
        self._shell_active = False
        self._sync_mode = False
        self._sync_capture = None
        self._logcat_lines_sent = 0
        self._logcat_text_buf = ""


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
        capture_apks: bool = True,
        max_apk_bytes: int = 100 * 1024 * 1024,
        capture_logcat: bool = False,
        logcat_lines_per_message: int = 50,
        logcat_max_total_lines: int = 500,
        hold_seconds: float = 0.0,
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
        self.capture_apks = capture_apks
        self.max_apk_bytes = max_apk_bytes
        self.capture_logcat = capture_logcat
        self.logcat_lines_per_message = logcat_lines_per_message
        self.logcat_max_total_lines = logcat_max_total_lines
        self.hold_seconds = hold_seconds
        self.shared_state = shared_state or {}
        self._server: Optional[asyncio.AbstractServer] = None

        # Session gate: serializes access so that a rapid sequence of commands
        # (same session) runs without delay, while a second session must wait
        # for the first to finish + hold_seconds.
        self._session_gate = asyncio.Semaphore(1)
        self._active_count = 0
        self._last_activity = 0.0
        self._hold_task: Optional[asyncio.Task] = None

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

        # Wait for session gate (serializes concurrent sessions)
        await self._acquire_session()

        try:
            server_reader, server_writer = await asyncio.open_connection(
                self.target_host, self.target_port
            )
        except Exception as e:
            log.error(f"Failed to connect to ADB server: {e}")
            client_writer.close()
            await self._release_session()
            return

        scanner = StreamScanner(
            capture_apks=self.capture_apks,
            max_apk_bytes=self.max_apk_bytes,
            capture_logcat=self.capture_logcat,
            logcat_lines_per_message=self.logcat_lines_per_message,
            logcat_max_total_lines=self.logcat_max_total_lines,
        )

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
                    elif direction == "s2c" and (self.intercept_screenshots or self.capture_logcat):
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
            await self._release_session()

    async def _acquire_session(self):
        """Acquire a slot in the current session, waiting if a different
        session is active and hold_seconds hasn't elapsed yet."""
        now = time.monotonic()
        # Same session only when idle AND within hold window.
        # If a connection is already active, a new arrival might be a
        # different session — it must wait for the semaphore.
        in_session = (self._active_count == 0 and
                      now - self._last_activity < self.hold_seconds)

        if not in_session:
            # New session — wait for gate (blocks if another session holds it)
            await self._session_gate.acquire()
            # Cancel any pending hold release from a previous session
            if self._hold_task:
                self._hold_task.cancel()
                self._hold_task = None

        self._active_count += 1
        self._last_activity = now

    async def _release_session(self):
        """Release a session slot.  When all slots are free the hold timer
        starts; after hold_seconds the gate opens for the next session."""
        self._active_count -= 1
        if self._active_count == 0:
            self._last_activity = time.monotonic()
            if self.hold_seconds > 0:
                self._hold_task = asyncio.create_task(self._release_gate())
            else:
                try:
                    self._session_gate.release()
                except ValueError:
                    pass  # already at max

    async def _release_gate(self):
        """Hold timer callback — opens the gate after hold_seconds."""
        await asyncio.sleep(self.hold_seconds)
        if self._active_count == 0:
            self._hold_task = None
            try:
                self._session_gate.release()
            except ValueError:
                pass

    async def _notify(self, intercept: AdbIntercept):
        if not self.on_intercept:
            return
        try:
            await self.on_intercept(intercept)
        except Exception as e:
            log.error(f"Intercept callback error: {e}")

    def _is_excluded(self, request: str) -> bool:
        req_lower = request.lower()
        # Never exclude logcat when capture is explicitly enabled
        if self.capture_logcat and req_lower.startswith('logcat'):
            return False
        for excluded in self.exclude_commands:
            if req_lower.startswith(excluded):
                return True
        return False
