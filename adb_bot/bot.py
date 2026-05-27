"""
Matrix Bot — sends ADB intercepts to a Matrix room with E2EE support.

Uses matrix-nio for full Matrix CS API + E2EE (olm/megolm).
"""

import asyncio
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Optional

from nio import (
    AsyncClient,
    AsyncClientConfig,
    LoginResponse,
    RoomSendResponse,
    UploadResponse,
    SyncError,
    SyncResponse,
    MatrixRoom,
    RoomMessageText,
    RoomEncryptedMedia,
    crypto,
)

from .proxy import AdbIntercept  # noqa: F401 — used by main

log = logging.getLogger(__name__)


class MatrixBot:
    """Matrix client that sends ADB intercept notifications to a room."""

    def __init__(
        self,
        homeserver: str,
        user_id: str,
        room_id: str,
        access_token: str = "",
        password: str = "",
        device_name: str = "adb-mitm-bot",
        store_path: str = "./e2ee_store",
        command_prefix: str = "📱 ADB",
        screenshot_prefix: str = "📸 Screenshot",
        error_prefix: str = "⚠️ ADB Error",
        show_timestamps: bool = True,
        show_device: bool = True,
    ):
        self.homeserver = homeserver
        self.user_id = user_id
        self.room_id = room_id
        self.access_token = access_token
        self.password = password
        self.device_name = device_name
        self.store_path = Path(store_path)
        self.command_prefix = command_prefix
        self.screenshot_prefix = screenshot_prefix
        self.error_prefix = error_prefix
        self.show_timestamps = show_timestamps
        self.show_device = show_device

        self._client: Optional[AsyncClient] = None
        self._sync_task: Optional[asyncio.Task] = None
        self._running = False
        self._intercept_queue: asyncio.Queue = asyncio.Queue()

    async def start(self) -> bool:
        """Login and start syncing."""
        # Ensure store path exists
        self.store_path.mkdir(parents=True, exist_ok=True)

        # Configure client
        config = AsyncClientConfig(
            store_sync_tokens=True,
            encryption_enabled=True,
        )

        self._client = AsyncClient(
            homeserver=self.homeserver,
            user=self.user_id,
            device_id=self.device_name,
            store_path=str(self.store_path),
            config=config,
        )

        # Login
        if self.access_token:
            self._client.access_token = self.access_token
            self._client.user_id = self.user_id
            self._client.device_id = self.device_name

            # Restore E2EE session
            try:
                self._client.load_store()
                log.info("Loaded existing E2EE session from store")
            except Exception as e:
                log.warning(f"Could not load E2EE store: {e}")

        elif self.password:
            resp = await self._client.login(password=self.password, device_name=self.device_name)
            if isinstance(resp, LoginResponse):
                self.access_token = resp.access_token
                log.info(f"Logged in as {resp.user_id}")
            else:
                log.error(f"Login failed: {resp}")
                return False
        else:
            log.error("No access_token or password configured")
            return False

        # Initial sync (non-blocking filter to be quick)
        log.info("Performing initial sync...")
        sync_resp = await self._client.sync(timeout=3000)
        if isinstance(sync_resp, SyncError):
            log.error(f"Initial sync failed: {sync_resp}")

        # Join room if not already in
        await self._ensure_room_joined()

        # Start sync loop in background
        self._running = True
        self._sync_task = asyncio.create_task(self._sync_loop())
        # Start intercept handler
        asyncio.create_task(self._handle_intercepts())

        log.info(f"Matrix bot started. Sending to room: {self.room_id}")
        return True

    async def stop(self):
        """Stop the bot."""
        self._running = False
        if self._sync_task:
            self._sync_task.cancel()
            try:
                await self._sync_task
            except asyncio.CancelledError:
                pass
        if self._client:
            await self._client.close()
        log.info("Matrix bot stopped")

    async def _sync_loop(self):
        """Background sync loop."""
        since = self._client.next_batch
        while self._running:
            try:
                sync_resp = await self._client.sync(timeout=30000, since=since)
                if isinstance(sync_resp, SyncResponse):
                    since = sync_resp.next_batch
                    # Handle E2EE key sharing
                    if sync_resp.to_device_events:
                        await self._client._handle_to_device_events(sync_resp.to_device_events)
                    if sync_resp.device_lists:
                        await self._client._handle_device_list_changes(sync_resp.device_lists)
                elif isinstance(sync_resp, SyncError):
                    log.error(f"Sync error: {sync_resp}")
                    await asyncio.sleep(5)
            except asyncio.CancelledError:
                break
            except Exception as e:
                log.error(f"Sync exception: {e}")
                await asyncio.sleep(5)

    async def _ensure_room_joined(self):
        """Check if we're in the room, join if not."""
        if not self.room_id:
            return

        # Resolve alias to room ID if needed
        room_id = self.room_id
        if room_id.startswith('#'):
            resp = await self._client.room_resolve_alias(room_id)
            if resp.room_id:
                room_id = resp.room_id
                log.info(f"Resolved alias {self.room_id} → {room_id}")
                self.room_id = room_id

        # Check if we're in this room
        if room_id in self._client.rooms:
            log.info(f"Already in room {room_id}")
            return

        log.info(f"Joining room {room_id}...")
        resp = await self._client.join(room_id)
        if resp.transport_response and resp.transport_response.ok:
            log.info(f"Joined room {room_id}")
        else:
            log.warning(f"Could not join room {room_id}: {resp}")

    async def send_intercept(self, intercept: AdbIntercept):
        """Queue an intercept for sending to Matrix."""
        await self._intercept_queue.put(intercept)

    async def _handle_intercepts(self):
        """Process intercept queue and send to Matrix."""
        while self._running or not self._intercept_queue.empty():
            try:
                intercept = await asyncio.wait_for(
                    self._intercept_queue.get(), timeout=1.0
                )
                await self._process_intercept(intercept)
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                log.error(f"Error processing intercept: {e}")

    async def _process_intercept(self, ic: AdbIntercept):
        """Process a single intercept and send to Matrix."""
        if not self._client:
            return

        kind = ic.kind

        if kind == "command":
            await self._send_command(ic)
        elif kind == "screenshot":
            await self._send_screenshot(ic)
        elif kind == "apk_file":
            await self._send_apk(ic)
        elif kind == "logcat_output":
            await self._send_logcat(ic)
        elif kind == "output":
            await self._send_output(ic)
        elif kind == "error":
            await self._send_error(ic)

    async def _send_command(self, ic: AdbIntercept):
        """Send a command notification."""
        prefix = self.command_prefix
        if self.show_device and ic.device_serial:
            prefix += f" [{ic.device_serial}]"

        body = f"{prefix} — Command: `{ic.request}`"
        await self._send_text(body)

    async def _send_screenshot(self, ic: AdbIntercept):
        """Upload and send a screenshot."""
        if not ic.data:
            return

        prefix = self.screenshot_prefix
        if self.show_device and ic.device_serial:
            prefix += f" [{ic.device_serial}]"

        timestamp = ""
        if self.show_timestamps:
            timestamp = datetime.now().strftime(" %Y-%m-%d %H:%M:%S")

        # Upload to Matrix media repository
        resp, _ = await self._client.upload(
            ic.data,
            content_type="image/png",
            filename=f"screenshot_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png",
        )

        if isinstance(resp, UploadResponse):
            mxc_url = resp.content_uri
            log.info(f"Screenshot uploaded: {mxc_url}")

            body = f"{prefix}{timestamp}"
            await self._send_image(mxc_url, body, ic.data)
        else:
            log.error(f"Screenshot upload failed: {resp}")
            body = f"{prefix}{timestamp} — upload failed: {resp}"
            await self._send_text(body)

    async def _send_output(self, ic: AdbIntercept):
        """Send command output."""
        prefix = "📤 Output"
        if self.show_device and ic.device_serial:
            prefix += f" [{ic.device_serial}]"

        text = ic.data.decode('utf-8', errors='replace').strip()
        if not text:
            return

        # Truncate long output
        if len(text) > 2000:
            text = text[:1997] + "..."

        body = f"{prefix}\n```\n{text}\n```"
        await self._send_text(body)

    async def _send_error(self, ic: AdbIntercept):
        """Send an error notification."""
        prefix = self.error_prefix
        if self.show_device and ic.device_serial:
            prefix += f" [{ic.device_serial}]"

        error_text = ic.data.decode('utf-8', errors='replace').strip()
        body = f"{prefix} — `{ic.request}` failed: {error_text}"
        await self._send_text(body)

    async def _send_apk(self, ic: AdbIntercept):
        """Upload and send a captured APK file."""
        if not ic.data:
            return

        # Extract filename from path
        filename = ic.request.split('/')[-1] if '/' in ic.request else ic.request
        if not filename:
            filename = "captured.apk"

        prefix = "📦 APK"
        if self.show_device and ic.device_serial:
            prefix += f" [{ic.device_serial}]"

        if self.show_timestamps:
            timestamp = datetime.now().strftime(" %Y-%m-%d %H:%M:%S")
        else:
            timestamp = ""

        # Upload to Matrix media repository
        resp, _ = await self._client.upload(
            ic.data,
            content_type="application/vnd.android.package-archive",
            filename=filename,
        )

        if isinstance(resp, UploadResponse):
            mxc_url = resp.content_uri
            log.info("APK uploaded: %s (%d bytes) -> %s", filename, len(ic.data), mxc_url)

            import json
            try:
                resp = await self._client.room_send(
                    room_id=self.room_id,
                    message_type="m.room.message",
                    content={
                        "msgtype": "m.file",
                        "body": f"{prefix}{timestamp} — {filename}",
                        "url": mxc_url,
                        "filename": filename,
                        "info": {
                            "mimetype": "application/vnd.android.package-archive",
                            "size": len(ic.data),
                        },
                    },
                )
                if isinstance(resp, RoomSendResponse):
                    log.info("Sent APK to room: %s", filename)
                else:
                    log.error("Send APK failed: %s", resp)
            except Exception as e:
                log.error("Send APK error: %s", e)
        else:
            log.error("APK upload failed: %s", resp)
            body = f"{prefix}{timestamp} — upload failed for {filename}: {resp}"
            await self._send_text(body)

    async def _send_logcat(self, ic: AdbIntercept):
        """Send a chunk of logcat output."""
        prefix = "📋 Logcat"
        if self.show_device and ic.device_serial:
            prefix += f" [{ic.device_serial}]"

        text = ic.data.decode('utf-8', errors='replace').strip()
        if not text:
            return

        # Truncate per-message
        if len(text) > 3000:
            text = text[:2997] + "..."

        body = f"{prefix}\n```\n{text}\n```"
        await self._send_text(body)

    async def _send_text(self, body: str):
        """Send a text message to the room."""
        if not self._client or not self.room_id:
            return

        try:
            resp = await self._client.room_send(
                room_id=self.room_id,
                message_type="m.room.message",
                content={
                    "msgtype": "m.text",
                    "body": body,
                    "format": "org.matrix.custom.html",
                    "formatted_body": _text_to_html(body),
                },
            )
            if isinstance(resp, RoomSendResponse):
                log.debug(f"Sent text: {body[:100]}...")
            else:
                log.error(f"Send text failed: {resp}")
        except Exception as e:
            log.error(f"Send text error: {e}")

    async def _send_image(self, mxc_url: str, body: str, data: bytes):
        """Send an image to the room."""
        if not self._client or not self.room_id:
            return

        import json
        w, h = _get_png_dimensions(data)

        try:
            resp = await self._client.room_send(
                room_id=self.room_id,
                message_type="m.room.message",
                content={
                    "msgtype": "m.image",
                    "body": body,
                    "url": mxc_url,
                    "info": {
                        "mimetype": "image/png",
                        "size": len(data),
                        "w": w,
                        "h": h,
                    },
                },
            )
            if isinstance(resp, RoomSendResponse):
                log.info(f"Sent image to room: {body}")
            else:
                log.error(f"Send image failed: {resp}")
        except Exception as e:
            log.error(f"Send image error: {e}")


def _text_to_html(text: str) -> str:
    """Convert basic markdown-ish text to Matrix HTML."""
    import re
    html = text
    # Inline code
    html = re.sub(r'`([^`]+)`', r'<code>\1</code>', html)
    # Code blocks
    html = re.sub(r'```\n([\s\S]*?)```', r'<pre><code>\1</code></pre>', html)
    return html


def _get_png_dimensions(data: bytes) -> tuple[int, int]:
    """Get width/height from PNG data."""
    if len(data) < 24 or data[:8] != b'\x89PNG\r\n\x1a\n':
        return 0, 0
    import struct
    # IHDR starts at byte 16 (8 header + 4 length + 4 'IHDR')
    w, h = struct.unpack('>II', data[16:24])
    return w, h
