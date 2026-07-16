"""
TCP Server：监听充电桩连接，创建 Session，管理全局 WebSocket 推送队列。
"""

import asyncio
import json
import logging
import os
from datetime import datetime
from asyncio import StreamReader, StreamWriter

from session import Session

logger = logging.getLogger(__name__)


class TcpServer:
    """充电桩接入 TCP 服务器"""

    def __init__(self, host: str = "0.0.0.0", port: int = 8888, ws_queue: asyncio.Queue | None = None):
        self.host = host
        self.port = port
        self.ws_queue = ws_queue or asyncio.Queue()
        self._server: asyncio.Server | None = None
        self._sessions: dict[str, Session] = {}
        self._counter = 0
        # 平台地址配置（可通过 API 动态修改）
        self.platform_host: str = "114.55.7.88"
        self.platform_port: int = 8776
        # E8→3B 转换开关
        self.e8_to_3b_enabled: bool = False
        # 帧日志文件
        self._log_path = os.path.join(os.path.dirname(__file__), "logs", f"frames_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl")
        os.makedirs(os.path.dirname(self._log_path), exist_ok=True)
        self._log_file = open(self._log_path, "a", encoding="utf-8")

    @property
    def sessions(self) -> dict[str, Session]:
        return self._sessions

    def log_frame(self, frame_data: dict):
        """将帧数据写入 JSON 日志文件"""
        try:
            self._log_file.write(json.dumps(frame_data, ensure_ascii=False) + "\n")
            self._log_file.flush()
        except Exception:
            pass

    async def start(self):
        """启动 TCP 监听"""
        self._server = await asyncio.start_server(
            self._handle_client, self.host, self.port
        )
        addr = self._server.sockets[0].getsockname()
        logger.info(f"TCP Server 已启动: {addr[0]}:{addr[1]}")
        print(f"[TCP] 监听充电桩接入: {addr[0]}:{addr[1]}")

    async def stop(self):
        """停止 TCP 服务，关闭所有会话"""
        if self._server:
            self._server.close()
            await self._server.wait_closed()

        # 关闭所有活跃会话（加超时）
        for session in list(self._sessions.values()):
            try:
                await asyncio.wait_for(session.stop(), timeout=3)
            except (asyncio.TimeoutError, Exception):
                pass
        self._sessions.clear()
        if self._log_file:
            self._log_file.close()
        logger.info("TCP Server 已停止")

    def set_e8_to_3b(self, enabled: bool):
        """动态更新所有运行中 Session 的 E8→3B 开关"""
        self.e8_to_3b_enabled = enabled
        for session in self._sessions.values():
            session.e8_to_3b = enabled
            logger.info(f"[{session.session_id}] E8→3B 开关已{'开启' if enabled else '关闭'}")

    async def _handle_client(self, reader: StreamReader, writer: StreamWriter):
        """处理新的充电桩 TCP 连接"""
        self._counter += 1
        session_id = f"pile-{self._counter:03d}"
        addr = writer.get_extra_info("peername")
        logger.info(f"[{session_id}] 新充电桩连接: {addr}")

        session = Session(
            pile_reader=reader,
            pile_writer=writer,
            ws_queue=self.ws_queue,
            session_id=session_id,
            platform_host=self.platform_host,
            platform_port=self.platform_port,
            on_frame=self.log_frame,
            e8_to_3b=self.e8_to_3b_enabled,
        )
        self._sessions[session_id] = session

        try:
            await session.start()
            # 等待所有后台任务结束（桩断开或平台断开）
            if session._tasks:
                done, _ = await asyncio.wait(session._tasks, return_when=asyncio.FIRST_COMPLETED)
                logger.info(f"[{session_id}] 后台任务结束，开始清理")
        except Exception as e:
            logger.error(f"[{session_id}] 会话异常: {e}", exc_info=True)
        finally:
            await session.stop()
            self._sessions.pop(session_id, None)
            logger.info(f"[{session_id}] 会话已移除")
