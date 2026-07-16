"""
FastAPI 主入口：HTTP 静态页面 + WebSocket 报文推送 + TCP Server 生命周期管理。
"""

import asyncio
import json
import logging
import os
import signal
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from tcp_server import TcpServer

# ---- 日志配置 ----

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("server")

# ---- 配置 ----

TCP_LISTEN_HOST = os.getenv("TCP_LISTEN_HOST", "0.0.0.0")
TCP_LISTEN_PORT = int(os.getenv("TCP_LISTEN_PORT", "8888"))

# ---- 全局状态 ----

shutdown_event = asyncio.Event()
ws_queue: asyncio.Queue = asyncio.Queue()
ws_clients: set[WebSocket] = set()
tcp_server: TcpServer = TcpServer(
    host=TCP_LISTEN_HOST,
    port=TCP_LISTEN_PORT,
    ws_queue=ws_queue,
)


# ---- 生命周期 ----


@asynccontextmanager
async def lifespan(app: FastAPI):
    """应用生命周期：启动/停止 TCP Server"""
    await tcp_server.start()
    yield
    await tcp_server.stop()


app = FastAPI(lifespan=lifespan, title="ykc_websocket")

# ---- 静态文件 ----

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
os.makedirs(STATIC_DIR, exist_ok=True)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/")
async def index():
    """渲染前端页面"""
    index_path = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"message": "ykc_websocket 运行中", "status": "ok"}


# ---- WebSocket ----


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    """WebSocket 端点：接收 ws_queue 中的解析帧，推送给浏览器"""
    await ws.accept()
    ws_clients.add(ws)
    logger.info("WebSocket 客户端已连接")

    try:
        while not shutdown_event.is_set():
            try:
                frame = await asyncio.wait_for(ws_queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break
            try:
                await ws.send_json(frame.to_dict())
            except Exception:
                break
    except (WebSocketDisconnect, asyncio.CancelledError):
        pass
    except Exception:
        pass
    finally:
        ws_clients.discard(ws)


# ---- 状态查询 ----


@app.get("/api/status")
async def status():
    """查询当前服务状态"""
    sessions = tcp_server.sessions
    return {
        "sessions": len(sessions),
        "session_ids": list(sessions.keys()),
        "tcp_listen": f"{TCP_LISTEN_HOST}:{TCP_LISTEN_PORT}",
        "platform_host": tcp_server.platform_host,
        "platform_port": tcp_server.platform_port,
    }


# ---- 配置管理 ----

from pydantic import BaseModel


class PlatformConfig(BaseModel):
    platform_host: str
    platform_port: int


@app.get("/api/config")
async def get_config():
    """获取当前平台连接配置"""
    return {
        "platform_host": tcp_server.platform_host,
        "platform_port": tcp_server.platform_port,
    }


@app.post("/api/config")
async def update_config(cfg: PlatformConfig):
    """更新平台连接配置（仅影响新建立的 Session）"""
    tcp_server.platform_host = cfg.platform_host
    tcp_server.platform_port = cfg.platform_port
    logger.info(f"平台配置已更新: {cfg.platform_host}:{cfg.platform_port}")
    return {
        "ok": True,
        "platform_host": cfg.platform_host,
        "platform_port": cfg.platform_port,
    }


# ---- E8→3B 转换开关 ----

@app.get("/api/e8to3b")
async def get_e8to3b():
    """获取 E8→3B 转换状态"""
    return {"enabled": tcp_server.e8_to_3b_enabled}


@app.post("/api/e8to3b")
async def toggle_e8to3b(data: dict):
    """切换 E8→3B 转换"""
    tcp_server.set_e8_to_3b(data.get("enabled", False))
    logger.info(f"E8→3B 转换: {'开启' if tcp_server.e8_to_3b_enabled else '关闭'}")
    return {"enabled": tcp_server.e8_to_3b_enabled}


# ---- 入口 ----

if __name__ == "__main__":
    import uvicorn

    print("=" * 50)
    print("  ykc_websocket 报文监控中转工具")
    print("=" * 50)
    print(f"  TCP 监听:    {TCP_LISTEN_HOST}:{TCP_LISTEN_PORT}")
    print(f"  Web 界面:    http://localhost:8080")
    print(f"  WebSocket:   ws://localhost:8080/ws")
    print(f"  按 Ctrl+C 退出")
    print("=" * 50)

    def _handle_signal(sig, frame):
        print("\n正在关闭...")
        shutdown_event.set()

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    config = uvicorn.Config(app, host="0.0.0.0", port=8080, log_level="info")
    server = uvicorn.Server(config)
    server.run()
