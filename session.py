"""
Session 管理：充电桩连接与平台连接的生命周期绑定。
一个充电桩 TCP 连接 = 一个 Session，内部维护桩连接 + 平台连接。
"""

import asyncio
import logging
import struct
from asyncio import StreamReader, StreamWriter

from protocol import FrameParser, ParsedFrame, FRAME_HEADER, crc16

logger = logging.getLogger(__name__)

# 平台重连配置
PLATFORM_RECONNECT_MAX = 3
PLATFORM_RECONNECT_DELAY = 3  # 秒


def _read_bcd5(data: bytes, offset: int) -> int:
    """读取 5 字节 BCD 小端序整数"""
    return int.from_bytes(data[offset:offset+5], "little")


def _read_u32(data: bytes, offset: int) -> int:
    """读取 4 字节小端序"""
    return struct.unpack("<I", data[offset:offset+4])[0]


def convert_e8_to_3b(e8_raw: bytes) -> bytes | None:
    """
    从 0xE8 增强版交易记录生成标准 0x3B 交易记录帧（158字节消息体）。
    0xE8 消息体固定部分 197 字节，之后为 n*22 字节的时段明细。
    """
    try:
        body = e8_raw[6:6 + e8_raw[1] - 4]  # 去除帧头的消息体
        if len(body) < 197:
            logger.warning(f"E8→3B: body长度不足 (实际{len(body)}, 需要>=197)")
            return None

        # 0x3B 交易流水号直接复用 0xE8 的交易流水号
        trade_sn = body[0:16]

        # 构建 0x3B 消息体 (158 bytes, 31字段)
        # 字段映射: 0x3B字段 ← 0xE8字段(偏移)
        body_3b = bytearray()
        body_3b.extend(trade_sn)                  # 1: 交易流水号 ← E8[0:16]
        body_3b.extend(body[16:23])               # 2: 桩编号 ← E8[16:23]
        body_3b.extend(body[23:24])               # 3: 枪号 ← E8[23]
        body_3b.extend(body[24:31])               # 4: 开始时间 ← E8[24:31]
        body_3b.extend(body[31:38])               # 5: 结束时间 ← E8[31:38]

        # 辅助：合并电费+服务费
        def _sum4(a, b):
            return struct.pack("<I", (int.from_bytes(a, "little") + int.from_bytes(b, "little")) & 0xFFFFFFFF)

        # 6-9: 尖（无计损）
        body_3b.extend(_sum4(body[38:42], body[42:46]))   # 6: 尖单价 ← 尖电费费率+尖服务费费率
        body_3b.extend(body[46:50])                       # 7: 尖电量
        body_3b.extend(_sum4(body[54:58], body[58:62]))   # 8: 尖金额 ← 尖电费金额+尖服务费金额
        # 10-12: 峰（无计损）
        body_3b.extend(_sum4(body[62:66], body[66:70]))   # 9: 峰单价
        body_3b.extend(body[70:74])                       # 10: 峰电量
        body_3b.extend(_sum4(body[78:82], body[82:86]))   # 11: 峰金额
        # 13-15: 平（无计损）
        body_3b.extend(_sum4(body[86:90], body[90:94]))   # 12: 平单价
        body_3b.extend(body[94:98])                       # 13: 平电量
        body_3b.extend(_sum4(body[102:106], body[106:110])) # 14: 平金额
        # 16-18: 谷（无计损）
        body_3b.extend(_sum4(body[110:114], body[114:118])) # 15: 谷单价
        body_3b.extend(body[118:122])                     # 16: 谷电量
        body_3b.extend(_sum4(body[126:130], body[130:134])) # 17: 谷金额

        # 18-19: 电表值 9B
        body_3b.extend(b"\x00" * 4 + body[134:139])       # 18: 电表总起值
        body_3b.extend(b"\x00" * 4 + body[139:144])       # 19: 电表总止值
        body_3b.extend(body[144:148])                     # 20: 总电量
        body_3b.extend(body[156:160])                     # 21: 消费金额(总费用)
        body_3b.extend(body[160:177])                     # 22: VIN
        body_3b.extend(body[177:178])                     # 23: 交易标识
        body_3b.extend(body[178:185])                     # 24: 交易日期时间
        body_3b.extend(body[185:186])                     # 25: 停止原因
        body_3b.extend(body[186:194])                     # 26: 物理卡号

        # body_3b length auto-determined

        # 构建完整帧
        seq = 1
        data_domain = struct.pack("<H", seq) + b"\x00" + b"\x3B" + bytes(body_3b)
        crc = crc16(data_domain)
        raw = bytes([FRAME_HEADER, len(data_domain)]) + data_domain + struct.pack(">H", crc)
        logger.info(f"E8→3B: data_len={len(data_domain)}(0x{len(data_domain):02X}) CRC=0x{crc:04X} hex={raw.hex(' ').upper()}")
        return raw
    except Exception:
        return None


class Session:
    """一个充电桩会话"""

    def __init__(self, pile_reader: StreamReader, pile_writer: StreamWriter, ws_queue: asyncio.Queue, session_id: str, platform_host: str = "114.55.7.88", platform_port: int = 8776, on_frame: callable = None, e8_to_3b: bool = False):
        self.session_id = session_id
        self.pile_reader = pile_reader
        self.pile_writer = pile_writer
        self.platform_reader: StreamReader | None = None
        self.platform_writer: StreamWriter | None = None
        self.ws_queue = ws_queue  # asyncio.Queue → WebSocket 推送
        self.platform_host = platform_host
        self.platform_port = platform_port
        self.on_frame = on_frame  # 帧日志回调
        self.e8_to_3b = e8_to_3b  # 是否将 0xE8 转为 0x3B
        self.parser = FrameParser()
        self._pile_addr = pile_writer.get_extra_info("peername")
        self._running = False
        self._tasks: list[asyncio.Task] = []
        self._early_frames: list[bytes] = []  # 平台连接建立前的缓冲帧

    # ---- 生命周期 ----

    async def start(self):
        """启动会话：先接住桩的数据，再连平台"""
        self._running = True

        # 1. 先启动上行读循环，确保桩发来的数据立即被接收
        self._tasks.append(asyncio.create_task(self._read_pile_loop()))

        # 2. 再连接真实平台（此时桩的数据已在读循环中缓冲）
        connected = await self._connect_platform()
        if not connected:
            logger.warning(f"[{self.session_id}] 平台连接失败，仅监听上行报文")
        else:
            logger.info(f"[{self.session_id}] 平台连接成功")
            # 补发平台连接前的缓冲帧
            for raw in self._early_frames:
                try:
                    self.platform_writer.write(raw)
                except Exception:
                    pass
            if self._early_frames:
                await self.platform_writer.drain()
                logger.info(f"[{self.session_id}] 已补发 {len(self._early_frames)} 帧到平台")
            self._early_frames.clear()
            # 3. 启动下行读循环
            self._tasks.append(asyncio.create_task(self._read_platform_loop()))

    async def stop(self):
        """停止会话，关闭所有连接"""
        if not self._running:
            return
        self._running = False
        for task in self._tasks:
            task.cancel()
        self._tasks.clear()

        # 关闭桩连接（不等待）
        try:
            self.pile_writer.close()
        except Exception:
            pass

        # 关闭平台连接（不等待）
        if self.platform_writer:
            try:
                self.platform_writer.close()
            except Exception:
                pass

        logger.info(f"[{self.session_id}] 会话已关闭")

    # ---- 平台连接 ----

    async def _connect_platform(self) -> bool:
        """建立到真实平台的 TCP 连接，支持重试"""
        for attempt in range(1, PLATFORM_RECONNECT_MAX + 1):
            try:
                self.platform_reader, self.platform_writer = await asyncio.wait_for(
                    asyncio.open_connection(self.platform_host, self.platform_port),
                    timeout=10,
                )
                return True
            except Exception as e:
                logger.warning(f"[{self.session_id}] 平台连接失败 (尝试 {attempt}/{PLATFORM_RECONNECT_MAX}): {e}")
                if attempt < PLATFORM_RECONNECT_MAX:
                    await asyncio.sleep(PLATFORM_RECONNECT_DELAY)
        return False

    # ---- 上行读循环：充电桩 → 中转 ----

    async def _read_pile_loop(self):
        """读取充电桩发送的 TCP 数据，解析帧并透传至平台"""
        logger.info(f"[{self.session_id}] 上行读循环启动 (桩: {self._pile_addr})")
        try:
            while self._running:
                logger.debug(f"[{self.session_id}] 等待桩数据...")
                data = await self.pile_reader.read(4096)
                logger.info(f"[{self.session_id}] read返回: {'空(连接关闭)' if not data else f'{len(data)} bytes'}")
                if not data:
                    logger.info(f"[{self.session_id}] 充电桩连接断开")
                    break

                # 0. 原始数据日志（前64字节）
                preview = data[:64].hex(" ").upper()
                logger.info(f"[{self.session_id}] 收到原始数据 {len(data)} bytes: {preview}{'...' if len(data) > 64 else ''}")

                # A. 解析帧
                frames = self.parser.feed(data)
                for frame in frames:
                    frame.session_id = self.session_id
                    logger.info(f"[{self.session_id}] ↑上行 0x{frame.frame_type:02X} {frame.frame_name} LEN={frame.data_length} SEQ={frame.seq_no}")

                    # B. 透传至平台（未连接时缓冲）
                    if self.platform_writer:
                        try:
                            self.platform_writer.write(frame.raw)
                            await self.platform_writer.drain()
                        except Exception as e:
                            logger.error(f"[{self.session_id}] 上行透传失败: {e}")
                        
                        # E8→3B 转换
                        if self.e8_to_3b and frame.frame_type == 0xE8:
                            logger.info(f"[{self.session_id}] 触发 E8→3B 转换...")
                            frame_3b = convert_e8_to_3b(frame.raw)
                            if frame_3b:
                                try:
                                    self.platform_writer.write(frame_3b)
                                    await self.platform_writer.drain()
                                    logger.info(f"[{self.session_id}] E8→3B 转换帧已发送 ({len(frame_3b)} bytes)")
                                except Exception as e:
                                    logger.error(f"[{self.session_id}] E8→3B 发送失败: {e}")
                                # 推送转换帧到前端
                                parsed_3b = self.parser._parse_single_frame(frame_3b)
                                parsed_3b.session_id = self.session_id
                                parsed_3b.frame_name = "交易记录(0xE8→3B转换)"
                                await self.ws_queue.put(parsed_3b)
                            else:
                                logger.warning(f"[{self.session_id}] E8→3B 转换失败：convert_e8_to_3b 返回 None")
                    else:
                        self._early_frames.append(frame.raw)

                    # C. 推送到 WebSocket 前端
                    await self.ws_queue.put(frame)
                    # D. 写入日志文件
                    if self.on_frame:
                        self.on_frame(frame.to_dict())

        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"[{self.session_id}] 上行读循环异常: {e}", exc_info=True)
        finally:
            await self.stop()

    # ---- 下行读循环：平台 → 中转 ----

    async def _read_platform_loop(self):
        """读取平台返回的 TCP 数据，解析帧并透传回充电桩"""
        logger.info(f"[{self.session_id}] 下行读循环启动 (平台: {self.platform_host}:{self.platform_port})")
        parser = FrameParser()  # 下行用独立的解析器
        try:
            while self._running:
                data = await self.platform_reader.read(4096)
                if not data:
                    logger.info(f"[{self.session_id}] 平台连接断开")
                    break

                # 0. 原始数据日志（前64字节）
                preview = data[:64].hex(" ").upper()
                logger.info(f"[{self.session_id}] 收到平台数据 {len(data)} bytes: {preview}{'...' if len(data) > 64 else ''}")

                # A. 解析帧
                frames = parser.feed(data)
                for frame in frames:
                    frame.session_id = self.session_id
                    logger.info(f"[{self.session_id}] ↓下行 0x{frame.frame_type:02X} {frame.frame_name} LEN={frame.data_length} SEQ={frame.seq_no}")

                    # B. 透传回充电桩
                    try:
                        self.pile_writer.write(frame.raw)
                        await self.pile_writer.drain()
                    except Exception as e:
                        logger.error(f"[{self.session_id}] 下行透传失败: {e}")

                    # C. 推送到 WebSocket 前端
                    await self.ws_queue.put(frame)
                    # D. 写入日志文件
                    if self.on_frame:
                        self.on_frame(frame.to_dict())

        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"[{self.session_id}] 下行读循环异常: {e}", exc_info=True)
        finally:
            await self.stop()
