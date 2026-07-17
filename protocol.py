"""
云快充/大华协议帧解析模块
帧结构：起始标志(1) + 数据长度(1) + 序列号域(2) + 加密标志(1) + 帧类型标志(1) + 消息体(N) + CRC16(2)
"""

import struct
from dataclasses import dataclass, field
from typing import Optional

# ============================================================
# 常量定义
# ============================================================

FRAME_HEADER = 0x68  # 帧起始标志
CRC_POLY = 0x180D  # CRC16 多项式

# ============================================================
# CRC16 查表法
# ============================================================

# 码表来自官方协议文档（多项式 0x180D）
_CRC_TABLE_HIGH = [
    0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0,
    0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41,
    0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0,
    0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40,
    0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1,
    0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41,
    0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1,
    0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41,
    0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0,
    0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40,
    0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1,
    0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40,
    0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0,
    0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40,
    0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0,
    0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40,
    0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0,
    0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41,
    0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0,
    0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41,
    0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0,
    0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40,
    0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1,
    0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41,
    0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0,
    0x80, 0x41, 0x00, 0xC1, 0x81, 0x40]

_CRC_TABLE_LOW = [
    0x00, 0xC0, 0xC1, 0x01, 0xC3, 0x03, 0x02, 0xC2, 0xC6, 0x06,
    0x07, 0xC7, 0x05, 0xC5, 0xC4, 0x04, 0xCC, 0x0C, 0x0D, 0xCD,
    0x0F, 0xCF, 0xCE, 0x0E, 0x0A, 0xCA, 0xCB, 0x0B, 0xC9, 0x09,
    0x08, 0xC8, 0xD8, 0x18, 0x19, 0xD9, 0x1B, 0xDB, 0xDA, 0x1A,
    0x1E, 0xDE, 0xDF, 0x1F, 0xDD, 0x1D, 0x1C, 0xDC, 0x14, 0xD4,
    0xD5, 0x15, 0xD7, 0x17, 0x16, 0xD6, 0xD2, 0x12, 0x13, 0xD3,
    0x11, 0xD1, 0xD0, 0x10, 0xF0, 0x30, 0x31, 0xF1, 0x33, 0xF3,
    0xF2, 0x32, 0x36, 0xF6, 0xF7, 0x37, 0xF5, 0x35, 0x34, 0xF4,
    0x3C, 0xFC, 0xFD, 0x3D, 0xFF, 0x3F, 0x3E, 0xFE, 0xFA, 0x3A,
    0x3B, 0xFB, 0x39, 0xF9, 0xF8, 0x38, 0x28, 0xE8, 0xE9, 0x29,
    0xEB, 0x2B, 0x2A, 0xEA, 0xEE, 0x2E, 0x2F, 0xEF, 0x2D, 0xED,
    0xEC, 0x2C, 0xE4, 0x24, 0x25, 0xE5, 0x27, 0xE7, 0xE6, 0x26,
    0x22, 0xE2, 0xE3, 0x23, 0xE1, 0x21, 0x20, 0xE0, 0xA0, 0x60,
    0x61, 0xA1, 0x63, 0xA3, 0xA2, 0x62, 0x66, 0xA6, 0xA7, 0x67,
    0xA5, 0x65, 0x64, 0xA4, 0x6C, 0xAC, 0xAD, 0x6D, 0xAF, 0x6F,
    0x6E, 0xAE, 0xAA, 0x6A, 0x6B, 0xAB, 0x69, 0xA9, 0xA8, 0x68,
    0x78, 0xB8, 0xB9, 0x79, 0xBB, 0x7B, 0x7A, 0xBA, 0xBE, 0x7E,
    0x7F, 0xBF, 0x7D, 0xBD, 0xBC, 0x7C, 0xB4, 0x74, 0x75, 0xB5,
    0x77, 0xB7, 0xB6, 0x76, 0x72, 0xB2, 0xB3, 0x73, 0xB1, 0x71,
    0x70, 0xB0, 0x50, 0x90, 0x91, 0x51, 0x93, 0x53, 0x52, 0x92,
    0x96, 0x56, 0x57, 0x97, 0x55, 0x95, 0x94, 0x54, 0x9C, 0x5C,
    0x5D, 0x9D, 0x5F, 0x9F, 0x9E, 0x5E, 0x5A, 0x9A, 0x9B, 0x5B,
    0x99, 0x59, 0x58, 0x98, 0x88, 0x48, 0x49, 0x89, 0x4B, 0x8B,
    0x8A, 0x4A, 0x4E, 0x8E, 0x8F, 0x4F, 0x8D, 0x4D, 0x4C, 0x8C,
    0x44, 0x84, 0x85, 0x45, 0x87, 0x47, 0x46, 0x86, 0x82, 0x42,
    0x43, 0x83, 0x41, 0x81, 0x80, 0x40]


def crc16(data: bytes) -> int:
    """计算 CRC16 校验值（多项式 0x180D），返回 (高字节 << 8 | 低字节)"""
    crc_high = 0xFF
    crc_low = 0xFF
    for byte in data:
        idx = crc_high ^ byte
        crc_high = crc_low ^ _CRC_TABLE_HIGH[idx]
        crc_low = _CRC_TABLE_LOW[idx]
    return (crc_high << 8) | crc_low


def crc16_verify(data: bytes, expected: int) -> bool:
    """校验数据 CRC 是否与期望值一致"""
    return crc16(data) == expected


# ============================================================
# 帧类型码映射
# ============================================================

# 标准云快充协议
FRAME_TYPE_MAP: dict[int, str] = {
    # 注册与心跳 (充电桩奇数 / 平台偶数)
    0x01: "充电桩登录认证",
    0x02: "登录认证应答",
    0x03: "充电桩心跳包",
    0x04: "心跳包应答",
    0x05: "计费模型验证请求",
    0x06: "计费模型验证请求应答",
    0x09: "充电桩计费模型请求",
    0x0A: "计费模型请求应答",
    # 实时数据
    0x12: "读取实时监测数据",
    0x13: "上传实时监测数据",
    0x15: "充电握手",
    0x17: "参数配置",
    0x19: "充电结束",
    0x1B: "错误报文",
    0x1D: "充电阶段BMS中止",
    0x21: "充电阶段充电机中止",
    0x23: "BMS需求与充电机输出",
    0x25: "充电过程BMS信息",
    # 运营交互
    0x31: "主动申请启动充电",
    0x32: "确认启动充电",
    0x33: "远程启机命令回复",
    0x34: "远程控制启机",
    0x35: "远程停机命令回复",
    0x36: "远程停机",
    0x3B: "交易记录",
    0x40: "交易记录确认",
    0x41: "余额更新应答",
    0x42: "远程账户余额更新",
    0x43: "离线卡数据同步应答",
    0x44: "离线卡数据同步",
    0x45: "离线卡数据清除应答",
    0x46: "离线卡数据清除",
    0x47: "离线卡数据查询应答",
    0x48: "离线卡数据查询",
    # 平台设置
    0x51: "工作参数设置应答",
    0x52: "工作参数设置",
    0x55: "对时设置应答",
    0x56: "对时设置",
    0x57: "计费模型设置应答",
    0x58: "计费模型设置",
    # 车位锁与维护
    0x61: "地锁数据上送",
    0x62: "地锁遥控",
    0x63: "地锁返回",
    0x91: "远程重启应答",
    0x92: "远程重启",
    0x93: "远程更新应答",
    0x94: "远程更新",
    # 大华补充协议
    0xC0: "桩整机状态",
    0xC2: "充电枪状态",
    0xD0: "账单明细",
    0xD1: "账单明细回复",
    0xE8: "交易记录(增强版)",
    0xE9: "交易记录回复",
}




# CRC16 文档码表（用于 E8→3B 转换，匹配平台端校验）
_CRC_TABLE_HIGH_DOC = [
    0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0,
    0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41,
    0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0,
    0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40,
    0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1,
    0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41,
    0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1,
    0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41,
    0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0,
    0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40,
    0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1,
    0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40,
    0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0,
    0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40,
    0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0,
    0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40,
    0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0,
    0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41,
    0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0,
    0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41,
    0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0,
    0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40,
    0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1,
    0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41,
    0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0,
    0x80, 0x41, 0x00, 0xC1, 0x81, 0x40]

_CRC_TABLE_LOW_DOC = [
    0x00, 0xC0, 0xC1, 0x01, 0xC3, 0x03, 0x02, 0xC2, 0xC6, 0x06,
    0x07, 0xC7, 0x05, 0xC5, 0xC4, 0x04, 0xCC, 0x0C, 0x0D, 0xCD,
    0x0F, 0xCF, 0xCE, 0x0E, 0x0A, 0xCA, 0xCB, 0x0B, 0xC9, 0x09,
    0x08, 0xC8, 0xD8, 0x18, 0x19, 0xD9, 0x1B, 0xDB, 0xDA, 0x1A,
    0x1E, 0xDE, 0xDF, 0x1F, 0xDD, 0x1D, 0x1C, 0xDC, 0x14, 0xD4,
    0xD5, 0x15, 0xD7, 0x17, 0x16, 0xD6, 0xD2, 0x12, 0x13, 0xD3,
    0x11, 0xD1, 0xD0, 0x10, 0xF0, 0x30, 0x31, 0xF1, 0x33, 0xF3,
    0xF2, 0x32, 0x36, 0xF6, 0xF7, 0x37, 0xF5, 0x35, 0x34, 0xF4,
    0x3C, 0xFC, 0xFD, 0x3D, 0xFF, 0x3F, 0x3E, 0xFE, 0xFA, 0x3A,
    0x3B, 0xFB, 0x39, 0xF9, 0xF8, 0x38, 0x28, 0xE8, 0xE9, 0x29,
    0xEB, 0x2B, 0x2A, 0xEA, 0xEE, 0x2E, 0x2F, 0xEF, 0x2D, 0xED,
    0xEC, 0x2C, 0xE4, 0x24, 0x25, 0xE5, 0x27, 0xE7, 0xE6, 0x26,
    0x22, 0xE2, 0xE3, 0x23, 0xE1, 0x21, 0x20, 0xE0, 0xA0, 0x60,
    0x61, 0xA1, 0x63, 0xA3, 0xA2, 0x62, 0x66, 0xA6, 0xA7, 0x67,
    0xA5, 0x65, 0x64, 0xA4, 0x6C, 0xAC, 0xAD, 0x6D, 0xAF, 0x6F,
    0x6E, 0xAE, 0xAA, 0x6A, 0x6B, 0xAB, 0x69, 0xA9, 0xA8, 0x68,
    0x78, 0xB8, 0xB9, 0x79, 0xBB, 0x7B, 0x7A, 0xBA, 0xBE, 0x7E,
    0x7F, 0xBF, 0x7D, 0xBD, 0xBC, 0x7C, 0xB4, 0x74, 0x75, 0xB5,
    0x77, 0xB7, 0xB6, 0x76, 0x72, 0xB2, 0xB3, 0x73, 0xB1, 0x71,
    0x70, 0xB0, 0x50, 0x90, 0x91, 0x51, 0x93, 0x53, 0x52, 0x92,
    0x96, 0x56, 0x57, 0x97, 0x55, 0x95, 0x94, 0x54, 0x9C, 0x5C,
    0x5D, 0x9D, 0x5F, 0x9F, 0x9E, 0x5E, 0x5A, 0x9A, 0x9B, 0x5B,
    0x99, 0x59, 0x58, 0x98, 0x88, 0x48, 0x49, 0x89, 0x4B, 0x8B,
    0x8A, 0x4A, 0x4E, 0x8E, 0x8F, 0x4F, 0x8D, 0x4D, 0x4C, 0x8C,
    0x44, 0x84, 0x85, 0x45, 0x87, 0x47, 0x46, 0x86, 0x82, 0x42,
    0x43, 0x83, 0x41, 0x81, 0x80, 0x40]

def crc16_doc(data: bytes) -> int:
    """CRC16 文档码表（用于生成 0x3B 转换帧）"""
    hi, lo = 0xFF, 0xFF
    for byte in data:
        idx = hi ^ byte
        hi = lo ^ _CRC_TABLE_HIGH_DOC[idx]
        lo = _CRC_TABLE_LOW_DOC[idx]
    return (hi << 8) | lo

def get_frame_name(frame_type: int) -> str:
    """根据帧类型码获取帧名称"""
    return FRAME_TYPE_MAP.get(frame_type, f"未知帧(0x{frame_type:02X})")


def get_direction(frame_type: int) -> str:
    """根据帧类型码推断方向。奇数=上行(桩→平台)，偶数=下行(平台→桩)。
    大华补充协议例外：0xC0/C2/D0/E8 为上行，0xD1/E9 为下行。"""
    # 大华上行帧（偶数但实际是桩→平台）
    if frame_type in (0xC0, 0xC2, 0xD0, 0xE8):
        return "up"
    # 大华下行帧（奇数但实际是平台→桩）
    if frame_type in (0xD1, 0xE9):
        return "down"
    return "up" if frame_type % 2 == 1 else "down"


# ============================================================
# BCD 解码
# ============================================================


def bcd_decode(data: bytes) -> str:
    """BCD 码解码为字符串，每字节两位十进制"""
    result = []
    for byte in data:
        high = (byte >> 4) & 0x0F
        low = byte & 0x0F
        result.append(f"{high}{low}")
    return "".join(result).lstrip("0") or "0"


def _read_u16_le(data: bytes, offset: int) -> int:
    """读取小端序 uint16"""
    return struct.unpack("<H", data[offset:offset+2])[0]


def _read_u32_le(data: bytes, offset: int) -> int:
    """读取小端序 uint32"""
    return struct.unpack("<I", data[offset:offset+4])[0]


# ============================================================
# 消息体字段解析器
# ============================================================


def parse_frame_body(frame_type: int, body: bytes, encrypted: bool) -> dict:
    """根据帧类型解析消息体，返回结构化字段。加密帧仅返回提示。"""
    if encrypted:
        return {"_encrypted": True, "_note": "消息体已 3DES 加密，无法解析"}

    parser = BODY_PARSERS.get(frame_type)
    if parser:
        return parser(body)

    # 默认：尝试提取桩编号（多数上行帧前 7 字节为桩编码 BCD）
    return _parse_common(body)


def _parse_common(body: bytes) -> dict:
    """通用解析：尝试提取 7 字节桩编号"""
    fields = {}
    if len(body) >= 7:
        try:
            fields["桩编号"] = bcd_decode(body[:7])
        except Exception:
            pass
    return fields


def _parse_0x01(body: bytes) -> dict:
    """0x01 充电桩登录认证：桩编码 7bytes BCD"""
    if len(body) < 7:
        return {}
    return {"桩编号": bcd_decode(body[:7])}


def _parse_0x03(body: bytes) -> dict:
    """0x03 充电桩心跳包：桩编码(7B BCD) + 枪号(1B BCD) + 枪状态(1B)"""
    if len(body) < 9:
        return _parse_common(body)
    state_map = {0x00: "正常", 0x01: "故障"}
    return {
        "桩编号": bcd_decode(body[:7]),
        "枪号": bcd_decode(body[7:8]),
        "枪状态": state_map.get(body[8], f"0x{body[8]:02X}"),
    }


def _parse_0x13(body: bytes) -> dict:
    """0x13 上传实时监测数据"""
    if len(body) < 38:
        return _parse_common(body)
    state_map = {0x00: "离线", 0x01: "故障", 0x02: "空闲", 0x03: "充电"}
    plug_map = {0x00: "否", 0x01: "是", 0x02: "未知"}
    return {
        "交易流水号": body[0:16].hex(" ").upper(),
        "桩编号": bcd_decode(body[16:23]),
        "枪号": bcd_decode(body[23:24]),
        "状态": state_map.get(body[24], f"0x{body[24]:02X}"),
        "枪是否归位": plug_map.get(body[25], f"0x{body[25]:02X}"),
        "是否插枪": plug_map.get(body[26], f"0x{body[26]:02X}"),
        "输出电压(V)": round(int.from_bytes(body[27:29], "little") / 10, 1),
        "输出电流(A)": round(int.from_bytes(body[29:31], "little") / 10, 1),
        "枪线温度(℃)": body[31] - 50,
        "SOC(%)": body[39],
        "电池最高温度(℃)": body[40] - 50 if body[40] else 0,
        "累计充电时间(min)": int.from_bytes(body[41:43], "little"),
        "剩余时间(min)": int.from_bytes(body[43:45], "little"),
        "充电度数(kWh)": round(int.from_bytes(body[45:49], "little") / 10000, 4),
        "已充金额(元)": round(int.from_bytes(body[53:57], "little") / 10000, 4),
    }


def _parse_0x15(body: bytes) -> dict:
    """0x15 充电握手 (GBT-27930)"""
    if len(body) < 26:
        return _parse_common(body)
    return {
        "交易流水号": body[0:16].hex(" ").upper(),
        "桩编号": bcd_decode(body[16:23]),
        "枪号": bcd_decode(body[23:24]),
    }


def _parse_0x17(body: bytes) -> dict:
    """0x17 参数配置 (GBT-27930)"""
    if len(body) < 49:
        return _parse_common(body)
    return {
        "交易流水号": body[0:16].hex(" ").upper(),
        "桩编号": bcd_decode(body[16:23]),
        "枪号": bcd_decode(body[23:24]),
        "BMS最高充电电压(V)": round(int.from_bytes(body[24:26], "little") * 0.01, 2),
        "BMS最高充电电流(A)": round(int.from_bytes(body[26:28], "little") * 0.1 - 400, 1),
        "BMS标称总能量(kWh)": round(int.from_bytes(body[28:30], "little") * 0.1, 1),
        "BMS最高总电压(V)": round(int.from_bytes(body[30:32], "little") * 0.1, 1),
        "BMS最高温度(℃)": body[32] - 50,
        "BMS整车SOC(%)": round(int.from_bytes(body[33:35], "little") * 0.1, 1),
        "BMS当前电压(V)": round(int.from_bytes(body[35:37], "little") * 0.1, 1),
        "电桩最高输出电压(V)": round(int.from_bytes(body[37:39], "little") * 0.1, 1),
        "电桩最低输出电压(V)": round(int.from_bytes(body[39:41], "little") * 0.1, 1),
        "电桩最大输出电流(A)": round(int.from_bytes(body[41:43], "little") * 0.1 - 400, 1),
        "电桩最小输出电流(A)": round(int.from_bytes(body[43:45], "little") * 0.1 - 400, 1),
    }


def _parse_0x19(body: bytes) -> dict:
    """0x19 充电结束 (GBT-27930)"""
    if len(body) < 24:
        return _parse_common(body)
    return {
        "交易流水号": body[0:16].hex(" ").upper(),
        "桩编号": bcd_decode(body[16:23]),
        "枪号": bcd_decode(body[23:24]),
    }


def _parse_0x31(body: bytes) -> dict:
    """0x31 主动申请启动充电"""
    if len(body) < 8:
        return _parse_common(body)
    mode_map = {0x01: "刷卡", 0x02: "密码", 0x03: "二维码"}
    return {
        "桩编号": bcd_decode(body[:7]),
        "启动方式": mode_map.get(body[7], f"0x{body[7]:02X}"),
    }


def _parse_0x34(body: bytes) -> dict:
    """0x34 远程控制启机（平台→桩）"""
    if len(body) < 7:
        return _parse_common(body)
    return {"桩编号": bcd_decode(body[:7])}


def _parse_0xC2(body: bytes) -> dict:
    """0xC2 充电枪状态（大华协议）
    桩编码(7B BCD) + 枪号(1B) + 枪状态(1B) + 枪是否插入(1B) + 故障原因(4B) + 充电模块通讯(4B)
    """
    if len(body) < 18:
        return _parse_common(body)

    gun_state_map = {0x00: "离线", 0x01: "故障", 0x02: "空闲", 0x03: "充电"}
    plugged_map = {0x00: "否", 0x01: "是"}

    return {
        "桩编号": bcd_decode(body[:7]),
        "枪号": "A枪" if body[7] == 1 else ("B枪" if body[7] == 2 else str(body[7])),
        "枪状态": gun_state_map.get(body[8], f"0x{body[8]:02X}"),
        "枪是否插入": plugged_map.get(body[9], f"0x{body[9]:02X}"),
        "故障原因(hex)": body[10:14].hex(" ").upper(),
        "充电模块通讯(hex)": body[14:18].hex(" ").upper(),
    }


def _parse_0x3B(body: bytes) -> dict:
    """0x3B 交易记录（无计损，26字段）"""
    if len(body) < 146:
        return _parse_common(body)

    def _bcd4(data: bytes) -> float:
        return round(int.from_bytes(data, "little") / 10000, 4)

    def _bcd9(data: bytes) -> float:
        return round(int.from_bytes(data, "little") / 10000, 4)

    trade_map = {0x01: "APP启动", 0x02: "卡启动", 0x04: "离线卡", 0x05: "VIN启动"}

    fields = {
        "交易流水号": body[0:16].hex(" ").upper(),
        "桩编号": bcd_decode(body[16:23]),
        "枪号": bcd_decode(body[23:24]),
        # 尖(3字段): 38-49
        "尖单价": round(int.from_bytes(body[38:42], "little") / 100000, 5),
        "尖电量": _bcd4(body[42:46]),
        "尖金额": _bcd4(body[46:50]),
        # 峰(3字段): 50-61
        "峰单价": round(int.from_bytes(body[50:54], "little") / 100000, 5),
        "峰电量": _bcd4(body[54:58]),
        "峰金额": _bcd4(body[58:62]),
        # 平(3字段): 62-73
        "平单价": round(int.from_bytes(body[62:66], "little") / 100000, 5),
        "平电量": _bcd4(body[66:70]),
        "平金额": _bcd4(body[70:74]),
        # 谷(3字段): 74-85
        "谷单价": round(int.from_bytes(body[74:78], "little") / 100000, 5),
        "谷电量": _bcd4(body[78:82]),
        "谷金额": _bcd4(body[82:86]),
        # 电表(9B): 86-103
        "电表总起值": _bcd9(body[86:95]),
        "电表总止值": _bcd9(body[95:104]),
        "总电量": _bcd4(body[104:108]),
        "消费金额": _bcd4(body[108:112]),
        # 标识
        "VIN": body[112:129].decode("ascii", errors="replace").strip("\x00"),
        "交易标识": trade_map.get(body[129], f"0x{body[129]:02X}"),
        "停止原因": f"0x{body[137]:02X}",
        "物理卡号": body[138:146].hex(" ").upper(),
    }
    return fields


def _parse_0xE8(body: bytes) -> dict:
    """0xE8 交易记录增强版（大华协议）
    固定 197 bytes + n*22 bytes 时段明细
    """
    if len(body) < 197:
        return _parse_common(body)

    def _bcd4(data: bytes) -> float:
        return round(int.from_bytes(data, "little") / 10000, 4)

    def _bcd5(data: bytes) -> float:
        return round(int.from_bytes(data, "little") / 10000, 4)

    trade_map = {0x01: "APP启动", 0x02: "卡启动", 0x04: "离线卡", 0x05: "VIN启动"}

    fields = {
        "交易流水号": body[0:16].hex(" ").upper(),
        "桩编号": bcd_decode(body[16:23]),
        "枪号": bcd_decode(body[23:24]),
        # 尖峰平谷
        "尖电费费率": round(int.from_bytes(body[38:42], "little") / 100000, 5),
        "尖服务费费率": round(int.from_bytes(body[42:46], "little") / 100000, 5),
        "尖电量": _bcd4(body[46:50]),
        "尖电费金额": _bcd4(body[54:58]),
        "尖服务费金额": _bcd4(body[58:62]),
        "峰电费费率": round(int.from_bytes(body[62:66], "little") / 100000, 5),
        "峰服务费费率": round(int.from_bytes(body[66:70], "little") / 100000, 5),
        "峰电量": _bcd4(body[70:74]),
        "峰电费金额": _bcd4(body[78:82]),
        "峰服务费金额": _bcd4(body[82:86]),
        "平电费费率": round(int.from_bytes(body[86:90], "little") / 100000, 5),
        "平服务费费率": round(int.from_bytes(body[90:94], "little") / 100000, 5),
        "平电量": _bcd4(body[94:98]),
        "平电费金额": _bcd4(body[102:106]),
        "平服务费金额": _bcd4(body[106:110]),
        "谷电费费率": round(int.from_bytes(body[110:114], "little") / 100000, 5),
        "谷服务费费率": round(int.from_bytes(body[114:118], "little") / 100000, 5),
        "谷电量": _bcd4(body[118:122]),
        "谷电费金额": _bcd4(body[126:130]),
        "谷服务费金额": _bcd4(body[130:134]),
        # 核心计费
        "电表总起值": _bcd5(body[134:139]),
        "电表总止值": _bcd5(body[139:144]),
        "总电量": _bcd4(body[144:148]),
        "充电总电费": _bcd4(body[148:152]),
        "充电总服务费": _bcd4(body[152:156]),
        "总费用": _bcd4(body[156:160]),
        # 标识
        "VIN": body[160:177].decode("ascii", errors="replace").strip("\x00"),
        "交易标识": trade_map.get(body[177], f"0x{body[177]:02X}"),
        "停止原因": f"0x{body[185]:02X}",
        "物理卡号": body[186:194].hex(" ").upper(),
        "计费模型编号": int.from_bytes(body[194:196], "little"),
        "充电时段数": body[196],
    }
    return fields


def _parse_0xC0(body: bytes) -> dict:
    """0xC0 桩整机状态（大华协议）
    桩编码(7B BCD) + 整机状态(4B BIN bit flags)
    """
    if len(body) < 11:
        return _parse_common(body)
    
    fault_bits = {
        0: "触摸屏通讯", 1: "读卡器通讯", 2: "交流输入电表通讯", 3: "急停",
        4: "风扇", 5: "防雷", 6: "门禁", 7: "输入接触器",
        8: "交流过压", 9: "交流欠压2", 10: "交流过流", 11: "充电桩过温",
        12: "中间接触器", 13: "烟雾报警"
    }
    status_val = int.from_bytes(body[7:11], "little")
    faults = []
    for bit in range(14):
        if status_val & (1 << bit):
            faults.append(fault_bits.get(bit, f"Bit{bit}"))
    
    return {
        "桩编号": bcd_decode(body[:7]),
        "整机状态": "正常" if status_val == 0 else f"故障({','.join(faults)})",
        "整机状态(hex)": body[7:11].hex(" ").upper(),
    }


def _parse_0xD0(body: bytes) -> dict:
    """0xD0 账单明细（大华协议）
    固定部分 77 bytes + n*22 bytes 时段明细
    """
    if len(body) < 77:
        return _parse_common(body)
    
    def _bcd4(data: bytes) -> float:
        return round(int.from_bytes(data, "little") / 10000, 4)
    
    fields = {
        "流水号": body[0:16].hex(" ").upper(),
        "桩编号": bcd_decode(body[16:23]),
        "枪号": bcd_decode(body[23:24]),
        "计费模型编号": int.from_bytes(body[24:26], "little"),
        "尖电费费率": round(int.from_bytes(body[26:30], "little") / 100000, 5),
        "尖服务费费率": round(int.from_bytes(body[30:34], "little") / 100000, 5),
        "峰电费费率": round(int.from_bytes(body[34:38], "little") / 100000, 5),
        "峰服务费费率": round(int.from_bytes(body[38:42], "little") / 100000, 5),
        "平电费费率": round(int.from_bytes(body[42:46], "little") / 100000, 5),
        "平服务费费率": round(int.from_bytes(body[46:50], "little") / 100000, 5),
        "谷电费费率": round(int.from_bytes(body[50:54], "little") / 100000, 5),
        "谷服务费费率": round(int.from_bytes(body[54:58], "little") / 100000, 5),
        "计损比例": body[58],
        "充电总电费": _bcd4(body[59:63]),
        "充电总服务费": _bcd4(body[63:67]),
        "总费用": _bcd4(body[67:71]),
        "账单明细索引": body[71],
        "充电时段数": body[72],
    }
    return fields


def _parse_0xD1(body: bytes) -> dict:
    """0xD1 账单明细回复（大华协议）
    流水号(16B BCD) + 桩编号(7B BCD)
    """
    if len(body) < 23:
        return _parse_common(body)
    return {
        "流水号": body[0:16].hex(" ").upper(),
        "桩编号": bcd_decode(body[16:23]),
    }


def _parse_0xE9(body: bytes) -> dict:
    """0xE9 交易记录回复（大华协议）
    流水号(7B BCD) + 确认结果(1B)
    """
    if len(body) < 8:
        return _parse_common(body)
    result_map = {0x00: "上传成功", 0x01: "非法账单"}
    return {
        "流水号": bcd_decode(body[:7]),
        "确认结果": result_map.get(body[7], f"0x{body[7]:02X}"),
    }


# 帧类型 → 解析器映射
BODY_PARSERS: dict[int, callable] = {
    0x01: _parse_0x01,
    0x03: _parse_0x03,
    0x13: _parse_0x13,
    0x15: _parse_0x15,
    0x17: _parse_0x17,
    0x19: _parse_0x19,
    0x31: _parse_0x31,
    0x34: _parse_0x34,
    0x3B: _parse_0x3B,
    0xC0: _parse_0xC0,
    0xC2: _parse_0xC2,
    0xD0: _parse_0xD0,
    0xD1: _parse_0xD1,
    0xE8: _parse_0xE8,
    0xE9: _parse_0xE9,
}


# ============================================================
# 帧数据结构
# ============================================================


@dataclass
class ParsedFrame:
    """解析后的帧"""
    raw: bytes  # 原始字节（含帧头、CRC）
    timestamp: float
    direction: str  # "up" / "down"
    frame_type: int
    frame_name: str
    data_length: int
    seq_no: int
    encrypted: bool
    body: bytes  # 消息体（不含帧头、长度、CRC等）
    crc_ok: bool
    session_id: str = ""  # 桩编号，解析后填充

    @property
    def fields(self) -> dict:
        """解析后的消息体字段"""
        return parse_frame_body(self.frame_type, self.body, self.encrypted)

    def hex_str(self) -> str:
        """原始报文的 hex 字符串（空格分隔）"""
        return " ".join(f"{b:02X}" for b in self.raw)

    def body_hex_str(self) -> str:
        """消息体的 hex 字符串"""
        return " ".join(f"{b:02X}" for b in self.body)

    def hex_dump(self) -> str:
        """原始报文的格式化 hex dump（16 字节一行，带偏移和 ASCII）"""
        lines = []
        for i in range(0, len(self.raw), 16):
            chunk = self.raw[i:i + 16]
            hex_part = " ".join(f"{b:02X}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append(f"{i:04X}  {hex_part:<48}  {ascii_part}")
        return "\n".join(lines)

    def summary(self) -> str:
        """一行概要，用于表格展示"""
        parts = [f"LEN={self.data_length}", f"SEQ={self.seq_no}"]
        f = self.fields
        if f and "_encrypted" not in f:
            for k, v in f.items():
                if not k.startswith("_"):
                    parts.append(f"{k}={v}")
                    if len(parts) > 3:
                        break
        return " | ".join(parts)

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "direction": self.direction,
            "direction_label": "↑上行" if self.direction == "up" else "↓下行",
            "frame_type": f"0x{self.frame_type:02X}",
            "frame_name": self.frame_name,
            "data_length": self.data_length,
            "seq_no": self.seq_no,
            "encrypted": self.encrypted,
            "hex": self.hex_str(),
            "hex_dump": self.hex_dump(),
            "body_hex": self.body_hex_str(),
            "crc_ok": self.crc_ok,
            "session_id": self.session_id,
            "raw_length": len(self.raw),
            "crc": self.raw[-2:].hex(" ").upper() if len(self.raw) >= 2 else "",
            "fields": self.fields,
            "summary": self.summary(),
        }


# ============================================================
# 帧解析器
# ============================================================


class FrameParser:
    """
    TCP 流式帧解析器。
    维护内部缓冲区，处理粘包/半包，按 0x68 帧头切分完整帧。
    """

    def __init__(self):
        self._buffer = bytearray()

    def feed(self, data: bytes) -> list[ParsedFrame]:
        """喂入 TCP 数据，返回成功解析的帧列表"""
        self._buffer.extend(data)
        frames = []

        while True:
            # 1. 找帧头 0x68
            head_idx = self._find_frame_head()
            if head_idx == -1:
                # 没有帧头，清空缓冲区
                self._buffer.clear()
                break

            # 丢弃帧头之前的异常字节
            if head_idx > 0:
                self._buffer = self._buffer[head_idx:]

            # 2. 至少需要 1(帧头) + 1(长度) = 2 字节才能读取长度
            if len(self._buffer) < 2:
                break

            data_length = self._buffer[1]  # 数据长度 = 序列号+加密标志+帧类型+消息体
            total_length = 1 + 1 + data_length + 2  # 帧头 + 长度字段 + 数据 + CRC

            # 3. 半包：等数据到齐
            if len(self._buffer) < total_length:
                break

            # 4. 切出完整帧
            raw = bytes(self._buffer[:total_length])
            self._buffer = self._buffer[total_length:]

            # 5. 解析帧
            frame = self._parse_single_frame(raw)
            frames.append(frame)

        return frames

    def _find_frame_head(self) -> int:
        """在缓冲区中查找帧头 0x68，返回索引；未找到返回 -1"""
        try:
            return self._buffer.index(FRAME_HEADER)
        except ValueError:
            return -1

    def _parse_single_frame(self, raw: bytes) -> ParsedFrame:
        """解析一个完整帧"""
        import time

        data_length = raw[1]
        seq_no = struct.unpack("<H", raw[2:4])[0]  # 小端序
        encrypted = raw[4] != 0x00
        frame_type = raw[5]
        body = raw[6 : 6 + data_length - 4]  # 数据长度减 (序列号2+加密标志1+帧类型1)

        # CRC 校验：对"序列号域 + 加密标志 + 帧类型标志 + 消息体"计算
        total_length = 1 + 1 + data_length + 2  # 帧头+长度字段+数据+CRC
        crc_data = raw[2 : 2 + data_length]
        expected_crc = struct.unpack("<H", raw[2 + data_length : 2 + data_length + 2])[0]

        crc_ok = crc16_verify(crc_data, expected_crc)
        direction = get_direction(frame_type)

        return ParsedFrame(
            raw=raw,
            timestamp=time.time(),
            direction=direction,
            frame_type=frame_type,
            frame_name=get_frame_name(frame_type),
            data_length=data_length,
            seq_no=seq_no,
            encrypted=encrypted,
            body=body,
            crc_ok=crc_ok,
        )
