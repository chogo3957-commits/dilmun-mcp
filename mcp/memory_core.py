"""
Dilmun Memory Core Module
Windows API를 통한 메모리 읽기/쓰기 핵심 엔진

주요 기능:
- 프로세스 메모리 접근 (ReadProcessMemory, WriteProcessMemory)
- 메모리 영역 쿼리 (VirtualQueryEx)
- 메모리 보호 권한 변경
- 메모리 패턴 검색
"""

import ctypes
import struct
from ctypes import wintypes
from typing import Optional, List, Tuple
import logging

logger = logging.getLogger(__name__)

# Windows Constants
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008

PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_GUARD = 0x100
PAGE_NOCACHE = 0x200
PAGE_WRITECOMBINE = 0x400

MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_DECOMMIT = 0x4000
MEM_RELEASE = 0x8000
MEM_FREE = 0x10000

# Windows API 함수 정의
class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    """VirtualQueryEx 반환 구조체"""
    _fields_ = [
        ("BaseAddress", wintypes.LPVOID),
        ("AllocationBase", wintypes.LPVOID),
        ("AllocationProtect", wintypes.DWORD),
        ("PartitionKey", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


class MemoryCore:
    """
    Windows 프로세스 메모리 접근 핵심 클래스
    """
    
    def __init__(self, process_handle: Optional[int] = None):
        """
        Args:
            process_handle: 프로세스 핸들 (None이면 현재 프로세스)
        """
        self.process_handle = process_handle
        self.kernel32 = ctypes.windll.kernel32
        self._setup_api_functions()
    
    def _setup_api_functions(self):
        """Windows API 함수 시그니처 설정"""
        # ReadProcessMemory
        self.kernel32.ReadProcessMemory.argtypes = [
            wintypes.HANDLE,
            wintypes.LPVOID,
            wintypes.LPVOID,
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_size_t),
        ]
        self.kernel32.ReadProcessMemory.restype = wintypes.BOOL
        
        # WriteProcessMemory
        self.kernel32.WriteProcessMemory.argtypes = [
            wintypes.HANDLE,
            wintypes.LPVOID,
            wintypes.LPVOID,
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_size_t),
        ]
        self.kernel32.WriteProcessMemory.restype = wintypes.BOOL
        
        # VirtualQueryEx
        self.kernel32.VirtualQueryEx.argtypes = [
            wintypes.HANDLE,
            wintypes.LPVOID,
            ctypes.POINTER(MEMORY_BASIC_INFORMATION),
            ctypes.c_size_t,
        ]
        self.kernel32.VirtualQueryEx.restype = ctypes.c_size_t
        
        # VirtualProtectEx
        self.kernel32.VirtualProtectEx.argtypes = [
            wintypes.HANDLE,
            wintypes.LPVOID,
            ctypes.c_size_t,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        ]
        self.kernel32.VirtualProtectEx.restype = wintypes.BOOL
    
    def read_bytes(self, address: int, size: int) -> Optional[bytes]:
        """
        메모리에서 바이트 읽기
        
        Args:
            address: 읽을 주소
            size: 읽을 바이트 수
            
        Returns:
            읽은 바이트 데이터, 실패 시 None
        """
        if not self.process_handle:
            logger.error("Process handle이 없습니다")
            return None
        
        try:
            buffer = ctypes.create_string_buffer(size)
            bytes_read = ctypes.c_size_t()
            
            result = self.kernel32.ReadProcessMemory(
                self.process_handle,
                ctypes.c_void_p(address),
                buffer,
                size,
                ctypes.byref(bytes_read),
            )
            
            if result:
                return buffer.raw[:bytes_read.value]
            else:
                logger.error(f"ReadProcessMemory 실패 at {hex(address)}")
                return None
        except Exception as e:
            logger.error(f"read_bytes 오류: {e}")
            return None
    
    def read_uint32(self, address: int) -> Optional[int]:
        """4바이트 부호없는 정수 읽기"""
        data = self.read_bytes(address, 4)
        if data:
            return struct.unpack('<I', data)[0]
        return None
    
    def read_int32(self, address: int) -> Optional[int]:
        """4바이트 부호있는 정수 읽기"""
        data = self.read_bytes(address, 4)
        if data:
            return struct.unpack('<i', data)[0]
        return None
    
    def read_uint16(self, address: int) -> Optional[int]:
        """2바이트 부호없는 정수 읽기"""
        data = self.read_bytes(address, 2)
        if data:
            return struct.unpack('<H', data)[0]
        return None
    
    def read_int16(self, address: int) -> Optional[int]:
        """2바이트 부호있는 정수 읽기"""
        data = self.read_bytes(address, 2)
        if data:
            return struct.unpack('<h', data)[0]
        return None
    
    def read_uint8(self, address: int) -> Optional[int]:
        """1바이트 부호없는 정수 읽기"""
        data = self.read_bytes(address, 1)
        if data:
            return struct.unpack('<B', data)[0]
        return None
    
    def read_int8(self, address: int) -> Optional[int]:
        """1바이트 부호있는 정수 읽기"""
        data = self.read_bytes(address, 1)
        if data:
            return struct.unpack('<b', data)[0]
        return None
    
    def read_float(self, address: int) -> Optional[float]:
        """부동소수점 읽기"""
        data = self.read_bytes(address, 4)
        if data:
            return struct.unpack('<f', data)[0]
        return None
    
    def read_double(self, address: int) -> Optional[float]:
        """8바이트 부동소수점 읽기"""
        data = self.read_bytes(address, 8)
        if data:
            return struct.unpack('<d', data)[0]
        return None
    
    def write_bytes(self, address: int, data: bytes) -> bool:
        """
        메모리에 바이트 쓰기
        
        Args:
            address: 쓸 주소
            data: 쓸 데이터
            
        Returns:
            성공 여부
        """
        if not self.process_handle:
            logger.error("Process handle이 없습니다")
            return False
        
        try:
            bytes_written = ctypes.c_size_t()
            
            result = self.kernel32.WriteProcessMemory(
                self.process_handle,
                ctypes.c_void_p(address),
                data,
                len(data),
                ctypes.byref(bytes_written),
            )
            
            if result:
                logger.info(f"메모리 쓰기 성공: {hex(address)} ({bytes_written.value} bytes)")
                return True
            else:
                logger.error(f"WriteProcessMemory 실패 at {hex(address)}")
                return False
        except Exception as e:
            logger.error(f"write_bytes 오류: {e}")
            return False
    
    def write_uint32(self, address: int, value: int) -> bool:
        """4바이트 부호없는 정수 쓰기"""
        data = struct.pack('<I', value & 0xFFFFFFFF)
        return self.write_bytes(address, data)
    
    def write_int32(self, address: int, value: int) -> bool:
        """4바이트 부호있는 정수 쓰기"""
        data = struct.pack('<i', value)
        return self.write_bytes(address, data)
    
    def write_uint16(self, address: int, value: int) -> bool:
        """2바이트 부호없는 정수 쓰기"""
        data = struct.pack('<H', value & 0xFFFF)
        return self.write_bytes(address, data)
    
    def write_int16(self, address: int, value: int) -> bool:
        """2바이트 부호있는 정수 쓰기"""
        data = struct.pack('<h', value)
        return self.write_bytes(address, data)
    
    def write_uint8(self, address: int, value: int) -> bool:
        """1바이트 부호없는 정수 쓰기"""
        data = struct.pack('<B', value & 0xFF)
        return self.write_bytes(address, data)
    
    def write_int8(self, address: int, value: int) -> bool:
        """1바이트 부호있는 정수 쓰기"""
        data = struct.pack('<b', value)
        return self.write_bytes(address, data)
    
    def write_float(self, address: int, value: float) -> bool:
        """부동소수점 쓰기"""
        data = struct.pack('<f', value)
        return self.write_bytes(address, data)
    
    def write_double(self, address: int, value: float) -> bool:
        """8바이트 부동소수점 쓰기"""
        data = struct.pack('<d', value)
        return self.write_bytes(address, data)
    
    def get_memory_info(self, address: int) -> Optional[MEMORY_BASIC_INFORMATION]:
        """
        지정된 주소의 메모리 정보 조회
        
        Args:
            address: 조회할 주소
            
        Returns:
            MEMORY_BASIC_INFORMATION 구조체
        """
        if not self.process_handle:
            logger.error("Process handle이 없습니다")
            return None
        
        try:
            mbi = MEMORY_BASIC_INFORMATION()
            size = ctypes.sizeof(MEMORY_BASIC_INFORMATION)
            
            result = self.kernel32.VirtualQueryEx(
                self.process_handle,
                ctypes.c_void_p(address),
                ctypes.byref(mbi),
                size,
            )
            
            if result > 0:
                return mbi
            else:
                logger.error(f"VirtualQueryEx 실패 at {hex(address)}")
                return None
        except Exception as e:
            logger.error(f"get_memory_info 오류: {e}")
            return None
    
    def change_protection(self, address: int, size: int, new_protect: int) -> bool:
        """
        메모리 보호 권한 변경
        
        Args:
            address: 주소
            size: 크기
            new_protect: 새로운 보호 플래그
            
        Returns:
            성공 여부
        """
        if not self.process_handle:
            logger.error("Process handle이 없습니다")
            return False
        
        try:
            old_protect = wintypes.DWORD()
            
            result = self.kernel32.VirtualProtectEx(
                self.process_handle,
                ctypes.c_void_p(address),
                size,
                new_protect,
                ctypes.byref(old_protect),
            )
            
            if result:
                logger.info(f"메모리 보호 변경 성공: {hex(address)} (0x{old_protect.value:X} -> 0x{new_protect:X})")
                return True
            else:
                logger.error(f"VirtualProtectEx 실패 at {hex(address)}")
                return False
        except Exception as e:
            logger.error(f"change_protection 오류: {e}")
            return False
    
    def search_pattern(self, pattern: bytes, start_address: int = 0, end_address: Optional[int] = None) -> List[int]:
        """
        메모리 패턴 검색
        
        Args:
            pattern: 검색할 바이트 패턴
            start_address: 시작 주소
            end_address: 종료 주소 (None이면 끝까지)
            
        Returns:
            발견된 주소 리스트
        """
        results = []
        current_address = start_address
        chunk_size = 0x10000  # 64KB 청크 단위로 읽음
        
        try:
            while True:
                # 메모리 정보 조회
                mbi = self.get_memory_info(current_address)
                if not mbi:
                    break
                
                # 범위 제한 체크
                if end_address and current_address >= end_address:
                    break
                
                # 읽을 수 있는 메모리 영역 확인
                if mbi.State == MEM_COMMIT and mbi.Protect != PAGE_NOACCESS:
                    # 읽을 크기 결정
                    read_size = min(mbi.RegionSize, chunk_size)
                    if end_address:
                        read_size = min(read_size, end_address - current_address)
                    
                    # 메모리 읽기
                    data = self.read_bytes(current_address, read_size)
                    if data:
                        # 패턴 검색
                        for i in range(len(data) - len(pattern) + 1):
                            if data[i:i+len(pattern)] == pattern:
                                results.append(current_address + i)
                
                # 다음 주소로 이동
                current_address += mbi.RegionSize
        except Exception as e:
            logger.error(f"search_pattern 오류: {e}")
        
        return results
    
    def is_valid_address(self, address: int) -> bool:
        """
        주소가 유효한지 확인
        
        Args:
            address: 확인할 주소
            
        Returns:
            유효 여부
        """
        mbi = self.get_memory_info(address)
        if not mbi:
            return False
        return mbi.State == MEM_COMMIT and mbi.Protect != PAGE_NOACCESS


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    print("Memory Core Module loaded successfully")
