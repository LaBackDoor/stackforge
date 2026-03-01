"""
Stackforge custom protocol support.

Example usage::

    from stackforge.custom import CustomLayer, ByteField, ShortField, IntField

    class MyProto(CustomLayer):
        name = "MyProto"
        fields_desc = [
            ByteField("opcode", 0),
            ShortField("length", 0),
            IntField("seq", 0),
        ]

    # Build a packet
    pkt = MyProto(opcode=1, length=6, seq=42)
    raw = bytes(pkt)  # serializes to wire format

    # Or stack it
    from stackforge import IP, UDP
    stacked = IP(dst="10.0.0.1") / UDP(dport=9000) / MyProto(opcode=1)
    raw = bytes(stacked)
"""

from __future__ import annotations

import struct
from typing import Any, ClassVar

# Registry of all custom protocols: name -> cls
_CUSTOM_PROTOCOLS: dict[str, type["CustomLayer"]] = {}


class BaseField:
    """Base class for custom protocol field descriptors."""

    def __init__(self, name: str, default: Any):
        self.name = name
        self.default = default

    @property
    def size(self) -> int:
        raise NotImplementedError

    def pack(self, value: Any) -> bytes:
        raise NotImplementedError

    def unpack(self, data: bytes, offset: int) -> tuple[Any, int]:
        """Return (value, bytes_consumed)."""
        raise NotImplementedError


class ByteField(BaseField):
    """Unsigned 8-bit integer field."""

    @property
    def size(self) -> int:
        return 1

    def pack(self, value: Any) -> bytes:
        return struct.pack("!B", int(value))

    def unpack(self, data: bytes, offset: int) -> tuple[Any, int]:
        return struct.unpack_from("!B", data, offset)[0], 1


class ShortField(BaseField):
    """Unsigned 16-bit big-endian integer field."""

    @property
    def size(self) -> int:
        return 2

    def pack(self, value: Any) -> bytes:
        return struct.pack("!H", int(value))

    def unpack(self, data: bytes, offset: int) -> tuple[Any, int]:
        return struct.unpack_from("!H", data, offset)[0], 2


class IntField(BaseField):
    """Unsigned 32-bit big-endian integer field."""

    @property
    def size(self) -> int:
        return 4

    def pack(self, value: Any) -> bytes:
        return struct.pack("!I", int(value))

    def unpack(self, data: bytes, offset: int) -> tuple[Any, int]:
        return struct.unpack_from("!I", data, offset)[0], 4


class LongField(BaseField):
    """Unsigned 64-bit big-endian integer field."""

    @property
    def size(self) -> int:
        return 8

    def pack(self, value: Any) -> bytes:
        return struct.pack("!Q", int(value))

    def unpack(self, data: bytes, offset: int) -> tuple[Any, int]:
        return struct.unpack_from("!Q", data, offset)[0], 8


class StrLenField(BaseField):
    """Fixed-length raw bytes field."""

    def __init__(self, name: str, default: bytes, length: int):
        super().__init__(name, default)
        self._length = length

    @property
    def size(self) -> int:
        return self._length

    def pack(self, value: Any) -> bytes:
        raw = bytes(value) if not isinstance(value, bytes) else value
        # Pad or truncate to fixed length
        if len(raw) < self._length:
            raw = raw + b"\x00" * (self._length - len(raw))
        return raw[: self._length]

    def unpack(self, data: bytes, offset: int) -> tuple[Any, int]:
        return data[offset : offset + self._length], self._length


class CustomLayer:
    """
    Base class for user-defined custom protocols.

    Subclass this and define a ``fields_desc`` class variable listing the
    fields in wire order::

        class MyProto(CustomLayer):
            name = "MyProto"
            fields_desc = [
                ByteField("opcode", 0),
                ShortField("length", 0),
            ]
    """

    name: ClassVar[str] = "Custom"
    fields_desc: ClassVar[list[BaseField]] = []

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        if cls.fields_desc:  # only register non-empty protocols
            _CUSTOM_PROTOCOLS[cls.name] = cls

    def __init__(self, **kwargs: Any) -> None:
        # Set defaults first
        self._values: dict[str, Any] = {}
        for field in self.fields_desc:
            self._values[field.name] = field.default
        # Apply any keyword overrides
        for k, v in kwargs.items():
            if k in self._values:
                self._values[k] = v
            else:
                raise TypeError(f"{self.__class__.__name__} has no field '{k}'")

    def __bytes__(self) -> bytes:
        """Serialize this layer to wire format."""
        result = b""
        for field in self.fields_desc:
            val = self._values.get(field.name, field.default)
            result += field.pack(val)
        return result

    def __len__(self) -> int:
        return sum(f.size for f in self.fields_desc)

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            raise AttributeError(name)
        try:
            return self._values[name]
        except KeyError:
            raise AttributeError(f"'{type(self).__name__}' has no field '{name}'")

    def __setattr__(self, name: str, value: Any) -> None:
        if name.startswith("_") or name in ("name", "fields_desc"):
            super().__setattr__(name, value)
        else:
            try:
                self._values[name] = value
            except AttributeError:
                super().__setattr__(name, value)

    def __truediv__(self, other: Any) -> "CustomLayerStack":
        return CustomLayerStack([self, other])

    def __rtruediv__(self, other: Any) -> "CustomLayerStack":
        return CustomLayerStack([other, self])

    def show(self) -> str:
        """Return a human-readable representation."""
        lines = [f"### {self.name} ###"]
        for field in self.fields_desc:
            val = self._values.get(field.name, field.default)
            lines.append(f"  {field.name} = {val!r}")
        return "\n".join(lines)

    @classmethod
    def parse(cls, data: bytes) -> "CustomLayer":
        """Parse a byte string into this layer type."""
        instance = cls()
        offset = 0
        for field in cls.fields_desc:
            if offset >= len(data):
                break
            val, consumed = field.unpack(data, offset)
            instance._values[field.name] = val
            offset += consumed
        return instance


class CustomLayerStack:
    """A stack of custom and standard layers."""

    def __init__(self, layers: list[Any]) -> None:
        self._layers = layers

    def __truediv__(self, other: Any) -> "CustomLayerStack":
        return CustomLayerStack(self._layers + [other])

    def __rtruediv__(self, other: Any) -> "CustomLayerStack":
        return CustomLayerStack([other] + self._layers)

    def __bytes__(self) -> bytes:
        result = b""
        for layer in self._layers:
            result += bytes(layer)
        return result

    def __len__(self) -> int:
        return sum(len(bytes(layer)) for layer in self._layers)


def get_protocol(name: str) -> type[CustomLayer] | None:
    """Look up a registered custom protocol by name."""
    return _CUSTOM_PROTOCOLS.get(name)


def list_protocols() -> list[str]:
    """Return the names of all registered custom protocols."""
    return list(_CUSTOM_PROTOCOLS.keys())
