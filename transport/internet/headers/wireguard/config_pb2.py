# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: transport/internet/headers/wireguard/config.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='transport/internet/headers/wireguard/config.proto',
  package='xray.transport.internet.headers.wireguard',
  syntax='proto3',
  serialized_options=b'\n-com.xray.transport.internet.headers.wireguardP\001Z>github.com/xtls/xray-core/transport/internet/headers/wireguard\252\002)Xray.Transport.Internet.Headers.Wireguard',
  create_key=_descriptor._internal_create_key,
  serialized_pb=b'\n1transport/internet/headers/wireguard/config.proto\x12)xray.transport.internet.headers.wireguard\"\x11\n\x0fWireguardConfigB\x9d\x01\n-com.xray.transport.internet.headers.wireguardP\x01Z>github.com/xtls/xray-core/transport/internet/headers/wireguard\xaa\x02)Xray.Transport.Internet.Headers.Wireguardb\x06proto3'
)




_WIREGUARDCONFIG = _descriptor.Descriptor(
  name='WireguardConfig',
  full_name='xray.transport.internet.headers.wireguard.WireguardConfig',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=96,
  serialized_end=113,
)

DESCRIPTOR.message_types_by_name['WireguardConfig'] = _WIREGUARDCONFIG
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

WireguardConfig = _reflection.GeneratedProtocolMessageType('WireguardConfig', (_message.Message,), {
  'DESCRIPTOR' : _WIREGUARDCONFIG,
  '__module__' : 'transport.internet.headers.wireguard.config_pb2'
  # @@protoc_insertion_point(class_scope:xray.transport.internet.headers.wireguard.WireguardConfig)
  })
_sym_db.RegisterMessage(WireguardConfig)


DESCRIPTOR._options = None
# @@protoc_insertion_point(module_scope)