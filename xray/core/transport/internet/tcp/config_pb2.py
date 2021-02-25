# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: transport/internet/tcp/config.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


from common.serial import typed_message_pb2 as common_dot_serial_dot_typed__message__pb2


DESCRIPTOR = _descriptor.FileDescriptor(
  name='transport/internet/tcp/config.proto',
  package='xray.transport.internet.tcp',
  syntax='proto3',
  serialized_options=b'\n\037com.xray.transport.internet.tcpP\001Z0github.com/xtls/xray-core/transport/internet/tcp\252\002\033Xray.Transport.Internet.Tcp',
  create_key=_descriptor._internal_create_key,
  serialized_pb=b'\n#transport/internet/tcp/config.proto\x12\x1bxray.transport.internet.tcp\x1a!common/serial/typed_message.proto\"h\n\x06\x43onfig\x12\x39\n\x0fheader_settings\x18\x02 \x01(\x0b\x32 .xray.common.serial.TypedMessage\x12\x1d\n\x15\x61\x63\x63\x65pt_proxy_protocol\x18\x03 \x01(\x08J\x04\x08\x01\x10\x02\x42s\n\x1f\x63om.xray.transport.internet.tcpP\x01Z0github.com/xtls/xray-core/transport/internet/tcp\xaa\x02\x1bXray.Transport.Internet.Tcpb\x06proto3'
  ,
  dependencies=[common_dot_serial_dot_typed__message__pb2.DESCRIPTOR,])




_CONFIG = _descriptor.Descriptor(
  name='Config',
  full_name='xray.transport.internet.tcp.Config',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='header_settings', full_name='xray.transport.internet.tcp.Config.header_settings', index=0,
      number=2, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='accept_proxy_protocol', full_name='xray.transport.internet.tcp.Config.accept_proxy_protocol', index=1,
      number=3, type=8, cpp_type=7, label=1,
      has_default_value=False, default_value=False,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
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
  serialized_start=103,
  serialized_end=207,
)

_CONFIG.fields_by_name['header_settings'].message_type = common_dot_serial_dot_typed__message__pb2._TYPEDMESSAGE
DESCRIPTOR.message_types_by_name['Config'] = _CONFIG
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

Config = _reflection.GeneratedProtocolMessageType('Config', (_message.Message,), {
  'DESCRIPTOR' : _CONFIG,
  '__module__' : 'transport.internet.tcp.config_pb2'
  # @@protoc_insertion_point(class_scope:xray.transport.internet.tcp.Config)
  })
_sym_db.RegisterMessage(Config)


DESCRIPTOR._options = None
# @@protoc_insertion_point(module_scope)