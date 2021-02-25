# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: transport/internet/http/config.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='transport/internet/http/config.proto',
  package='xray.transport.internet.http',
  syntax='proto3',
  serialized_options=b'\n com.xray.transport.internet.httpP\001Z1github.com/xtls/xray-core/transport/internet/http\252\002\034Xray.Transport.Internet.Http',
  create_key=_descriptor._internal_create_key,
  serialized_pb=b'\n$transport/internet/http/config.proto\x12\x1cxray.transport.internet.http\"$\n\x06\x43onfig\x12\x0c\n\x04host\x18\x01 \x03(\t\x12\x0c\n\x04path\x18\x02 \x01(\tBv\n com.xray.transport.internet.httpP\x01Z1github.com/xtls/xray-core/transport/internet/http\xaa\x02\x1cXray.Transport.Internet.Httpb\x06proto3'
)




_CONFIG = _descriptor.Descriptor(
  name='Config',
  full_name='xray.transport.internet.http.Config',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='host', full_name='xray.transport.internet.http.Config.host', index=0,
      number=1, type=9, cpp_type=9, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='path', full_name='xray.transport.internet.http.Config.path', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
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
  serialized_start=70,
  serialized_end=106,
)

DESCRIPTOR.message_types_by_name['Config'] = _CONFIG
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

Config = _reflection.GeneratedProtocolMessageType('Config', (_message.Message,), {
  'DESCRIPTOR' : _CONFIG,
  '__module__' : 'transport.internet.http.config_pb2'
  # @@protoc_insertion_point(class_scope:xray.transport.internet.http.Config)
  })
_sym_db.RegisterMessage(Config)


DESCRIPTOR._options = None
# @@protoc_insertion_point(module_scope)
