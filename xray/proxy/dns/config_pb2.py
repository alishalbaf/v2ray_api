# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: proxy/dns/config.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


from common.net import destination_pb2 as common_dot_net_dot_destination__pb2


DESCRIPTOR = _descriptor.FileDescriptor(
  name='proxy/dns/config.proto',
  package='xray.proxy.dns',
  syntax='proto3',
  serialized_options=b'\n\022com.xray.proxy.dnsP\001Z#github.com/xtls/xray-core/proxy/dns\252\002\016Xray.Proxy.Dns',
  create_key=_descriptor._internal_create_key,
  serialized_pb=b'\n\x16proxy/dns/config.proto\x12\x0exray.proxy.dns\x1a\x1c\x63ommon/net/destination.proto\"3\n\x06\x43onfig\x12)\n\x06server\x18\x01 \x01(\x0b\x32\x19.xray.common.net.EndpointBL\n\x12\x63om.xray.proxy.dnsP\x01Z#github.com/xtls/xray-core/proxy/dns\xaa\x02\x0eXray.Proxy.Dnsb\x06proto3'
  ,
  dependencies=[common_dot_net_dot_destination__pb2.DESCRIPTOR,])




_CONFIG = _descriptor.Descriptor(
  name='Config',
  full_name='xray.proxy.dns.Config',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='server', full_name='xray.proxy.dns.Config.server', index=0,
      number=1, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
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
  serialized_start=72,
  serialized_end=123,
)

_CONFIG.fields_by_name['server'].message_type = common_dot_net_dot_destination__pb2._ENDPOINT
DESCRIPTOR.message_types_by_name['Config'] = _CONFIG
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

Config = _reflection.GeneratedProtocolMessageType('Config', (_message.Message,), {
  'DESCRIPTOR' : _CONFIG,
  '__module__' : 'proxy.dns.config_pb2'
  # @@protoc_insertion_point(class_scope:xray.proxy.dns.Config)
  })
_sym_db.RegisterMessage(Config)


DESCRIPTOR._options = None
# @@protoc_insertion_point(module_scope)
