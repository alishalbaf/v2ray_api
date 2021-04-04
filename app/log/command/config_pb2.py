# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: app/log/command/config.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='app/log/command/config.proto',
  package='xray.app.log.command',
  syntax='proto3',
  serialized_options=b'\n\030com.xray.app.log.commandP\001Z)github.com/xtls/xray-core/app/log/command\252\002\024Xray.App.Log.Command',
  create_key=_descriptor._internal_create_key,
  serialized_pb=b'\n\x1c\x61pp/log/command/config.proto\x12\x14xray.app.log.command\"\x08\n\x06\x43onfig\"\x16\n\x14RestartLoggerRequest\"\x17\n\x15RestartLoggerResponse2{\n\rLoggerService\x12j\n\rRestartLogger\x12*.xray.app.log.command.RestartLoggerRequest\x1a+.xray.app.log.command.RestartLoggerResponse\"\x00\x42^\n\x18\x63om.xray.app.log.commandP\x01Z)github.com/xtls/xray-core/app/log/command\xaa\x02\x14Xray.App.Log.Commandb\x06proto3'
)




_CONFIG = _descriptor.Descriptor(
  name='Config',
  full_name='xray.app.log.command.Config',
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
  serialized_start=54,
  serialized_end=62,
)


_RESTARTLOGGERREQUEST = _descriptor.Descriptor(
  name='RestartLoggerRequest',
  full_name='xray.app.log.command.RestartLoggerRequest',
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
  serialized_start=64,
  serialized_end=86,
)


_RESTARTLOGGERRESPONSE = _descriptor.Descriptor(
  name='RestartLoggerResponse',
  full_name='xray.app.log.command.RestartLoggerResponse',
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
  serialized_start=88,
  serialized_end=111,
)

DESCRIPTOR.message_types_by_name['Config'] = _CONFIG
DESCRIPTOR.message_types_by_name['RestartLoggerRequest'] = _RESTARTLOGGERREQUEST
DESCRIPTOR.message_types_by_name['RestartLoggerResponse'] = _RESTARTLOGGERRESPONSE
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

Config = _reflection.GeneratedProtocolMessageType('Config', (_message.Message,), {
  'DESCRIPTOR' : _CONFIG,
  '__module__' : 'app.log.command.config_pb2'
  # @@protoc_insertion_point(class_scope:xray.app.log.command.Config)
  })
_sym_db.RegisterMessage(Config)

RestartLoggerRequest = _reflection.GeneratedProtocolMessageType('RestartLoggerRequest', (_message.Message,), {
  'DESCRIPTOR' : _RESTARTLOGGERREQUEST,
  '__module__' : 'app.log.command.config_pb2'
  # @@protoc_insertion_point(class_scope:xray.app.log.command.RestartLoggerRequest)
  })
_sym_db.RegisterMessage(RestartLoggerRequest)

RestartLoggerResponse = _reflection.GeneratedProtocolMessageType('RestartLoggerResponse', (_message.Message,), {
  'DESCRIPTOR' : _RESTARTLOGGERRESPONSE,
  '__module__' : 'app.log.command.config_pb2'
  # @@protoc_insertion_point(class_scope:xray.app.log.command.RestartLoggerResponse)
  })
_sym_db.RegisterMessage(RestartLoggerResponse)


DESCRIPTOR._options = None

_LOGGERSERVICE = _descriptor.ServiceDescriptor(
  name='LoggerService',
  full_name='xray.app.log.command.LoggerService',
  file=DESCRIPTOR,
  index=0,
  serialized_options=None,
  create_key=_descriptor._internal_create_key,
  serialized_start=113,
  serialized_end=236,
  methods=[
  _descriptor.MethodDescriptor(
    name='RestartLogger',
    full_name='xray.app.log.command.LoggerService.RestartLogger',
    index=0,
    containing_service=None,
    input_type=_RESTARTLOGGERREQUEST,
    output_type=_RESTARTLOGGERRESPONSE,
    serialized_options=None,
    create_key=_descriptor._internal_create_key,
  ),
])
_sym_db.RegisterServiceDescriptor(_LOGGERSERVICE)

DESCRIPTOR.services_by_name['LoggerService'] = _LOGGERSERVICE

# @@protoc_insertion_point(module_scope)
