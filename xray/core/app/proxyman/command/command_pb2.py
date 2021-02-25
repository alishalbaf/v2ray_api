# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: app/proxyman/command/command.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


from common.protocol import user_pb2 as common_dot_protocol_dot_user__pb2
from common.serial import typed_message_pb2 as common_dot_serial_dot_typed__message__pb2
from core import config_pb2 as core_dot_config__pb2


DESCRIPTOR = _descriptor.FileDescriptor(
  name='app/proxyman/command/command.proto',
  package='xray.app.proxyman.command',
  syntax='proto3',
  serialized_options=b'\n\035com.xray.app.proxyman.commandP\001Z.github.com/xtls/xray-core/app/proxyman/command\252\002\031Xray.App.Proxyman.Command',
  create_key=_descriptor._internal_create_key,
  serialized_pb=b'\n\"app/proxyman/command/command.proto\x12\x19xray.app.proxyman.command\x1a\x1a\x63ommon/protocol/user.proto\x1a!common/serial/typed_message.proto\x1a\x11\x63ore/config.proto\"<\n\x10\x41\x64\x64UserOperation\x12(\n\x04user\x18\x01 \x01(\x0b\x32\x1a.xray.common.protocol.User\"$\n\x13RemoveUserOperation\x12\r\n\x05\x65mail\x18\x01 \x01(\t\"E\n\x11\x41\x64\x64InboundRequest\x12\x30\n\x07inbound\x18\x01 \x01(\x0b\x32\x1f.xray.core.InboundHandlerConfig\"\x14\n\x12\x41\x64\x64InboundResponse\"#\n\x14RemoveInboundRequest\x12\x0b\n\x03tag\x18\x01 \x01(\t\"\x17\n\x15RemoveInboundResponse\"W\n\x13\x41lterInboundRequest\x12\x0b\n\x03tag\x18\x01 \x01(\t\x12\x33\n\toperation\x18\x02 \x01(\x0b\x32 .xray.common.serial.TypedMessage\"\x16\n\x14\x41lterInboundResponse\"H\n\x12\x41\x64\x64OutboundRequest\x12\x32\n\x08outbound\x18\x01 \x01(\x0b\x32 .xray.core.OutboundHandlerConfig\"\x15\n\x13\x41\x64\x64OutboundResponse\"$\n\x15RemoveOutboundRequest\x12\x0b\n\x03tag\x18\x01 \x01(\t\"\x18\n\x16RemoveOutboundResponse\"X\n\x14\x41lterOutboundRequest\x12\x0b\n\x03tag\x18\x01 \x01(\t\x12\x33\n\toperation\x18\x02 \x01(\x0b\x32 .xray.common.serial.TypedMessage\"\x17\n\x15\x41lterOutboundResponse\"\x08\n\x06\x43onfig2\xc5\x05\n\x0eHandlerService\x12k\n\nAddInbound\x12,.xray.app.proxyman.command.AddInboundRequest\x1a-.xray.app.proxyman.command.AddInboundResponse\"\x00\x12t\n\rRemoveInbound\x12/.xray.app.proxyman.command.RemoveInboundRequest\x1a\x30.xray.app.proxyman.command.RemoveInboundResponse\"\x00\x12q\n\x0c\x41lterInbound\x12..xray.app.proxyman.command.AlterInboundRequest\x1a/.xray.app.proxyman.command.AlterInboundResponse\"\x00\x12n\n\x0b\x41\x64\x64Outbound\x12-.xray.app.proxyman.command.AddOutboundRequest\x1a..xray.app.proxyman.command.AddOutboundResponse\"\x00\x12w\n\x0eRemoveOutbound\x12\x30.xray.app.proxyman.command.RemoveOutboundRequest\x1a\x31.xray.app.proxyman.command.RemoveOutboundResponse\"\x00\x12t\n\rAlterOutbound\x12/.xray.app.proxyman.command.AlterOutboundRequest\x1a\x30.xray.app.proxyman.command.AlterOutboundResponse\"\x00\x42m\n\x1d\x63om.xray.app.proxyman.commandP\x01Z.github.com/xtls/xray-core/app/proxyman/command\xaa\x02\x19Xray.App.Proxyman.Commandb\x06proto3'
  ,
  dependencies=[common_dot_protocol_dot_user__pb2.DESCRIPTOR,common_dot_serial_dot_typed__message__pb2.DESCRIPTOR,core_dot_config__pb2.DESCRIPTOR,])




_ADDUSEROPERATION = _descriptor.Descriptor(
  name='AddUserOperation',
  full_name='xray.app.proxyman.command.AddUserOperation',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='user', full_name='xray.app.proxyman.command.AddUserOperation.user', index=0,
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
  serialized_start=147,
  serialized_end=207,
)


_REMOVEUSEROPERATION = _descriptor.Descriptor(
  name='RemoveUserOperation',
  full_name='xray.app.proxyman.command.RemoveUserOperation',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='email', full_name='xray.app.proxyman.command.RemoveUserOperation.email', index=0,
      number=1, type=9, cpp_type=9, label=1,
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
  serialized_start=209,
  serialized_end=245,
)


_ADDINBOUNDREQUEST = _descriptor.Descriptor(
  name='AddInboundRequest',
  full_name='xray.app.proxyman.command.AddInboundRequest',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='inbound', full_name='xray.app.proxyman.command.AddInboundRequest.inbound', index=0,
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
  serialized_start=247,
  serialized_end=316,
)


_ADDINBOUNDRESPONSE = _descriptor.Descriptor(
  name='AddInboundResponse',
  full_name='xray.app.proxyman.command.AddInboundResponse',
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
  serialized_start=318,
  serialized_end=338,
)


_REMOVEINBOUNDREQUEST = _descriptor.Descriptor(
  name='RemoveInboundRequest',
  full_name='xray.app.proxyman.command.RemoveInboundRequest',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='tag', full_name='xray.app.proxyman.command.RemoveInboundRequest.tag', index=0,
      number=1, type=9, cpp_type=9, label=1,
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
  serialized_start=340,
  serialized_end=375,
)


_REMOVEINBOUNDRESPONSE = _descriptor.Descriptor(
  name='RemoveInboundResponse',
  full_name='xray.app.proxyman.command.RemoveInboundResponse',
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
  serialized_start=377,
  serialized_end=400,
)


_ALTERINBOUNDREQUEST = _descriptor.Descriptor(
  name='AlterInboundRequest',
  full_name='xray.app.proxyman.command.AlterInboundRequest',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='tag', full_name='xray.app.proxyman.command.AlterInboundRequest.tag', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='operation', full_name='xray.app.proxyman.command.AlterInboundRequest.operation', index=1,
      number=2, type=11, cpp_type=10, label=1,
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
  serialized_start=402,
  serialized_end=489,
)


_ALTERINBOUNDRESPONSE = _descriptor.Descriptor(
  name='AlterInboundResponse',
  full_name='xray.app.proxyman.command.AlterInboundResponse',
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
  serialized_start=491,
  serialized_end=513,
)


_ADDOUTBOUNDREQUEST = _descriptor.Descriptor(
  name='AddOutboundRequest',
  full_name='xray.app.proxyman.command.AddOutboundRequest',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='outbound', full_name='xray.app.proxyman.command.AddOutboundRequest.outbound', index=0,
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
  serialized_start=515,
  serialized_end=587,
)


_ADDOUTBOUNDRESPONSE = _descriptor.Descriptor(
  name='AddOutboundResponse',
  full_name='xray.app.proxyman.command.AddOutboundResponse',
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
  serialized_start=589,
  serialized_end=610,
)


_REMOVEOUTBOUNDREQUEST = _descriptor.Descriptor(
  name='RemoveOutboundRequest',
  full_name='xray.app.proxyman.command.RemoveOutboundRequest',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='tag', full_name='xray.app.proxyman.command.RemoveOutboundRequest.tag', index=0,
      number=1, type=9, cpp_type=9, label=1,
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
  serialized_start=612,
  serialized_end=648,
)


_REMOVEOUTBOUNDRESPONSE = _descriptor.Descriptor(
  name='RemoveOutboundResponse',
  full_name='xray.app.proxyman.command.RemoveOutboundResponse',
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
  serialized_start=650,
  serialized_end=674,
)


_ALTEROUTBOUNDREQUEST = _descriptor.Descriptor(
  name='AlterOutboundRequest',
  full_name='xray.app.proxyman.command.AlterOutboundRequest',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='tag', full_name='xray.app.proxyman.command.AlterOutboundRequest.tag', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='operation', full_name='xray.app.proxyman.command.AlterOutboundRequest.operation', index=1,
      number=2, type=11, cpp_type=10, label=1,
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
  serialized_start=676,
  serialized_end=764,
)


_ALTEROUTBOUNDRESPONSE = _descriptor.Descriptor(
  name='AlterOutboundResponse',
  full_name='xray.app.proxyman.command.AlterOutboundResponse',
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
  serialized_start=766,
  serialized_end=789,
)


_CONFIG = _descriptor.Descriptor(
  name='Config',
  full_name='xray.app.proxyman.command.Config',
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
  serialized_start=791,
  serialized_end=799,
)

_ADDUSEROPERATION.fields_by_name['user'].message_type = common_dot_protocol_dot_user__pb2._USER
_ADDINBOUNDREQUEST.fields_by_name['inbound'].message_type = core_dot_config__pb2._INBOUNDHANDLERCONFIG
_ALTERINBOUNDREQUEST.fields_by_name['operation'].message_type = common_dot_serial_dot_typed__message__pb2._TYPEDMESSAGE
_ADDOUTBOUNDREQUEST.fields_by_name['outbound'].message_type = core_dot_config__pb2._OUTBOUNDHANDLERCONFIG
_ALTEROUTBOUNDREQUEST.fields_by_name['operation'].message_type = common_dot_serial_dot_typed__message__pb2._TYPEDMESSAGE
DESCRIPTOR.message_types_by_name['AddUserOperation'] = _ADDUSEROPERATION
DESCRIPTOR.message_types_by_name['RemoveUserOperation'] = _REMOVEUSEROPERATION
DESCRIPTOR.message_types_by_name['AddInboundRequest'] = _ADDINBOUNDREQUEST
DESCRIPTOR.message_types_by_name['AddInboundResponse'] = _ADDINBOUNDRESPONSE
DESCRIPTOR.message_types_by_name['RemoveInboundRequest'] = _REMOVEINBOUNDREQUEST
DESCRIPTOR.message_types_by_name['RemoveInboundResponse'] = _REMOVEINBOUNDRESPONSE
DESCRIPTOR.message_types_by_name['AlterInboundRequest'] = _ALTERINBOUNDREQUEST
DESCRIPTOR.message_types_by_name['AlterInboundResponse'] = _ALTERINBOUNDRESPONSE
DESCRIPTOR.message_types_by_name['AddOutboundRequest'] = _ADDOUTBOUNDREQUEST
DESCRIPTOR.message_types_by_name['AddOutboundResponse'] = _ADDOUTBOUNDRESPONSE
DESCRIPTOR.message_types_by_name['RemoveOutboundRequest'] = _REMOVEOUTBOUNDREQUEST
DESCRIPTOR.message_types_by_name['RemoveOutboundResponse'] = _REMOVEOUTBOUNDRESPONSE
DESCRIPTOR.message_types_by_name['AlterOutboundRequest'] = _ALTEROUTBOUNDREQUEST
DESCRIPTOR.message_types_by_name['AlterOutboundResponse'] = _ALTEROUTBOUNDRESPONSE
DESCRIPTOR.message_types_by_name['Config'] = _CONFIG
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

AddUserOperation = _reflection.GeneratedProtocolMessageType('AddUserOperation', (_message.Message,), {
  'DESCRIPTOR' : _ADDUSEROPERATION,
  '__module__' : 'app.proxyman.command.command_pb2'
  # @@protoc_insertion_point(class_scope:xray.app.proxyman.command.AddUserOperation)
  })
_sym_db.RegisterMessage(AddUserOperation)

RemoveUserOperation = _reflection.GeneratedProtocolMessageType('RemoveUserOperation', (_message.Message,), {
  'DESCRIPTOR' : _REMOVEUSEROPERATION,
  '__module__' : 'app.proxyman.command.command_pb2'
  # @@protoc_insertion_point(class_scope:xray.app.proxyman.command.RemoveUserOperation)
  })
_sym_db.RegisterMessage(RemoveUserOperation)

AddInboundRequest = _reflection.GeneratedProtocolMessageType('AddInboundRequest', (_message.Message,), {
  'DESCRIPTOR' : _ADDINBOUNDREQUEST,
  '__module__' : 'app.proxyman.command.command_pb2'
  # @@protoc_insertion_point(class_scope:xray.app.proxyman.command.AddInboundRequest)
  })
_sym_db.RegisterMessage(AddInboundRequest)

AddInboundResponse = _reflection.GeneratedProtocolMessageType('AddInboundResponse', (_message.Message,), {
  'DESCRIPTOR' : _ADDINBOUNDRESPONSE,
  '__module__' : 'app.proxyman.command.command_pb2'
  # @@protoc_insertion_point(class_scope:xray.app.proxyman.command.AddInboundResponse)
  })
_sym_db.RegisterMessage(AddInboundResponse)

RemoveInboundRequest = _reflection.GeneratedProtocolMessageType('RemoveInboundRequest', (_message.Message,), {
  'DESCRIPTOR' : _REMOVEINBOUNDREQUEST,
  '__module__' : 'app.proxyman.command.command_pb2'
  # @@protoc_insertion_point(class_scope:xray.app.proxyman.command.RemoveInboundRequest)
  })
_sym_db.RegisterMessage(RemoveInboundRequest)

RemoveInboundResponse = _reflection.GeneratedProtocolMessageType('RemoveInboundResponse', (_message.Message,), {
  'DESCRIPTOR' : _REMOVEINBOUNDRESPONSE,
  '__module__' : 'app.proxyman.command.command_pb2'
  # @@protoc_insertion_point(class_scope:xray.app.proxyman.command.RemoveInboundResponse)
  })
_sym_db.RegisterMessage(RemoveInboundResponse)

AlterInboundRequest = _reflection.GeneratedProtocolMessageType('AlterInboundRequest', (_message.Message,), {
  'DESCRIPTOR' : _ALTERINBOUNDREQUEST,
  '__module__' : 'app.proxyman.command.command_pb2'
  # @@protoc_insertion_point(class_scope:xray.app.proxyman.command.AlterInboundRequest)
  })
_sym_db.RegisterMessage(AlterInboundRequest)

AlterInboundResponse = _reflection.GeneratedProtocolMessageType('AlterInboundResponse', (_message.Message,), {
  'DESCRIPTOR' : _ALTERINBOUNDRESPONSE,
  '__module__' : 'app.proxyman.command.command_pb2'
  # @@protoc_insertion_point(class_scope:xray.app.proxyman.command.AlterInboundResponse)
  })
_sym_db.RegisterMessage(AlterInboundResponse)

AddOutboundRequest = _reflection.GeneratedProtocolMessageType('AddOutboundRequest', (_message.Message,), {
  'DESCRIPTOR' : _ADDOUTBOUNDREQUEST,
  '__module__' : 'app.proxyman.command.command_pb2'
  # @@protoc_insertion_point(class_scope:xray.app.proxyman.command.AddOutboundRequest)
  })
_sym_db.RegisterMessage(AddOutboundRequest)

AddOutboundResponse = _reflection.GeneratedProtocolMessageType('AddOutboundResponse', (_message.Message,), {
  'DESCRIPTOR' : _ADDOUTBOUNDRESPONSE,
  '__module__' : 'app.proxyman.command.command_pb2'
  # @@protoc_insertion_point(class_scope:xray.app.proxyman.command.AddOutboundResponse)
  })
_sym_db.RegisterMessage(AddOutboundResponse)

RemoveOutboundRequest = _reflection.GeneratedProtocolMessageType('RemoveOutboundRequest', (_message.Message,), {
  'DESCRIPTOR' : _REMOVEOUTBOUNDREQUEST,
  '__module__' : 'app.proxyman.command.command_pb2'
  # @@protoc_insertion_point(class_scope:xray.app.proxyman.command.RemoveOutboundRequest)
  })
_sym_db.RegisterMessage(RemoveOutboundRequest)

RemoveOutboundResponse = _reflection.GeneratedProtocolMessageType('RemoveOutboundResponse', (_message.Message,), {
  'DESCRIPTOR' : _REMOVEOUTBOUNDRESPONSE,
  '__module__' : 'app.proxyman.command.command_pb2'
  # @@protoc_insertion_point(class_scope:xray.app.proxyman.command.RemoveOutboundResponse)
  })
_sym_db.RegisterMessage(RemoveOutboundResponse)

AlterOutboundRequest = _reflection.GeneratedProtocolMessageType('AlterOutboundRequest', (_message.Message,), {
  'DESCRIPTOR' : _ALTEROUTBOUNDREQUEST,
  '__module__' : 'app.proxyman.command.command_pb2'
  # @@protoc_insertion_point(class_scope:xray.app.proxyman.command.AlterOutboundRequest)
  })
_sym_db.RegisterMessage(AlterOutboundRequest)

AlterOutboundResponse = _reflection.GeneratedProtocolMessageType('AlterOutboundResponse', (_message.Message,), {
  'DESCRIPTOR' : _ALTEROUTBOUNDRESPONSE,
  '__module__' : 'app.proxyman.command.command_pb2'
  # @@protoc_insertion_point(class_scope:xray.app.proxyman.command.AlterOutboundResponse)
  })
_sym_db.RegisterMessage(AlterOutboundResponse)

Config = _reflection.GeneratedProtocolMessageType('Config', (_message.Message,), {
  'DESCRIPTOR' : _CONFIG,
  '__module__' : 'app.proxyman.command.command_pb2'
  # @@protoc_insertion_point(class_scope:xray.app.proxyman.command.Config)
  })
_sym_db.RegisterMessage(Config)


DESCRIPTOR._options = None

_HANDLERSERVICE = _descriptor.ServiceDescriptor(
  name='HandlerService',
  full_name='xray.app.proxyman.command.HandlerService',
  file=DESCRIPTOR,
  index=0,
  serialized_options=None,
  create_key=_descriptor._internal_create_key,
  serialized_start=802,
  serialized_end=1511,
  methods=[
  _descriptor.MethodDescriptor(
    name='AddInbound',
    full_name='xray.app.proxyman.command.HandlerService.AddInbound',
    index=0,
    containing_service=None,
    input_type=_ADDINBOUNDREQUEST,
    output_type=_ADDINBOUNDRESPONSE,
    serialized_options=None,
    create_key=_descriptor._internal_create_key,
  ),
  _descriptor.MethodDescriptor(
    name='RemoveInbound',
    full_name='xray.app.proxyman.command.HandlerService.RemoveInbound',
    index=1,
    containing_service=None,
    input_type=_REMOVEINBOUNDREQUEST,
    output_type=_REMOVEINBOUNDRESPONSE,
    serialized_options=None,
    create_key=_descriptor._internal_create_key,
  ),
  _descriptor.MethodDescriptor(
    name='AlterInbound',
    full_name='xray.app.proxyman.command.HandlerService.AlterInbound',
    index=2,
    containing_service=None,
    input_type=_ALTERINBOUNDREQUEST,
    output_type=_ALTERINBOUNDRESPONSE,
    serialized_options=None,
    create_key=_descriptor._internal_create_key,
  ),
  _descriptor.MethodDescriptor(
    name='AddOutbound',
    full_name='xray.app.proxyman.command.HandlerService.AddOutbound',
    index=3,
    containing_service=None,
    input_type=_ADDOUTBOUNDREQUEST,
    output_type=_ADDOUTBOUNDRESPONSE,
    serialized_options=None,
    create_key=_descriptor._internal_create_key,
  ),
  _descriptor.MethodDescriptor(
    name='RemoveOutbound',
    full_name='xray.app.proxyman.command.HandlerService.RemoveOutbound',
    index=4,
    containing_service=None,
    input_type=_REMOVEOUTBOUNDREQUEST,
    output_type=_REMOVEOUTBOUNDRESPONSE,
    serialized_options=None,
    create_key=_descriptor._internal_create_key,
  ),
  _descriptor.MethodDescriptor(
    name='AlterOutbound',
    full_name='xray.app.proxyman.command.HandlerService.AlterOutbound',
    index=5,
    containing_service=None,
    input_type=_ALTEROUTBOUNDREQUEST,
    output_type=_ALTEROUTBOUNDRESPONSE,
    serialized_options=None,
    create_key=_descriptor._internal_create_key,
  ),
])
_sym_db.RegisterServiceDescriptor(_HANDLERSERVICE)

DESCRIPTOR.services_by_name['HandlerService'] = _HANDLERSERVICE

# @@protoc_insertion_point(module_scope)