// auth.proto

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.5
// 	protoc        v5.29.3
// source: douyin-shop/path/auth.proto

package path

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
	unsafe "unsafe"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type DeliverTokenReq struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	UserId        string                 `protobuf:"bytes,1,opt,name=user_id,json=userId,proto3" json:"user_id,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *DeliverTokenReq) Reset() {
	*x = DeliverTokenReq{}
	mi := &file_douyin_shop_path_auth_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *DeliverTokenReq) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DeliverTokenReq) ProtoMessage() {}

func (x *DeliverTokenReq) ProtoReflect() protoreflect.Message {
	mi := &file_douyin_shop_path_auth_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DeliverTokenReq.ProtoReflect.Descriptor instead.
func (*DeliverTokenReq) Descriptor() ([]byte, []int) {
	return file_douyin_shop_path_auth_proto_rawDescGZIP(), []int{0}
}

func (x *DeliverTokenReq) GetUserId() string {
	if x != nil {
		return x.UserId
	}
	return ""
}

type DeliveryResp struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Token         string                 `protobuf:"bytes,1,opt,name=token,proto3" json:"token,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *DeliveryResp) Reset() {
	*x = DeliveryResp{}
	mi := &file_douyin_shop_path_auth_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *DeliveryResp) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DeliveryResp) ProtoMessage() {}

func (x *DeliveryResp) ProtoReflect() protoreflect.Message {
	mi := &file_douyin_shop_path_auth_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DeliveryResp.ProtoReflect.Descriptor instead.
func (*DeliveryResp) Descriptor() ([]byte, []int) {
	return file_douyin_shop_path_auth_proto_rawDescGZIP(), []int{1}
}

func (x *DeliveryResp) GetToken() string {
	if x != nil {
		return x.Token
	}
	return ""
}

type VerifyTokenReq struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Token         string                 `protobuf:"bytes,1,opt,name=token,proto3" json:"token,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *VerifyTokenReq) Reset() {
	*x = VerifyTokenReq{}
	mi := &file_douyin_shop_path_auth_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *VerifyTokenReq) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*VerifyTokenReq) ProtoMessage() {}

func (x *VerifyTokenReq) ProtoReflect() protoreflect.Message {
	mi := &file_douyin_shop_path_auth_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use VerifyTokenReq.ProtoReflect.Descriptor instead.
func (*VerifyTokenReq) Descriptor() ([]byte, []int) {
	return file_douyin_shop_path_auth_proto_rawDescGZIP(), []int{2}
}

func (x *VerifyTokenReq) GetToken() string {
	if x != nil {
		return x.Token
	}
	return ""
}

type VerifyResp struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Res           bool                   `protobuf:"varint,1,opt,name=res,proto3" json:"res,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *VerifyResp) Reset() {
	*x = VerifyResp{}
	mi := &file_douyin_shop_path_auth_proto_msgTypes[3]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *VerifyResp) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*VerifyResp) ProtoMessage() {}

func (x *VerifyResp) ProtoReflect() protoreflect.Message {
	mi := &file_douyin_shop_path_auth_proto_msgTypes[3]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use VerifyResp.ProtoReflect.Descriptor instead.
func (*VerifyResp) Descriptor() ([]byte, []int) {
	return file_douyin_shop_path_auth_proto_rawDescGZIP(), []int{3}
}

func (x *VerifyResp) GetRes() bool {
	if x != nil {
		return x.Res
	}
	return false
}

var File_douyin_shop_path_auth_proto protoreflect.FileDescriptor

var file_douyin_shop_path_auth_proto_rawDesc = string([]byte{
	0x0a, 0x1b, 0x64, 0x6f, 0x75, 0x79, 0x69, 0x6e, 0x2d, 0x73, 0x68, 0x6f, 0x70, 0x2f, 0x70, 0x61,
	0x74, 0x68, 0x2f, 0x61, 0x75, 0x74, 0x68, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x04, 0x61,
	0x75, 0x74, 0x68, 0x22, 0x2a, 0x0a, 0x0f, 0x44, 0x65, 0x6c, 0x69, 0x76, 0x65, 0x72, 0x54, 0x6f,
	0x6b, 0x65, 0x6e, 0x52, 0x65, 0x71, 0x12, 0x17, 0x0a, 0x07, 0x75, 0x73, 0x65, 0x72, 0x5f, 0x69,
	0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x75, 0x73, 0x65, 0x72, 0x49, 0x64, 0x22,
	0x24, 0x0a, 0x0c, 0x44, 0x65, 0x6c, 0x69, 0x76, 0x65, 0x72, 0x79, 0x52, 0x65, 0x73, 0x70, 0x12,
	0x14, 0x0a, 0x05, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05,
	0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x22, 0x26, 0x0a, 0x0e, 0x56, 0x65, 0x72, 0x69, 0x66, 0x79, 0x54,
	0x6f, 0x6b, 0x65, 0x6e, 0x52, 0x65, 0x71, 0x12, 0x14, 0x0a, 0x05, 0x74, 0x6f, 0x6b, 0x65, 0x6e,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x22, 0x1e, 0x0a,
	0x0a, 0x56, 0x65, 0x72, 0x69, 0x66, 0x79, 0x52, 0x65, 0x73, 0x70, 0x12, 0x10, 0x0a, 0x03, 0x72,
	0x65, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x08, 0x52, 0x03, 0x72, 0x65, 0x73, 0x32, 0x89, 0x01,
	0x0a, 0x0b, 0x41, 0x75, 0x74, 0x68, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x3e, 0x0a,
	0x11, 0x44, 0x65, 0x6c, 0x69, 0x76, 0x65, 0x72, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x42, 0x79, 0x52,
	0x50, 0x43, 0x12, 0x15, 0x2e, 0x61, 0x75, 0x74, 0x68, 0x2e, 0x44, 0x65, 0x6c, 0x69, 0x76, 0x65,
	0x72, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x52, 0x65, 0x71, 0x1a, 0x12, 0x2e, 0x61, 0x75, 0x74, 0x68,
	0x2e, 0x44, 0x65, 0x6c, 0x69, 0x76, 0x65, 0x72, 0x79, 0x52, 0x65, 0x73, 0x70, 0x12, 0x3a, 0x0a,
	0x10, 0x56, 0x65, 0x72, 0x69, 0x66, 0x79, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x42, 0x79, 0x52, 0x50,
	0x43, 0x12, 0x14, 0x2e, 0x61, 0x75, 0x74, 0x68, 0x2e, 0x56, 0x65, 0x72, 0x69, 0x66, 0x79, 0x54,
	0x6f, 0x6b, 0x65, 0x6e, 0x52, 0x65, 0x71, 0x1a, 0x10, 0x2e, 0x61, 0x75, 0x74, 0x68, 0x2e, 0x56,
	0x65, 0x72, 0x69, 0x66, 0x79, 0x52, 0x65, 0x73, 0x70, 0x42, 0x12, 0x5a, 0x10, 0x64, 0x6f, 0x75,
	0x79, 0x69, 0x6e, 0x2d, 0x73, 0x68, 0x6f, 0x70, 0x2f, 0x70, 0x61, 0x74, 0x68, 0x62, 0x06, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x33,
})

var (
	file_douyin_shop_path_auth_proto_rawDescOnce sync.Once
	file_douyin_shop_path_auth_proto_rawDescData []byte
)

func file_douyin_shop_path_auth_proto_rawDescGZIP() []byte {
	file_douyin_shop_path_auth_proto_rawDescOnce.Do(func() {
		file_douyin_shop_path_auth_proto_rawDescData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(file_douyin_shop_path_auth_proto_rawDesc), len(file_douyin_shop_path_auth_proto_rawDesc)))
	})
	return file_douyin_shop_path_auth_proto_rawDescData
}

var file_douyin_shop_path_auth_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
var file_douyin_shop_path_auth_proto_goTypes = []any{
	(*DeliverTokenReq)(nil), // 0: auth.DeliverTokenReq
	(*DeliveryResp)(nil),    // 1: auth.DeliveryResp
	(*VerifyTokenReq)(nil),  // 2: auth.VerifyTokenReq
	(*VerifyResp)(nil),      // 3: auth.VerifyResp
}
var file_douyin_shop_path_auth_proto_depIdxs = []int32{
	0, // 0: auth.AuthService.DeliverTokenByRPC:input_type -> auth.DeliverTokenReq
	2, // 1: auth.AuthService.VerifyTokenByRPC:input_type -> auth.VerifyTokenReq
	1, // 2: auth.AuthService.DeliverTokenByRPC:output_type -> auth.DeliveryResp
	3, // 3: auth.AuthService.VerifyTokenByRPC:output_type -> auth.VerifyResp
	2, // [2:4] is the sub-list for method output_type
	0, // [0:2] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_douyin_shop_path_auth_proto_init() }
func file_douyin_shop_path_auth_proto_init() {
	if File_douyin_shop_path_auth_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_douyin_shop_path_auth_proto_rawDesc), len(file_douyin_shop_path_auth_proto_rawDesc)),
			NumEnums:      0,
			NumMessages:   4,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_douyin_shop_path_auth_proto_goTypes,
		DependencyIndexes: file_douyin_shop_path_auth_proto_depIdxs,
		MessageInfos:      file_douyin_shop_path_auth_proto_msgTypes,
	}.Build()
	File_douyin_shop_path_auth_proto = out.File
	file_douyin_shop_path_auth_proto_goTypes = nil
	file_douyin_shop_path_auth_proto_depIdxs = nil
}
