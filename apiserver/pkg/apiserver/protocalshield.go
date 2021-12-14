// Copyright (c) 2021 Tigera, Inc. All rights reserved.

package apiserver

import (
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
)

// protocolShieldSerializer filters out media types that the apiserver doesn't accept.
type protocolShieldSerializer struct {
	*serializer.CodecFactory
	accepts []runtime.SerializerInfo
}

func newProtocolShieldSerializer(codecs *serializer.CodecFactory) *protocolShieldSerializer {
	if codecs == nil {
		return nil
	}
	pss := &protocolShieldSerializer{
		CodecFactory: codecs,
		accepts:      []runtime.SerializerInfo{},
	}
	for _, info := range codecs.SupportedMediaTypes() {
		// Calico apiserver supports JSON and YAML (server-side apply) media types.
		if (info.MediaType == runtime.ContentTypeJSON) || (info.MediaType == runtime.ContentTypeYAML) {
			pss.accepts = append(pss.accepts, info)
		}
	}
	return pss
}

func (pss *protocolShieldSerializer) SupportedMediaTypes() []runtime.SerializerInfo {
	if pss == nil {
		return nil
	}
	return pss.accepts
}

func (pss *protocolShieldSerializer) EncoderForVersion(encoder runtime.Encoder, gv runtime.GroupVersioner) runtime.Encoder {
	if pss == nil {
		return nil
	}
	return pss.CodecFactory.CodecForVersions(encoder, nil, gv, nil)
}
func (pss *protocolShieldSerializer) DecoderToVersion(decoder runtime.Decoder, gv runtime.GroupVersioner) runtime.Decoder {
	if pss == nil {
		return nil
	}
	return pss.CodecFactory.CodecForVersions(nil, decoder, nil, gv)
}
