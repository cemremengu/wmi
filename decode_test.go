package wmi

import (
	"context"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseQualifierSet(t *testing.T) {
	heap := append(encodedStringTest("description"), encodedStringTest("hello")...)
	body := make([]byte, 0, 32)

	tmp := make([]byte, 9)
	binary.LittleEndian.PutUint32(tmp[0:4], 0x80000000|1)
	tmp[4] = 0x10
	binary.LittleEndian.PutUint32(tmp[5:9], cimTypeBoolean)
	body = append(body, tmp...)
	body = append(body, 0xff, 0xff)

	nameOff := uint32(0)
	valueOff := mustUint32(len(encodedStringTest("description")))
	binary.LittleEndian.PutUint32(tmp[0:4], nameOff)
	tmp[4] = 0x20
	binary.LittleEndian.PutUint32(tmp[5:9], cimTypeString)
	body = append(body, tmp...)
	ref := make([]byte, 4)
	binary.LittleEndian.PutUint32(ref, valueOff)
	body = append(body, ref...)

	packet := make([]byte, 4+len(body))
	binary.LittleEndian.PutUint32(packet[:4], mustUint32(len(packet)))
	copy(packet[4:], body)

	quals, next, err := parseQualifierSet(packet, 0, heap)
	require.NoError(t, err)
	require.Equal(t, len(packet), next, "unexpected next offset")
	require.Len(t, quals, 2, "unexpected qualifier count")
	require.Equal(t, "key", quals[0].Name)
	require.Equal(t, true, quals[0].Value)
	require.Equal(t, "description", quals[1].Name)
	require.Equal(t, "hello", quals[1].Value)
}

func TestResolvePropertyDefsLoadsQualifiers(t *testing.T) {
	name := encodedStringTest("Caption")
	qbody := make([]byte, 0, 16)
	tmp := make([]byte, 9)
	binary.LittleEndian.PutUint32(tmp[0:4], 0x80000000|10)
	tmp[4] = 1
	binary.LittleEndian.PutUint32(tmp[5:9], cimTypeString)
	qbody = append(qbody, tmp...)
	valueRefPos := len(qbody)
	qbody = append(qbody, 0, 0, 0, 0)

	heap := append([]byte{}, name...)
	infoRef := mustUint32(len(heap))
	info := make([]byte, 14)
	binary.LittleEndian.PutUint16(info[0:2], cimTypeString)
	binary.LittleEndian.PutUint16(info[4:6], 7)
	heap = append(heap, info...)

	qset := make([]byte, 4+len(qbody))
	binary.LittleEndian.PutUint32(qset[:4], mustUint32(len(qset)))
	copy(qset[4:], qbody)
	heap = append(heap, qset...)
	valueOff := mustUint32(len(heap))
	binary.LittleEndian.PutUint32(heap[int(infoRef)+14+4+valueRefPos:], valueOff)
	heap = append(heap, encodedStringTest("text")...)

	defs := []*propertyDef{{nameRef: 0, infoRef: infoRef}}
	resolvePropertyDefs(defs, heap)

	require.Equal(t, "Caption", defs[0].Name)
	require.EqualValues(t, 7, defs[0].Order)
	require.EqualValues(t, cimTypeString, defs[0].Type)
	require.Len(t, defs[0].Qualifiers, 1, "unexpected qualifier count")
	require.Equal(t, "CIMTYPE", defs[0].Qualifiers[0].Name)
	require.Equal(t, "text", defs[0].Qualifiers[0].Value)
}

func TestParseObjectBlockEdgeCases(t *testing.T) {
	_, _, err := parseObjectBlock([]byte{0x1}, 0, nil)
	require.ErrorIs(t, err, ErrLegacyEncoding)

	cp := &classPart{defs: []*propertyDef{{Name: "Prop"}}, ndValueTableLength: 0}
	data := append([]byte{0x00}, make([]byte, 9)...)
	data = append(data, 0x04, 0x00, 0x00, 0x00)
	data = append(data, 0x02)
	data = append(data, 0x04, 0x00, 0x00, 0x00)
	data = append(data, 0x00, 0x00, 0x00, 0x00)
	obj, next, err := parseObjectBlock(data, 0, cp)
	require.NoError(t, err)
	require.NotNil(t, obj)
	require.Equal(t, len(data), next)
}

func TestObjectPropertiesOptions(t *testing.T) {
	obj := &objectBlock{
		classPart: &classPart{
			defs: []*propertyDef{{
				Name:  "Answer",
				Type:  cimTypeUInt32,
				Order: 0,
				Qualifiers: []Qualifier{{
					Name:  "key",
					Type:  cimTypeBoolean,
					Value: true,
				}},
			}},
			ndValueTableLength: 1,
			ndValueTable:       []byte{0, 0, 0, 0, 0},
		},
		ndValueTable: []byte{0, 42, 0, 0, 0},
	}

	props, err := obj.properties(false, false, true)
	require.NoError(t, err)
	require.Len(t, props["Answer"].Qualifiers, 1, "expected qualifiers to be loaded")
	value, ok := props["Answer"].Value.(uint32)
	require.True(t, ok && value == 42, "unexpected property value: %#v", props["Answer"].Value)

	props, err = obj.properties(false, false, false)
	require.NoError(t, err)
	require.Empty(t, props["Answer"].Qualifiers, "expected qualifiers to be skipped")

	obj.ndValueTable = []byte{0, 0, 0, 0, 0}
	props, err = obj.properties(true, false, false)
	require.NoError(t, err)
	require.Nil(t, props["Answer"].Value, "expected missing value to remain nil when defaults are ignored")

	props, err = obj.properties(false, true, false)
	require.NoError(t, err)
	_, ok = props["Answer"]
	require.False(t, ok, "expected missing property to be removed when ignoreMissing is enabled")
}

func TestGetArrayReferencesRejectsNonArrayReference(t *testing.T) {
	prop := &Property{
		Name:  "Parent",
		Type:  cimTypeReference,
		Value: "Win32_Process.Handle=\"1\"",
	}
	_, err := prop.GetArrayReferences(context.Background(), nil, nil, false)
	require.Error(t, err)
	require.True(
		t,
		strings.Contains(err.Error(), "not an array of references"),
		"expected array reference validation error, got %v",
		err,
	)
}

func encodedStringTest(s string) []byte {
	return append(append([]byte{0}, []byte(s)...), 0)
}
