package wmi

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
)

// Property represents a single WMI property with its name, type, and decoded value.
type Property struct {
	Name             string
	Type             uint16
	Order            uint16
	Value            any
	Qualifiers       []Qualifier
	NullDefault      bool
	InheritedDefault bool
}

// Qualifier represents a CIM qualifier attached to a property or class.
type Qualifier struct {
	Name   string
	Flavor byte
	Type   uint32
	Value  any
}

// CIMTypeName returns the human-readable CIM type name for the property.
func (p *Property) CIMTypeName() string {
	switch p.baseType() {
	case cimTypeSInt8:
		return "sint8"
	case cimTypeUInt8:
		return "uint8"
	case cimTypeSInt16:
		return "sint16"
	case cimTypeUInt16:
		return "uint16"
	case cimTypeSInt32:
		return "sint32"
	case cimTypeUInt32:
		return "uint32"
	case cimTypeSInt64:
		return "sint64"
	case cimTypeUInt64:
		return "uint64"
	case cimTypeReal32:
		return "real32"
	case cimTypeReal64:
		return "real64"
	case cimTypeBoolean:
		return "bool"
	case cimTypeString:
		return "string"
	case cimTypeDateTime:
		return "datetime"
	case cimTypeReference:
		return "reference"
	case cimTypeChar16:
		return "char16"
	case cimTypeObject:
		return "object"
	default:
		return "unknown"
	}
}

// IsArray reports whether the property holds an array value.
func (p *Property) IsArray() bool { return p.Type&cimArrayFlag != 0 }

// IsReference reports whether the property is a CIM reference.
func (p *Property) IsReference() bool { return p.baseType() == cimTypeReference }

// IsArrayReference reports whether the property is an array of CIM references.
func (p *Property) IsArrayReference() bool { return p.IsArray() && p.baseType() == cimTypeReference }

func (p *Property) baseType() uint16 { return p.Type &^ (cimArrayFlag | cimInheritedFlag) }

// GetReference resolves a single reference property and returns the referenced object's properties.
func (p *Property) GetReference(
	ctx context.Context,
	conn *Connection,
	service *Service,
	filterProps []string,
) (map[string]*Property, error) {
	value, ok := p.Value.(string)
	if !ok {
		return nil, fmt.Errorf("property %s is not a reference", p.Name)
	}
	return p.getReference(ctx, conn, service, value, filterProps)
}

// GetArrayReferences resolves each element of an array-of-references property.
func (p *Property) GetArrayReferences(
	ctx context.Context,
	conn *Connection,
	service *Service,
	filterProps []string,
	missingAsNil bool,
) ([]map[string]*Property, error) {
	values, ok := p.Value.([]any)
	if !ok || !p.IsArrayReference() {
		return nil, fmt.Errorf("property %s is not an array of references", p.Name)
	}
	refs := make([]map[string]*Property, 0, len(values))
	for _, item := range values {
		value, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("property %s contains a non-string reference value", p.Name)
		}
		props, err := p.getReference(ctx, conn, service, value, filterProps)
		if err != nil {
			if missingAsNil && isErrorCode(err, wbemSFalse) {
				refs = append(refs, nil)
				continue
			}
			return nil, err
		}
		refs = append(refs, props)
	}
	return refs, nil
}

func (p *Property) getReference(
	ctx context.Context,
	conn *Connection,
	service *Service,
	value string,
	filterProps []string,
) (map[string]*Property, error) {
	i := strings.IndexByte(value, ':')
	if i < 0 {
		return nil, fmt.Errorf("invalid reference %q", value)
	}
	value = value[i+1:]
	parts := strings.SplitN(value, ".", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid reference %q", value)
	}
	props := "*"
	if len(filterProps) > 0 {
		props = strings.Join(filterProps, ", ")
	}
	query := NewQuery(
		fmt.Sprintf("SELECT %s FROM %s WHERE %s", props, parts[0], strings.Join(strings.Split(parts[1], ","), " AND ")),
	)
	rows, err := query.Context(conn, service).Collect(ctx)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	return rows[0], nil
}

type propertyDef struct {
	nameRef    uint32
	infoRef    uint32
	Name       string
	Type       uint16
	Order      uint16
	Qualifiers []Qualifier
}

type classPart struct {
	ndValueTableLength uint32
	ndValueTable       []byte
	classHeap          []byte
	defs               []*propertyDef
}

type objectBlock struct {
	classPart    *classPart
	ndValueTable []byte
	instanceHeap []byte
}

func parseSmartResponse(data []byte, classParts map[string]*classPart) (*objectBlock, error) {
	offset, err := parseORPCTHAT(data)
	if err != nil {
		return nil, err
	}
	if offset+20 > len(data) {
		return nil, errors.New("short smart response")
	}
	offset += 20
	if offset+8 > len(data) || string(data[offset:offset+8]) != "WBEMDATA" {
		return nil, errors.New("invalid WBEMDATA packet")
	}
	offset += 8
	if offset+34 > len(data) {
		return nil, errors.New("short smart response header")
	}
	offset += 34
	obj, _, err := parseWbemDatapacketObject(data, offset, classParts)
	return obj, err
}

func parseNextBigResponse(data []byte) (*objectBlock, error) {
	offset, err := parseORPCTHAT(data)
	if err != nil {
		return nil, err
	}
	if offset+12 > len(data) {
		return nil, errors.New("short next response")
	}
	nCount := int(binary.LittleEndian.Uint32(data[offset:]))
	offset += 12
	var obj *objectBlock
	for range nCount {
		if offset+12 > len(data) {
			return nil, errors.New("short varying array")
		}
		ndata := int(binary.LittleEndian.Uint32(data[offset+4:]))
		offset += 12
		_, custom, err := parseObjRef(data, offset, ndata)
		if err != nil {
			return nil, err
		}
		offset += ndata + pad4(ndata)
		if len(custom.objectData) < 8 {
			return nil, errors.New("short encoding unit")
		}
		obj, _, err = parseObjectBlock(custom.objectData, 8, nil)
		if err != nil {
			return nil, err
		}
	}
	if obj == nil {
		return nil, wbemError(wbemSFalse)
	}
	return obj, nil
}

func parseWbemDatapacketObject(data []byte, offset int, classParts map[string]*classPart) (*objectBlock, int, error) {
	if offset+33 > len(data) {
		return nil, offset, errors.New("short WBEM datapacket")
	}
	offset += 8
	objectType := data[offset]
	offset++
	offset += 8
	clsid := binToUUID(data, offset)
	offset += 16
	var cp *classPart
	if objectType == 3 {
		cp = classParts[clsid]
	}
	obj, next, err := parseObjectBlock(data, offset, cp)
	if err != nil {
		return nil, offset, err
	}
	if objectType == 2 {
		classParts[clsid] = obj.classPart
	}
	return obj, next, nil
}

func parseObjectBlock(data []byte, offset int, cp *classPart) (*objectBlock, int, error) {
	if offset >= len(data) {
		return nil, offset, errors.New("short object block")
	}
	flags := data[offset]
	offset++
	if flags&0x4 != 0 {
		_, next, err := decodeEncodedString(data, offset)
		if err != nil {
			return nil, offset, err
		}
		offset = next
		_, next, err = decodeEncodedString(data, offset)
		if err != nil {
			return nil, offset, err
		}
		offset = next
	}
	if flags&0x1 != 0 {
		return nil, offset, ErrLegacyEncoding
	}
	if cp == nil {
		var err error
		cp, offset, err = parseClassPart(data, offset)
		if err != nil {
			return nil, offset, err
		}
	}
	if offset+9 > len(data) {
		return nil, offset, errors.New("short instance header")
	}
	offset += 9
	end := offset + int(cp.ndValueTableLength)
	if end > len(data) {
		return nil, offset, errors.New("short instance nd value table")
	}
	ndValueTable := append([]byte(nil), data[offset:end]...)
	offset = end
	_, offset, err := parseQualifierSet(data, offset, nil)
	if err != nil {
		return nil, offset, err
	}
	if offset >= len(data) {
		return nil, offset, errors.New("short property qualifier flags")
	}
	flags = data[offset]
	offset++
	if flags&0x2 != 0 {
		for range cp.defs {
			_, offset, err = parseQualifierSet(data, offset, nil)
			if err != nil {
				return nil, offset, err
			}
		}
	}
	heap, next, err := parseHeap(data, offset)
	if err != nil {
		return nil, offset, err
	}
	return &objectBlock{classPart: cp, ndValueTable: ndValueTable, instanceHeap: heap}, next, nil
}

func parseClassPart(data []byte, offset int) (*classPart, int, error) {
	start := offset
	if offset+13 > len(data) {
		return nil, offset, errors.New("short class header")
	}
	encodingLength := int(binary.LittleEndian.Uint32(data[offset:]))
	offset += 4
	offset++
	offset += 4
	ndValueTableLength := binary.LittleEndian.Uint32(data[offset:])
	offset += 4

	if offset+4 > len(data) {
		return nil, offset, errors.New("short derivation list")
	}
	encLength := int(binary.LittleEndian.Uint32(data[offset:]))
	if offset+encLength > len(data) {
		return nil, offset, errors.New("short derivation data")
	}
	offset += encLength
	_, offset, err := parseQualifierSet(data, offset, nil)
	if err != nil {
		return nil, offset, err
	}
	defs, offset, err := parsePropertyDefs(data, offset)
	if err != nil {
		return nil, offset, err
	}
	end := offset + int(ndValueTableLength)
	if end > len(data) {
		return nil, offset, errors.New("short class nd value table")
	}
	ndValueTable := append([]byte(nil), data[offset:end]...)
	offset = end
	classHeap, offset, err := parseHeap(data, offset)
	if err != nil {
		return nil, offset, err
	}
	resolvePropertyDefs(defs, classHeap)
	return &classPart{
		ndValueTableLength: ndValueTableLength,
		ndValueTable:       ndValueTable,
		classHeap:          classHeap,
		defs:               defs,
	}, start + encodingLength, nil
}

func parsePropertyDefs(data []byte, offset int) ([]*propertyDef, int, error) {
	if offset+4 > len(data) {
		return nil, offset, errors.New("short property lookup table")
	}
	count := int(binary.LittleEndian.Uint32(data[offset:]))
	offset += 4
	defs := make([]*propertyDef, 0, count)
	for range count {
		if offset+8 > len(data) {
			return nil, offset, errors.New("short property entry")
		}
		defs = append(defs, &propertyDef{
			nameRef: binary.LittleEndian.Uint32(data[offset:]),
			infoRef: binary.LittleEndian.Uint32(data[offset+4:]),
		})
		offset += 8
	}
	return defs, offset, nil
}

func resolvePropertyDefs(defs []*propertyDef, heap []byte) {
	for _, def := range defs {
		if def.nameRef&0x80000000 != 0 {
			def.Name = dictionaryReference[def.nameRef&0x7fffffff]
		} else {
			name, _, _ := decodeEncodedString(heap, int(def.nameRef))
			def.Name = name
		}
		if int(def.infoRef)+14 <= len(heap) {
			def.Type = binary.LittleEndian.Uint16(heap[def.infoRef:])
			def.Order = binary.LittleEndian.Uint16(heap[def.infoRef+4:])
			def.Qualifiers, _, _ = parseQualifierSet(heap, int(def.infoRef)+14, heap)
		}
	}
	sort.Slice(defs, func(i, j int) bool { return defs[i].Order < defs[j].Order })
}

func parseQualifierSet(data []byte, offset int, heap []byte) ([]Qualifier, int, error) {
	if offset+4 > len(data) {
		return nil, offset, errors.New("short qualifier set")
	}
	encLength := int(binary.LittleEndian.Uint32(data[offset:]))
	end := offset + encLength
	if end > len(data) {
		return nil, offset, errors.New("short qualifier set body")
	}
	qualifiers, err := decodeQualifierSet(data[offset+4:end], heap)
	if err != nil {
		return nil, offset, err
	}
	return qualifiers, end, nil
}

func decodeQualifierSet(data []byte, heap []byte) ([]Qualifier, error) {
	quals := make([]Qualifier, 0)
	for offset := 0; offset < len(data); {
		qual, next, err := parseQualifier(data, offset, heap)
		if err != nil {
			return nil, err
		}
		quals = append(quals, qual)
		offset = next
	}
	return quals, nil
}

func parseQualifier(data []byte, offset int, heap []byte) (Qualifier, int, error) {
	if offset+9 > len(data) {
		return Qualifier{}, offset, errors.New("short qualifier")
	}
	nameRef := binary.LittleEndian.Uint32(data[offset:])
	qual := Qualifier{
		Flavor: data[offset+4],
		Type:   binary.LittleEndian.Uint32(data[offset+5:]),
	}
	offset += 9
	qualType, err := checkedUint16(qual.Type)
	if err != nil {
		return Qualifier{}, offset, err
	}
	size := cimTypeSize(qualType)
	if offset+size > len(data) {
		return Qualifier{}, offset, errors.New("short qualifier value")
	}
	switch {
	case nameRef == 0xffffffff:
		qual.Name = ""
	case nameRef&0x80000000 != 0:
		qual.Name = dictionaryReference[nameRef&0x7fffffff]
	case heap != nil:
		name, _, err := decodeEncodedString(heap, int(nameRef))
		if err != nil {
			return Qualifier{}, offset, err
		}
		qual.Name = name
	}
	value, err := decodeQualifierValue(qualType, data[offset:offset+size], heap)
	if err != nil {
		return Qualifier{}, offset, err
	}
	qual.Value = value
	return qual, offset + size, nil
}

func decodeQualifierValue(cimType uint16, entry []byte, heap []byte) (any, error) {
	base := cimType &^ (cimArrayFlag | cimInheritedFlag)
	if heap == nil &&
		(cimType&cimArrayFlag != 0 || base == cimTypeString || base == cimTypeDateTime || base == cimTypeReference || base == cimTypeObject) {
		return binary.LittleEndian.Uint32(entry), nil
	}
	return decodePropertyValue(cimType, entry, heap)
}

func parseHeap(data []byte, offset int) ([]byte, int, error) {
	if offset+4 > len(data) {
		return nil, offset, errors.New("short heap")
	}
	heapLength := int(binary.LittleEndian.Uint32(data[offset:]) & 0x7fffffff)
	offset += 4
	end := offset + heapLength
	if end > len(data) {
		return nil, offset, errors.New("short heap body")
	}
	return append([]byte(nil), data[offset:end]...), end, nil
}

func (o *objectBlock) properties(ignoreDefaults, ignoreMissing, loadQualifiers bool) (map[string]*Property, error) {
	props := make(map[string]*Property, len(o.classPart.defs))
	for _, def := range o.classPart.defs {
		prop := &Property{
			Name:  def.Name,
			Type:  def.Type,
			Order: def.Order,
		}
		if loadQualifiers {
			prop.Qualifiers = append([]Qualifier(nil), def.Qualifiers...)
		}
		props[def.Name] = prop
	}
	if !ignoreDefaults {
		setPropDefaults(props, o.classPart.ndValueTable)
		if err := setPropValues(
			props,
			o.classPart.defs,
			o.classPart.classHeap,
			o.classPart.ndValueTable,
			true,
			false,
			false,
		); err != nil {
			return nil, err
		}
	}
	if err := setPropValues(
		props,
		o.classPart.defs,
		o.instanceHeap,
		o.ndValueTable,
		false,
		ignoreMissing,
		ignoreDefaults,
	); err != nil {
		return nil, err
	}
	return props, nil
}

func setPropDefaults(props map[string]*Property, ndValueTable []byte) {
	if len(props) == 0 {
		return
	}
	ndTableSize := (len(props)-1)/4 + 1
	ndTable := ndValueTable[:ndTableSize]
	for _, prop := range props {
		entry := (ndTable[prop.Order/4] >> ((prop.Order % 4) * 2)) & 0x3
		prop.NullDefault = entry&0x1 != 0
		prop.InheritedDefault = entry&0x2 != 0
	}
}

func setPropValues(
	props map[string]*Property,
	defs []*propertyDef,
	heap, ndValueTable []byte,
	setDefaults, ignoreMissing, ignoreDefaults bool,
) error {
	offset := 0
	if len(defs) > 0 {
		offset = (len(defs)-1)/4 + 1
	}
	for _, def := range defs {
		prop := props[def.Name]
		size := cimTypeSize(prop.Type)
		if offset+size > len(ndValueTable) {
			return fmt.Errorf("short value for property %s", prop.Name)
		}
		entry := ndValueTable[offset : offset+size]
		offset += size
		if isMissingValue(entry) || (setDefaults && !prop.InheritedDefault) {
			switch {
			case ignoreMissing:
				delete(props, prop.Name)
			case setDefaults:
				prop.Value = defaultValue(prop.Type)
			case ignoreDefaults:
				prop.Value = nil
			}
			continue
		}
		value, err := decodePropertyValue(prop.Type, entry, heap)
		if err != nil {
			return err
		}
		prop.Value = value
	}
	return nil
}

func defaultValue(cimType uint16) any {
	if cimType&cimArrayFlag != 0 {
		return []any{}
	}
	switch cimType &^ (cimArrayFlag | cimInheritedFlag) {
	case cimTypeBoolean:
		return false
	case cimTypeString, cimTypeDateTime, cimTypeReference:
		return ""
	case cimTypeObject:
		return nil
	default:
		return 0
	}
}

func isMissingValue(b []byte) bool {
	allZero := true
	allFF := true
	for _, v := range b {
		allZero = allZero && v == 0
		allFF = allFF && v == 0xff
	}
	return allZero || allFF
}

func cimTypeSize(cimType uint16) int {
	if cimType&cimArrayFlag != 0 {
		return 4
	}
	switch cimType &^ (cimArrayFlag | cimInheritedFlag) {
	case cimTypeSInt8, cimTypeUInt8:
		return 1
	case cimTypeSInt16, cimTypeUInt16, cimTypeBoolean, cimTypeChar16:
		return 2
	case cimTypeSInt32, cimTypeUInt32, cimTypeReal32, cimTypeString, cimTypeDateTime, cimTypeReference, cimTypeObject:
		return 4
	case cimTypeSInt64, cimTypeUInt64, cimTypeReal64:
		return 8
	default:
		return 4
	}
}

func decodePropertyValue(cimType uint16, entry []byte, heap []byte) (any, error) {
	base := cimType &^ (cimArrayFlag | cimInheritedFlag)
	if cimType&cimArrayFlag != 0 {
		return decodeArrayValue(base, int(binary.LittleEndian.Uint32(entry)), heap)
	}
	switch base {
	case cimTypeSInt8:
		return mustReadLE[int8](entry), nil
	case cimTypeUInt8:
		return entry[0], nil
	case cimTypeSInt16:
		return mustReadLE[int16](entry), nil
	case cimTypeUInt16:
		return binary.LittleEndian.Uint16(entry), nil
	case cimTypeSInt32:
		return mustReadLE[int32](entry), nil
	case cimTypeUInt32:
		return binary.LittleEndian.Uint32(entry), nil
	case cimTypeSInt64:
		return mustReadLE[int64](entry), nil
	case cimTypeUInt64:
		return binary.LittleEndian.Uint64(entry), nil
	case cimTypeReal32:
		return math.Float32frombits(binary.LittleEndian.Uint32(entry)), nil
	case cimTypeReal64:
		return math.Float64frombits(binary.LittleEndian.Uint64(entry)), nil
	case cimTypeBoolean:
		return binary.LittleEndian.Uint16(entry) == 0xffff, nil
	case cimTypeString, cimTypeReference:
		s, _, err := decodeEncodedString(heap, int(binary.LittleEndian.Uint32(entry)))
		return s, err
	case cimTypeDateTime:
		s, _, err := decodeEncodedString(heap, int(binary.LittleEndian.Uint32(entry)))
		if err != nil {
			return nil, err
		}
		return ParseWMIDateTime(s), nil
	case cimTypeChar16:
		return string(rune(binary.LittleEndian.Uint16(entry))), nil
	case cimTypeObject:
		return nil, ErrNotImplemented
	default:
		return nil, fmt.Errorf("unsupported CIM type %d", cimType)
	}
}

func decodeArrayValue(base uint16, entry int, heap []byte) (any, error) {
	if entry+4 > len(heap) {
		return nil, errors.New("short array ref")
	}
	numItems := int(binary.LittleEndian.Uint32(heap[entry:]) &^ cimArrayFlag)
	offset := entry + 4
	switch base {
	case cimTypeString, cimTypeReference, cimTypeDateTime:
		offset += numItems * 4
		out := make([]any, 0, numItems)
		for range numItems {
			s, next, err := decodeEncodedString(heap, offset)
			if err != nil {
				return nil, err
			}
			if base == cimTypeDateTime {
				out = append(out, ParseWMIDateTime(s))
			} else {
				out = append(out, s)
			}
			offset = next
		}
		return out, nil
	default:
		size := cimTypeSize(base)
		out := make([]any, 0, numItems)
		for range numItems {
			v, err := decodePropertyValue(base, heap[offset:offset+size], heap)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
			offset += size
		}
		return out, nil
	}
}
