package wmi

import (
	"fmt"
	"math"
	"reflect"
	"strings"
)

// Decode maps WMI properties into a struct. Fields are matched by the "wmi"
// struct tag, or by exact field name when no tag is present. Use "-" to skip
// a field.
//
//	type OS struct {
//	    Caption string `wmi:"Caption"`
//	    Version string `wmi:"Version"`
//	}
//	var os OS
//	wmi.Decode(props, &os)
func Decode(props map[string]*Property, dest any) error {
	rv := reflect.ValueOf(dest)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		return fmt.Errorf("wmi.Decode: dest must be a non-nil pointer to a struct, got %T", dest)
	}
	rv = rv.Elem()
	if rv.Kind() != reflect.Struct {
		return fmt.Errorf("wmi.Decode: dest must point to a struct, got %s", rv.Type())
	}
	rt := rv.Type()
	for i := range rt.NumField() {
		field := rt.Field(i)
		if !field.IsExported() {
			continue
		}
		tag := field.Tag.Get("wmi")
		if tag == "-" {
			continue
		}
		name := tag
		// Support tag options (e.g. `wmi:"Name,omitempty"`); only use the key part.
		if idx := strings.IndexByte(name, ','); idx >= 0 {
			name = name[:idx]
		}
		// If the tag key is empty (e.g. `wmi:",omitempty"`), fall back to field name.
		if name == "" {
			name = field.Name
		}
		prop, ok := props[name]
		if !ok || prop == nil {
			continue
		}
		if prop.Value == nil {
			continue
		}
		fv := rv.Field(i)
		if err := assignValue(fv, prop.Value); err != nil {
			return fmt.Errorf("wmi.Decode: field %s (property %s): %w", field.Name, name, err)
		}
	}
	return nil
}

// DecodeAll decodes a slice of property maps into a slice of structs.
//
//	var procs []Process
//	wmi.DecodeAll(rows, &procs)
func DecodeAll(rows []map[string]*Property, dest any) error {
	rv := reflect.ValueOf(dest)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		return fmt.Errorf("wmi.DecodeAll: dest must be a non-nil pointer to a slice, got %T", dest)
	}
	sv := rv.Elem()
	if sv.Kind() != reflect.Slice {
		return fmt.Errorf("wmi.DecodeAll: dest must point to a slice, got %s", sv.Type())
	}
	elemType := sv.Type().Elem()
	isPtr := elemType.Kind() == reflect.Pointer
	if isPtr {
		elemType = elemType.Elem()
	}
	if elemType.Kind() != reflect.Struct {
		return fmt.Errorf("wmi.DecodeAll: slice element must be a struct or *struct, got %s", sv.Type().Elem())
	}
	result := reflect.MakeSlice(sv.Type(), 0, len(rows))
	for _, props := range rows {
		elem := reflect.New(elemType)
		if err := Decode(props, elem.Interface()); err != nil {
			return err
		}
		if isPtr {
			result = reflect.Append(result, elem)
		} else {
			result = reflect.Append(result, elem.Elem())
		}
	}
	sv.Set(result)
	return nil
}

func assignValue(fv reflect.Value, val any) error {
	rv := reflect.ValueOf(val)

	// Direct assignability covers most cases: matching types, any, etc.
	if rv.Type().AssignableTo(fv.Type()) {
		fv.Set(rv)
		return nil
	}

	// Handle pointer fields: allocate and assign into the element.
	if fv.Kind() == reflect.Pointer {
		ptr := reflect.New(fv.Type().Elem())
		if err := assignValue(ptr.Elem(), val); err != nil {
			return err
		}
		fv.Set(ptr)
		return nil
	}

	// Numeric conversions: WMI types (int8..uint64, float32/64) to Go numeric types.
	if isNumericKind(rv.Kind()) && isNumericKind(fv.Kind()) {
		converted, ok := convertNumeric(rv, fv.Type())
		if !ok {
			return fmt.Errorf("numeric value %v (%s) overflows %s", val, rv.Type(), fv.Type())
		}
		fv.Set(converted)
		return nil
	}

	// []any → typed slice
	if fv.Kind() == reflect.Slice {
		if items, ok := val.([]any); ok {
			return assignSlice(fv, items)
		}
	}

	return fmt.Errorf("cannot assign %T to %s", val, fv.Type())
}

func assignSlice(fv reflect.Value, items []any) error {
	elemType := fv.Type().Elem()
	result := reflect.MakeSlice(fv.Type(), 0, len(items))
	for i, item := range items {
		elem := reflect.New(elemType).Elem()
		if err := assignValue(elem, item); err != nil {
			return fmt.Errorf("index %d: %w", i, err)
		}
		result = reflect.Append(result, elem)
	}
	fv.Set(result)
	return nil
}

func isNumericKind(k reflect.Kind) bool {
	switch k {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64:
		return true
	default:
		return false
	}
}

func convertNumeric(src reflect.Value, dstType reflect.Type) (reflect.Value, bool) {
	switch dstType.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		lo, hi := signedRange(dstType)
		if !fitsSignedRange(src, lo, hi) {
			return reflect.Value{}, false
		}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if !fitsUnsignedRange(src, unsignedMax(dstType)) {
			return reflect.Value{}, false
		}
	case reflect.Float32, reflect.Float64:
		limit := math.MaxFloat64
		if dstType.Kind() == reflect.Float32 {
			limit = math.MaxFloat32
		}
		if !fitsFloatRange(src, limit) {
			return reflect.Value{}, false
		}
	default:
		return reflect.Value{}, false
	}
	return src.Convert(dstType), true
}

func fitsSignedRange(src reflect.Value, lo, hi int64) bool {
	switch src.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v := src.Int()
		return v >= lo && v <= hi
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v := src.Uint()
		return hi >= 0 && v <= uint64(hi)
	case reflect.Float32, reflect.Float64:
		v := src.Float()
		return !math.IsNaN(v) && !math.IsInf(v, 0) && math.Trunc(v) == v &&
			v >= float64(lo) && v <= float64(hi)
	default:
		return false
	}
}

func fitsUnsignedRange(src reflect.Value, hi uint64) bool {
	switch src.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v := src.Int()
		return v >= 0 && uint64(v) <= hi
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return src.Uint() <= hi
	case reflect.Float32, reflect.Float64:
		v := src.Float()
		return !math.IsNaN(v) && !math.IsInf(v, 0) && math.Trunc(v) == v &&
			v >= 0 && v <= float64(hi)
	default:
		return false
	}
}

func fitsFloatRange(src reflect.Value, limit float64) bool {
	switch src.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v := float64(src.Int())
		return v >= -limit && v <= limit
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return float64(src.Uint()) <= limit
	case reflect.Float32, reflect.Float64:
		v := src.Float()
		return !math.IsInf(v, 0) && !math.IsNaN(v) && v >= -limit && v <= limit
	default:
		return false
	}
}

func signedRange(t reflect.Type) (int64, int64) {
	bits := t.Bits()
	if bits >= 64 {
		return math.MinInt64, math.MaxInt64
	}

	hi := int64(1<<(bits-1)) - 1
	lo := -1 - hi
	return lo, hi
}

func unsignedMax(t reflect.Type) uint64 {
	bits := t.Bits()
	if bits >= 64 {
		return math.MaxUint64
	}
	return (uint64(1) << bits) - 1
}
