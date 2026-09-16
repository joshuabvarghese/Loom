package webui

import (
	"github.com/jhump/protoreflect/desc"
	"google.golang.org/protobuf/types/descriptorpb"
)

// schemaConverter turns a chain of protobuf message descriptors into a
// single JSON Schema (draft-07) document, suitable for feeding straight into
// Monaco's `jsonDefaults.setDiagnosticsOptions({ schemas: [...] })`.
//
// Message types are memoized into "$defs" and referenced via "$ref" so that
// self-referential or mutually-recursive messages (e.g. a Tree with
// `repeated Tree children`) don't blow the stack — a real concern once you
// stop assuming every .proto is a flat DTO.
type schemaConverter struct {
	defs    map[string]map[string]interface{} // fully-qualified message name -> its schema object
	used    map[string]bool                   // fqns that were actually $ref'd from somewhere
	visited map[string]bool                   // fqns currently being built, to break cycles
}

func newSchemaConverter() *schemaConverter {
	return &schemaConverter{
		defs:    map[string]map[string]interface{}{},
		used:    map[string]bool{},
		visited: map[string]bool{},
	}
}

// buildSchema returns a complete draft-07 document for md: the message's own
// shape inlined at the root (so simple, non-recursive requests round-trip as
// the flat {"type":"object","properties":{...}} shape callers expect), plus
// a "$defs" section for any nested message types that needed one.
func (sc *schemaConverter) buildSchema(md *desc.MessageDescriptor) map[string]interface{} {
	fqn := md.GetFullyQualifiedName()

	sc.visited[fqn] = true
	root := sc.messageObject(md)
	delete(sc.visited, fqn)

	// Register the root under $defs too, in case something nested inside it
	// refers back to it (e.g. a linked-list style message). We only expose
	// this entry in the final "$defs" block if it was actually referenced.
	sc.defs[fqn] = root

	doc := map[string]interface{}{
		"$schema": "http://json-schema.org/draft-07/schema#",
	}
	for k, v := range root {
		doc[k] = v
	}

	if defs := sc.exportedDefs(fqn); len(defs) > 0 {
		doc["$defs"] = defs
	}
	return doc
}

// exportedDefs returns every def except rootFQN, unless rootFQN was itself
// referenced from somewhere (a genuine cycle), in which case it's kept too.
func (sc *schemaConverter) exportedDefs(rootFQN string) map[string]interface{} {
	out := map[string]interface{}{}
	for fqn, obj := range sc.defs {
		if fqn == rootFQN && !sc.used[rootFQN] {
			continue
		}
		out[fqn] = obj
	}
	return out
}

// messageObject builds the {"type":"object", "properties": {...}, ...} body
// for md, without the "$schema" wrapper.
func (sc *schemaConverter) messageObject(md *desc.MessageDescriptor) map[string]interface{} {
	props := map[string]interface{}{}
	var required []string

	for _, f := range md.GetFields() {
		props[f.GetJSONName()] = sc.fieldSchema(f)
		if isFieldRequired(f) {
			required = append(required, f.GetJSONName())
		}
	}

	obj := map[string]interface{}{
		"type":       "object",
		"properties": props,
	}
	if len(required) > 0 {
		obj["required"] = required
	}
	if d := leadingComment(md.GetSourceInfo()); d != "" {
		obj["description"] = d
	}
	return obj
}

// fieldSchema returns the schema for a single field, handling maps, enums,
// nested messages, repeated wrapping, and scalar types in that order.
func (sc *schemaConverter) fieldSchema(f *desc.FieldDescriptor) map[string]interface{} {
	var base map[string]interface{}

	switch {
	case f.IsMap():
		// JSON objects only have string keys, which lines up with how
		// protobuf maps are represented in canonical proto3 JSON regardless
		// of the declared key type.
		base = map[string]interface{}{
			"type":                 "object",
			"additionalProperties": sc.valueSchema(f.GetMapValueType()),
		}
	case f.GetEnumType() != nil:
		base = enumSchema(f.GetEnumType())
	case f.GetMessageType() != nil:
		base = sc.messageRef(f.GetMessageType())
	default:
		base = scalarSchema(f.GetType())
	}

	if f.IsRepeated() && !f.IsMap() {
		base = map[string]interface{}{
			"type":  "array",
			"items": base,
		}
	}

	if d := leadingComment(f.GetSourceInfo()); d != "" {
		// Note: draft-07 technically ignores sibling keywords next to a bare
		// "$ref", but Monaco's json-language-service still surfaces this on
		// hover, which is the main thing we want it for here.
		base["description"] = d
	}
	return base
}

// valueSchema is like fieldSchema but for a map's synthetic value field
// (map value fields never repeat and can't map-of-map, so it's simpler).
func (sc *schemaConverter) valueSchema(f *desc.FieldDescriptor) map[string]interface{} {
	switch {
	case f.GetEnumType() != nil:
		return enumSchema(f.GetEnumType())
	case f.GetMessageType() != nil:
		return sc.messageRef(f.GetMessageType())
	default:
		return scalarSchema(f.GetType())
	}
}

// messageRef memoizes md into sc.defs (building it at most once, and
// tolerating self/mutual recursion via the sc.visited guard) and returns a
// {"$ref": "#/$defs/..."} pointing at it.
func (sc *schemaConverter) messageRef(md *desc.MessageDescriptor) map[string]interface{} {
	fqn := md.GetFullyQualifiedName()
	sc.used[fqn] = true
	ref := map[string]interface{}{"$ref": "#/$defs/" + fqn}

	if _, built := sc.defs[fqn]; built {
		return ref
	}
	if sc.visited[fqn] {
		// Cycle: the ancestor call currently building this fqn will finish
		// and populate sc.defs[fqn] itself; we just need the pointer.
		return ref
	}

	sc.visited[fqn] = true
	sc.defs[fqn] = sc.messageObject(md)
	delete(sc.visited, fqn)
	return ref
}

// isFieldRequired applies a best-effort notion of "required" for editor
// hinting purposes. Proto3 has no real required/optional distinction for
// scalars, so this is a heuristic, not a protocol fact:
//   - proto2 "required" fields are always required.
//   - proto3 singular scalar fields (string/bytes/bool/numeric) that aren't
//     part of a oneof and aren't declared with the "optional" keyword are
//     treated as required, since omitting them usually means "the caller
//     forgot", not "this enum defaulted sensibly".
//   - enums, messages, maps, and repeated fields are never marked required:
//     each already has an unambiguous, meaningful zero/empty value.
func isFieldRequired(f *desc.FieldDescriptor) bool {
	if f.GetLabel() == descriptorpb.FieldDescriptorProto_LABEL_REQUIRED {
		return true
	}
	if f.IsRepeated() || f.IsMap() || f.IsProto3Optional() || f.GetOneOf() != nil {
		return false
	}
	if f.GetEnumType() != nil || f.GetMessageType() != nil {
		return false
	}
	return true
}

// enumSchema renders an enum as a plain string enum of its value names,
// which is how canonical proto3 JSON represents enums by default.
func enumSchema(ed *desc.EnumDescriptor) map[string]interface{} {
	values := ed.GetValues()
	names := make([]string, len(values))
	for i, v := range values {
		names[i] = v.GetName()
	}
	obj := map[string]interface{}{
		"type": "string",
		"enum": names,
	}
	if d := leadingComment(ed.GetSourceInfo()); d != "" {
		obj["description"] = d
	}
	return obj
}

// scalarSchema maps a protobuf scalar type to its canonical proto3 JSON
// representation. Notably: 64-bit integer types are serialized as JSON
// strings (not numbers) per the protobuf JSON spec, to avoid precision loss
// in JS's float64-backed Number type — the same reason grpcurl and protojson
// emit them as strings.
func scalarSchema(t descriptorpb.FieldDescriptorProto_Type) map[string]interface{} {
	switch t {
	case descriptorpb.FieldDescriptorProto_TYPE_DOUBLE,
		descriptorpb.FieldDescriptorProto_TYPE_FLOAT:
		return map[string]interface{}{"type": "number"}

	case descriptorpb.FieldDescriptorProto_TYPE_INT32,
		descriptorpb.FieldDescriptorProto_TYPE_UINT32,
		descriptorpb.FieldDescriptorProto_TYPE_SINT32,
		descriptorpb.FieldDescriptorProto_TYPE_FIXED32,
		descriptorpb.FieldDescriptorProto_TYPE_SFIXED32:
		return map[string]interface{}{"type": "integer"}

	case descriptorpb.FieldDescriptorProto_TYPE_INT64,
		descriptorpb.FieldDescriptorProto_TYPE_UINT64,
		descriptorpb.FieldDescriptorProto_TYPE_SINT64,
		descriptorpb.FieldDescriptorProto_TYPE_FIXED64,
		descriptorpb.FieldDescriptorProto_TYPE_SFIXED64:
		return map[string]interface{}{
			"type":    "string",
			"pattern": "^-?[0-9]+$",
		}

	case descriptorpb.FieldDescriptorProto_TYPE_BOOL:
		return map[string]interface{}{"type": "boolean"}

	case descriptorpb.FieldDescriptorProto_TYPE_BYTES:
		return map[string]interface{}{
			"type":            "string",
			"contentEncoding": "base64",
		}

	case descriptorpb.FieldDescriptorProto_TYPE_STRING:
		return map[string]interface{}{"type": "string"}

	default:
		// TYPE_GROUP and anything else unrecognized: fall back to an
		// unconstrained string rather than rejecting the whole schema.
		return map[string]interface{}{"type": "string"}
	}
}

// leadingComment extracts a field/message/enum's leading proto comment, if
// the descriptor carries source info. Server reflection frequently doesn't
// (compiled .proto files usually strip comments unless built with
// `protoc --include_source_info`), so this degrades gracefully to "" rather
// than being relied upon.
func leadingComment(loc *descriptorpb.SourceCodeInfo_Location) string {
	if loc == nil {
		return ""
	}
	return trimComment(loc.GetLeadingComments())
}

func trimComment(c string) string {
	// Collapse "// foo\n// bar\n" style multi-line comments into one line;
	// good enough for a tooltip-length description.
	out := make([]byte, 0, len(c))
	lastSpace := false
	for i := 0; i < len(c); i++ {
		b := c[i]
		if b == '\n' || b == '\r' || b == '\t' {
			b = ' '
		}
		if b == ' ' {
			if lastSpace {
				continue
			}
			lastSpace = true
		} else {
			lastSpace = false
		}
		out = append(out, b)
	}
	// Trim surrounding whitespace left by the collapse above.
	start, end := 0, len(out)
	for start < end && out[start] == ' ' {
		start++
	}
	for end > start && out[end-1] == ' ' {
		end--
	}
	return string(out[start:end])
}
