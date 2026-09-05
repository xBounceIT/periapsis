package federatedsaml

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"
)

type expandedName struct {
	space string
	local string
}

type xmlAttribute struct {
	name  expandedName
	value string
}

type xmlNode struct {
	name       expandedName
	attributes []xmlAttribute
	children   []*xmlNode
	text       string
}

type xmlParseStatistics struct {
	nodes      int
	attributes int
	textBytes  int
	ids        map[string]struct{}
}

func parseBoundedXML(document []byte, maximumBytes int, limits Limits) (*xmlNode, error) {
	if len(document) < 4 || len(document) > maximumBytes || !utf8.Valid(document) {
		return nil, errors.New("bounded XML rejected")
	}
	decoder := xml.NewDecoder(bytes.NewReader(document))
	decoder.Strict = true
	decoder.AutoClose = nil
	decoder.Entity = map[string]string{}
	statistics := xmlParseStatistics{ids: make(map[string]struct{})}
	var root *xmlNode
	stack := make([]*xmlNode, 0, limits.MaxXMLDepth)
	seenDeclaration := false
	closedRoot := false
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, errors.New("bounded XML rejected")
		}
		switch value := token.(type) {
		case xml.StartElement:
			if closedRoot || len(stack) >= limits.MaxXMLDepth || !validNamespace(value.Name.Space) ||
				value.Name.Local == "" {
				return nil, errors.New("bounded XML rejected")
			}
			statistics.nodes++
			if statistics.nodes > limits.MaxXMLNodes {
				return nil, errors.New("bounded XML rejected")
			}
			node := &xmlNode{name: expandedName{space: value.Name.Space, local: value.Name.Local}}
			seenAttributes := make(map[expandedName]struct{}, len(value.Attr))
			for _, attribute := range value.Attr {
				name := expandedName{space: attribute.Name.Space, local: attribute.Name.Local}
				if !validNamespaceAttribute(name, attribute.Value) || !validXMLText(attribute.Value) {
					return nil, errors.New("bounded XML rejected")
				}
				if _, duplicate := seenAttributes[name]; duplicate {
					return nil, errors.New("bounded XML rejected")
				}
				seenAttributes[name] = struct{}{}
				statistics.attributes++
				if statistics.attributes > limits.MaxXMLAttributes {
					return nil, errors.New("bounded XML rejected")
				}
				if strings.EqualFold(attribute.Name.Local, "id") {
					validIDName := attribute.Name.Space == "" && (attribute.Name.Local == "ID" ||
						attribute.Name.Local == "Id" && (node.name == (expandedName{space: xmlEncryptionNamespace, local: "EncryptedData"}) ||
							node.name == (expandedName{space: xmlEncryptionNamespace, local: "EncryptedKey"})))
					if !validIDName ||
						!validXMLID(attribute.Value) {
						return nil, errors.New("bounded XML rejected")
					}
					if _, duplicate := statistics.ids[attribute.Value]; duplicate {
						return nil, errors.New("bounded XML rejected")
					}
					statistics.ids[attribute.Value] = struct{}{}
				}
				node.attributes = append(node.attributes, xmlAttribute{name: name, value: attribute.Value})
			}
			if len(stack) == 0 {
				if root != nil {
					return nil, errors.New("bounded XML rejected")
				}
				root = node
			} else {
				stack[len(stack)-1].children = append(stack[len(stack)-1].children, node)
			}
			stack = append(stack, node)
		case xml.EndElement:
			if len(stack) == 0 {
				return nil, errors.New("bounded XML rejected")
			}
			current := stack[len(stack)-1]
			if current.name != (expandedName{space: value.Name.Space, local: value.Name.Local}) {
				return nil, errors.New("bounded XML rejected")
			}
			stack = stack[:len(stack)-1]
			if len(stack) == 0 {
				closedRoot = true
			}
		case xml.CharData:
			if len(stack) == 0 {
				if strings.TrimSpace(string(value)) != "" {
					return nil, errors.New("bounded XML rejected")
				}
				continue
			}
			statistics.textBytes += len(value)
			if statistics.textBytes > limits.MaxXMLTextBytes || !utf8.Valid(value) {
				return nil, errors.New("bounded XML rejected")
			}
			stack[len(stack)-1].text += string(value)
		case xml.ProcInst:
			if root != nil || seenDeclaration || value.Target != "xml" ||
				!validXMLDeclaration(string(value.Inst)) {
				return nil, errors.New("bounded XML rejected")
			}
			seenDeclaration = true
		case xml.Comment, xml.Directive:
			return nil, errors.New("bounded XML rejected")
		default:
			return nil, errors.New("bounded XML rejected")
		}
	}
	if root == nil || len(stack) != 0 || !closedRoot {
		return nil, errors.New("bounded XML rejected")
	}
	return root, nil
}

func validXMLDeclaration(value string) bool {
	return value == `version="1.0"` || value == `version="1.0" encoding="UTF-8"` ||
		value == `version="1.0" encoding="utf-8"`
}

func validNamespace(value string) bool {
	switch value {
	case "", samlProtocolNamespace, samlAssertionNamespace, samlMetadataNamespace,
		xmlSignatureNamespace, xmlEncryptionNamespace, xmlEncryption11NS,
		xmlSchemaInstanceNS, xmlSchemaNamespace:
		return true
	default:
		return false
	}
}

func validNamespaceAttribute(name expandedName, value string) bool {
	if name.space == xmlnsNamespace || name.space == "" && name.local == "xmlns" {
		return validNamespace(value) && value != ""
	}
	return name.space == "" || name.space == xmlNamespace || name.space == xmlSchemaInstanceNS ||
		validNamespace(name.space)
}

func validXMLText(value string) bool {
	if !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character == 0 || character == '\uFFFE' || character == '\uFFFF' ||
			unicode.IsControl(character) && character != '\t' && character != '\n' && character != '\r' {
			return false
		}
	}
	return true
}

func validXMLID(value string) bool {
	if value == "" || len(value) > maximumIdentifierBytes || !utf8.ValidString(value) {
		return false
	}
	for index := range value {
		character := value[index]
		if index == 0 {
			if character == '_' || character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' {
				continue
			}
			return false
		}
		if character == '_' || character == '-' || character == '.' ||
			character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' {
			continue
		}
		return false
	}
	return true
}

func attribute(node *xmlNode, space, local string, required bool, maximum int) (string, bool, error) {
	if node == nil {
		return "", false, errors.New("XML shape rejected")
	}
	for _, candidate := range node.attributes {
		if candidate.name == (expandedName{space: space, local: local}) {
			if candidate.value == "" || len(candidate.value) > maximum || !validXMLText(candidate.value) {
				return "", false, errors.New("XML shape rejected")
			}
			return candidate.value, true, nil
		}
	}
	if required {
		return "", false, errors.New("XML shape rejected")
	}
	return "", false, nil
}

func allowedAttributes(node *xmlNode, allowed ...expandedName) bool {
	if node == nil {
		return false
	}
	for _, candidate := range node.attributes {
		if candidate.name.space == xmlnsNamespace ||
			candidate.name.space == "" && candidate.name.local == "xmlns" {
			continue
		}
		found := false
		for _, expected := range allowed {
			if candidate.name == expected {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func simpleElementText(node *xmlNode, maximum int) (string, error) {
	if node == nil || len(node.children) != 0 || !allowedAttributes(node) {
		return "", errors.New("XML shape rejected")
	}
	return elementText(node, maximum)
}

func elementText(node *xmlNode, maximum int) (string, error) {
	if node == nil || len(node.children) != 0 {
		return "", errors.New("XML shape rejected")
	}
	value := node.text
	if value == "" || len(value) > maximum || strings.TrimSpace(value) != value ||
		!validXMLText(value) || !noControlCharacters(value) {
		return "", errors.New("XML shape rejected")
	}
	return value, nil
}
