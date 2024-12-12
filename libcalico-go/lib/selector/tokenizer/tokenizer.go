// Copyright (c) 2016, 2019 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tokenizer

import (
	"errors"
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"
)

type Kind int

//go:generate stringer -type=Kind

const (
	TokNone Kind = iota
	TokLabel
	TokStringLiteral
	TokLBrace
	TokRBrace
	TokComma
	TokEq
	TokNe
	TokIn
	TokNot
	TokNotIn
	TokContains
	TokStartsWith
	TokEndsWith
	TokAll
	TokHas
	TokLParen
	TokRParen
	TokAnd
	TokOr
	TokGlobal
	TokEOF
)

const tokenizerDebug = false
const MaxLabelLength = 512

// Token has a kind and a value
type Token struct {
	Kind  Kind
	Value string
}

func (t Token) String() string {
	return fmt.Sprintf("%s(%s)", t.Kind, t.Value)
}

// Tokenize transforms string to token slice
func Tokenize(input string) ([]Token, error) {
	return AppendTokens(nil, input)
}

// AppendTokens transforms string to token slice, appending it to the input
// tokens slice, which may be nil.
func AppendTokens(tokens []Token, input string) ([]Token, error) {
	for {
		if debugEnabled() {
			log.Debug("Remaining input: ", input)
		}
		startLen := len(input)
		input = trimWhitespace(input)
		if len(input) == 0 {
			tokens = append(tokens, Token{Kind: TokEOF})
			return tokens, nil
		}
		var lastTokKind = TokNone
		if len(tokens) > 0 {
			lastTokKind = tokens[len(tokens)-1].Kind
		}
		var found bool
		switch input[0] {
		case '(':
			tokens = append(tokens, Token{Kind: TokLParen})
			input = input[1:]
		case ')':
			tokens = append(tokens, Token{Kind: TokRParen})
			input = input[1:]
		case '"':
			input = input[1:]
			index := strings.Index(input, `"`)
			if index == -1 {
				return nil, errors.New("unterminated string")
			}
			value := input[0:index]
			tokens = append(tokens, Token{TokStringLiteral, value})
			input = input[index+1:]
		case '\'':
			input = input[1:]
			index := strings.Index(input, `'`)
			if index == -1 {
				return nil, errors.New("unterminated string")
			}
			value := input[0:index]
			tokens = append(tokens, Token{TokStringLiteral, value})
			input = input[index+1:]
		case '{':
			tokens = append(tokens, Token{Kind: TokLBrace})
			input = input[1:]
		case '}':
			tokens = append(tokens, Token{Kind: TokRBrace})
			input = input[1:]
		case ',':
			tokens = append(tokens, Token{Kind: TokComma})
			input = input[1:]
		case '=':
			if input, found = strings.CutPrefix(input, "=="); found {
				tokens = append(tokens, Token{Kind: TokEq})
			} else {
				return nil, errors.New("expected ==")
			}
		case '!':
			if input, found = strings.CutPrefix(input, "!="); found {
				tokens = append(tokens, Token{Kind: TokNe})
			} else {
				tokens = append(tokens, Token{Kind: TokNot})
				input = input[1:]
			}
		case '&':
			if input, found = strings.CutPrefix(input, "&&"); found {
				tokens = append(tokens, Token{Kind: TokAnd})
			} else {
				return nil, errors.New("expected &&")
			}
		case '|':
			if input, found = strings.CutPrefix(input, "||"); found {
				tokens = append(tokens, Token{Kind: TokOr})
			} else {
				return nil, errors.New("expected ||")
			}
		default:
			// Handle less-simple cases with custom logic.  We've already stripped any whitespace.
			var ident string
			var err error
			if lastTokKind == TokLabel {
				// If we just saw a label, look for an operator next.
				if input, found = cutPrefixCheckBreak(input, "contains"); found {
					tokens = append(tokens, Token{Kind: TokContains})
				} else if input, found = cutMultiWordPrefixCheckBreak(input, "starts", "with"); found {
					tokens = append(tokens, Token{Kind: TokStartsWith})
				} else if input, found = cutMultiWordPrefixCheckBreak(input, "ends", "with"); found {
					tokens = append(tokens, Token{Kind: TokEndsWith})
				} else if input, found = cutMultiWordPrefixCheckBreak(input, "not", "in"); found {
					tokens = append(tokens, Token{Kind: TokNotIn})
				} else if input, found = cutPrefixCheckBreak(input, "in"); found {
					tokens = append(tokens, Token{Kind: TokIn})
				} else {
					return nil, fmt.Errorf("expected operator after label %q",
						tokens[len(tokens)-1].Value)
				}
			} else if input, found = strings.CutPrefix(input, "has("); found {
				// Found "has()" ?
				input = trimWhitespace(input)
				if ident, input, err = cutIdentifier(input); err != nil {
					return nil, err
				}
				input = trimWhitespace(input)
				if input, found = strings.CutPrefix(input, ")"); found {
					tokens = append(tokens, Token{TokHas, ident})
				} else {
					return nil, fmt.Errorf("no closing ')' after has(")
				}
			} else if input, found = strings.CutPrefix(input, "all("); found {
				// Found "all()" ?
				input = trimWhitespace(input)
				if input, found = strings.CutPrefix(input, ")"); found {
					tokens = append(tokens, Token{Kind: TokAll})
				} else {
					return nil, fmt.Errorf("no closing ')' after all(")
				}
			} else if input, found = strings.CutPrefix(input, "global("); found {
				// Found "global()" ?
				input = trimWhitespace(input)
				if input, found = strings.CutPrefix(input, ")"); found {
					tokens = append(tokens, Token{Kind: TokGlobal})
				} else {
					return nil, fmt.Errorf("no closing ')' after global(")
				}
			} else if ident, input, err = cutIdentifier(input); err == nil {
				tokens = append(tokens, Token{TokLabel, ident})
			} else {
				return nil, err
			}
		}
		if len(input) >= startLen {
			return nil, errors.New("infinite loop detected in tokenizer")
		}
	}
}

func trimWhitespace(input string) string {
	end := 0
	for ; end < len(input); end++ {
		if input[end] == ' ' || input[end] == '\t' {
			continue
		}
		break
	}
	return input[end:]
}

func debugEnabled() bool {
	if tokenizerDebug {
		return log.IsLevelEnabled(log.DebugLevel)
	}
	return false
}

func cutPrefixCheckBreak(input string, prefix string) (string, bool) {
	remainder, found := strings.CutPrefix(input, prefix)
	if !found {
		return input, false
	}
	if !isWordBoundary(remainder) {
		return input, false
	}
	return remainder, true
}

func cutMultiWordPrefixCheckBreak(input string, words ...string) (string, bool) {
	remainder := input
	for _, word := range words {
		var found bool
		if remainder, found = strings.CutPrefix(remainder, word); !found {
			return input, false
		}
		remainder = trimWhitespace(remainder)
	}
	// Only check that there's a word boundary after the last word.  We allow
	// "not in" or "notin" as a single operator.
	if !isWordBoundary(remainder) {
		return input, false
	}
	return remainder, true
}

func isWordBoundary(in string) bool {
	if in == "" {
		// End of string is an implicit word boundary.
		return true
	}
	if identifierChar(in[0]) {
		return false
	}
	return true
}

func ValidLabel(label string) bool {
	_, remainder, err := cutIdentifier(label)
	return err == nil && remainder == ""
}

func cutIdentifier(in string) (ident string, remainder string, err error) {
	defer func() {
		if len(ident) > MaxLabelLength {
			err = fmt.Errorf("label too long: %s", ident)
			ident = ""
		} else if len(ident) == 0 {
			err = errors.New("expected identifier")
		}
	}()
	for i := 0; i < len(in); i++ {
		c := in[i]
		if identifierChar(c) {
			continue
		}
		return in[:i], in[i:], nil
	}
	return in, "", nil
}

func identifierChar(c uint8) bool {
	return c >= 'a' && c <= 'z' ||
		c >= 'A' && c <= 'Z' ||
		c >= '0' && c <= '9' ||
		c == '_' ||
		c == '.' ||
		c == '/' ||
		c == '-'
}
