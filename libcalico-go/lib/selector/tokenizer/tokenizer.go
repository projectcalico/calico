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
	"regexp"
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

var whitespace = " \t"

// Token has a kind and a value
type Token struct {
	Kind  Kind
	Value string
}

func (t Token) String() string {
	return fmt.Sprintf("%s(%s)", t.Kind, t.Value)
}

const (
	// LabelKeyMatcher is the base regex for a valid label key.
	LabelKeyMatcher = `[a-zA-Z0-9_./-]{1,512}`
)

var (
	identifierRegex = regexp.MustCompile("^" + LabelKeyMatcher)
)

// Tokenize transforms string to token slice
func Tokenize(input string) (tokens []Token, err error) {
	return AppendTokens(nil, input)
}

// AppendTokens transforms string to token slice, appending it to the input
// tokens slice, which may be nil.
func AppendTokens(tokens []Token, input string) ([]Token, error) {
	for {
		if tokenizerDebug {
			log.Debug("Remaining input: ", input)
		}
		startLen := len(input)
		input = strings.TrimLeft(input, whitespace)
		if len(input) == 0 {
			tokens = append(tokens, Token{Kind: TokEOF})
			return tokens, nil
		}
		var lastTokKind = TokNone
		if len(tokens) > 0 {
			lastTokKind = tokens[len(tokens)-1].Kind
		}
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
			if len(input) > 1 && input[1] == '=' {
				tokens = append(tokens, Token{Kind: TokEq})
				input = input[2:]
			} else {
				return nil, errors.New("expected ==")
			}
		case '!':
			if len(input) > 1 && input[1] == '=' {
				tokens = append(tokens, Token{Kind: TokNe})
				input = input[2:]
			} else {
				tokens = append(tokens, Token{Kind: TokNot})
				input = input[1:]
			}
		case '&':
			if len(input) > 1 && input[1] == '&' {
				tokens = append(tokens, Token{Kind: TokAnd})
				input = input[2:]
			} else {
				return nil, errors.New("expected &&")
			}
		case '|':
			if len(input) > 1 && input[1] == '|' {
				tokens = append(tokens, Token{Kind: TokOr})
				input = input[2:]
			} else {
				return nil, errors.New("expected ||")
			}
		default:
			// Handle less-simple cases with regex matches.  We've already stripped any whitespace.
			if lastTokKind == TokLabel {
				// If we just saw a label, look for a contains/starts with/ends with operator instead of another label.
				if strings.HasPrefix(input, "contains") {
					tokens = append(tokens, Token{Kind: TokContains})
					input = input[len("contains"):]
				} else if strings.HasPrefix(input, "starts") {
					input = input[len("starts"):]
					input = strings.TrimLeft(input, whitespace)
					if strings.HasPrefix(input, "with") {
						tokens = append(tokens, Token{Kind: TokStartsWith})
						input = input[len("with"):]
					} else {
						return nil, fmt.Errorf("unexpected characters after label '%v', was expecting an operator",
							tokens[len(tokens)-1].Value)
					}
				} else if strings.HasPrefix(input, "ends") {
					input = input[len("ends"):]
					input = strings.TrimLeft(input, whitespace)
					if strings.HasPrefix(input, "with") {
						tokens = append(tokens, Token{Kind: TokEndsWith})
						input = input[len("with"):]
					} else {
						return nil, fmt.Errorf("unexpected characters after label '%v', was expecting an operator",
							tokens[len(tokens)-1].Value)
					}
				} else if strings.HasPrefix(input, "not") {
					input = input[len("not"):]
					input = strings.TrimLeft(input, whitespace)
					if strings.HasPrefix(input, "in") {
						tokens = append(tokens, Token{Kind: TokNotIn})
						input = input[len("in"):]
					} else {
						return nil, fmt.Errorf("unexpected characters after label '%v', was expecting an operator",
							tokens[len(tokens)-1].Value)
					}
				} else if strings.HasPrefix(input, "in") {
					tokens = append(tokens, Token{Kind: TokIn})
					input = input[len("in"):]
				} else {
					return nil, fmt.Errorf("unexpected characters after label '%v', was expecting an operator",
						tokens[len(tokens)-1].Value)
				}
			} else if strings.HasPrefix(input, "has(") {
				// Found "has()"
				input = input[len("has("):]
				input = strings.TrimLeft(input, whitespace)
				if ident := findIdentifier(input); ident != "" {
					// Found "has(label)"
					input = input[len(ident):]
					input = strings.TrimLeft(input, whitespace)
					if strings.HasPrefix(input, ")") {
						tokens = append(tokens, Token{TokHas, ident})
						input = input[1:]
					} else {
						return nil, fmt.Errorf("no closing ')' after has(")
					}
				} else {
					return nil, errors.New("no label name in has( expression")
				}
			} else if strings.HasPrefix(input, "all(") {
				// Found "all"
				input = input[len("all("):]
				input = strings.TrimLeft(input, whitespace)
				if strings.HasPrefix(input, ")") {
					tokens = append(tokens, Token{Kind: TokAll})
					input = input[1:]
				} else {
					return nil, fmt.Errorf("no closing ')' after all(")
				}
			} else if strings.HasPrefix(input, "global(") {
				// Found "all"
				input = input[len("global("):]
				input = strings.TrimLeft(input, whitespace)
				if strings.HasPrefix(input, ")") {
					tokens = append(tokens, Token{Kind: TokGlobal})
					input = input[1:]
				} else {
					return nil, fmt.Errorf("no closing ')' after global(")
				}
			} else if ident := findIdentifier(input); ident != "" {
				// Found "label"
				if log.IsLevelEnabled(log.DebugLevel) {
					log.Debug("Identifier ", ident)
				}
				tokens = append(tokens, Token{TokLabel, ident})
				input = input[len(ident):]
			} else {
				return nil, errors.New("unexpected characters")
			}
		}
		if len(input) >= startLen {
			return nil, errors.New("infinite loop detected in tokenizer")
		}
	}
}

func findIdentifier(in string) string {
	for i := 0; i < len(in); i++ {
		c := in[i]
		if c >= 'a' && c <= 'z' {
			continue
		}
		if c >= 'A' && c <= 'Z' {
			continue
		}
		if c >= '0' && c <= '9' {
			continue
		}
		if c == '_' || c == '.' || c == '/' || c == '-' {
			continue
		}
		return in[:i]
	}
	return in
}
