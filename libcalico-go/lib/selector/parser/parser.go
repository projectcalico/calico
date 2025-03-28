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

package parser

import (
	"errors"
	"fmt"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/selector/tokenizer"
)

const parserDebug = false

var (
	sharedParserLock sync.Mutex
	sharedParser     = NewParser()
)

// Parse parses a string representation of a selector expression into a Selector.
func Parse(selector string) (sel Selector, err error) {
	sharedParserLock.Lock()
	defer sharedParserLock.Unlock()

	return sharedParser.Parse(selector)
}

var (
	sharedValidatorLock sync.Mutex
	sharedValidator     = NewParser()
)

func Validate(selector string) (err error) {
	sharedValidatorLock.Lock()
	defer sharedValidatorLock.Unlock()

	return sharedValidator.Validate(selector)
}

func NewParser() *Parser {
	return &Parser{
		tokBuf: make([]tokenizer.Token, 0, 128),
	}
}

type Parser struct {
	tokBuf []tokenizer.Token
}

func (p *Parser) Parse(selector string) (sel Selector, err error) {
	if log.IsLevelEnabled(log.DebugLevel) {
		log.Debugf("Parsing %q", selector)
	}
	return p.parseRoot(selector, false)
}

func (p *Parser) Validate(selector string) (err error) {
	if log.IsLevelEnabled(log.DebugLevel) {
		log.Debugf("Validating %q", selector)
	}
	_, err = p.parseRoot(selector, true)
	return
}

func (p *Parser) parseRoot(selector string, validateOnly bool) (sel Selector, err error) {
	// Tokenize the input.  We re-use the same shared buffer to avoid
	// allocations.
	tokens, err := tokenizer.AppendTokens(p.tokBuf[:0], selector)
	if err != nil {
		return
	}
	if cap(tokens) > cap(p.tokBuf) && cap(tokens) < 4096 {
		// Allow buffer to grow if we're seeing large inputs.
		p.tokBuf = tokens[:0]
	}

	if tokens[0].Kind == tokenizer.TokEOF {
		if validateOnly {
			return nil, nil
		}
		return &selectorRoot{root: &AllNode{}}, nil
	}
	if log.IsLevelEnabled(log.DebugLevel) {
		log.Debugf("Tokens %v", tokens)
	}

	// The "||" operator has the lowest precedence so we start with that.
	node, remTokens, err := p.parseOrExpression(tokens, validateOnly)
	if err != nil {
		return
	}
	if len(remTokens) != 1 {
		err = errors.New(fmt.Sprint("unexpected content at end of selector ", remTokens))
		return
	}
	if validateOnly {
		return
	}
	sel = &selectorRoot{root: node}
	return
}

// parseOrExpression parses a one or more "&&" terms, separated by "||" operators.
func (p *Parser) parseOrExpression(tokens []tokenizer.Token, validateOnly bool) (sel node, remTokens []tokenizer.Token, err error) {
	if parserDebug {
		log.Debugf("Parsing ||s from %v", tokens)
	}
	// Look for the first expression.
	var andNodes []node
	sel, remTokens, err = p.parseAndExpression(tokens, validateOnly)
	if err != nil {
		return
	}
	if !validateOnly {
		andNodes = append(andNodes, sel)
	}

	// Then loop looking for "||" followed by an <expression>
	for {
		switch remTokens[0].Kind {
		case tokenizer.TokOr:
			remTokens = remTokens[1:]
			sel, remTokens, err = p.parseAndExpression(remTokens, validateOnly)
			if err != nil {
				return
			}
			if validateOnly {
				continue
			}
			andNodes = append(andNodes, sel)
		default:
			if validateOnly {
				return
			}
			if len(andNodes) == 1 {
				sel = andNodes[0]
			} else {
				sel = &OrNode{andNodes}
			}
			return
		}
	}
}

// parseAndExpression parses a one or more operations, separated by "&&" operators.
func (p *Parser) parseAndExpression(
	tokens []tokenizer.Token,
	validateOnly bool,
) (sel node, remTokens []tokenizer.Token, err error) {
	if parserDebug {
		log.Debugf("Parsing &&s from %v", tokens)
	}
	// Look for the first operation.
	var opNodes []node
	sel, remTokens, err = p.parseOperation(tokens, validateOnly)
	if err != nil {
		return
	}
	if !validateOnly {
		opNodes = append(opNodes, sel)
	}

	// Then loop looking for "&&" followed by another operation.
	for {
		switch remTokens[0].Kind {
		case tokenizer.TokAnd:
			remTokens = remTokens[1:]
			sel, remTokens, err = p.parseOperation(remTokens, validateOnly)
			if err != nil {
				return
			}
			if validateOnly {
				continue
			}
			opNodes = append(opNodes, sel)
		default:
			if validateOnly {
				return
			}
			if len(opNodes) == 1 {
				sel = opNodes[0]
			} else {
				sel = &AndNode{opNodes}
			}
			return
		}
	}
}

var (
	ErrUnexpectedEOF  = errors.New("unexpected end of string looking for op")
	ErrExpectedRParen = errors.New("expected )")
	ErrExpectedRBrace = errors.New("expected }")
	ErrExpectedString = errors.New("expected string")
	ErrExpectedSetLit = errors.New("expected set literal")
)

// parseOperations parses a single, possibly negated operation (i.e. ==, !=, has()).
// It also handles calling parseOrExpression recursively for parenthesized expressions.
func (p *Parser) parseOperation(tokens []tokenizer.Token, validateOnly bool) (sel node, remTokens []tokenizer.Token, err error) {
	if parserDebug {
		log.Debugf("Parsing op from %v", tokens)
	}
	if len(tokens) == 0 {
		err = ErrUnexpectedEOF
		return
	}

	// First, collapse any leading "!" operators to a single boolean.
	negated := false
	for {
		if tokens[0].Kind == tokenizer.TokNot {
			negated = !negated
			tokens = tokens[1:]
		} else {
			break
		}
	}

	// Then, look for the various types of operator.
	switch tokens[0].Kind {
	case tokenizer.TokHas:
		if !validateOnly {
			sel = &HasNode{tokens[0].Value}
		}
		remTokens = tokens[1:]
	case tokenizer.TokAll:
		if !validateOnly {
			sel = &AllNode{}
		}
		remTokens = tokens[1:]
	case tokenizer.TokGlobal:
		if !validateOnly {
			sel = &GlobalNode{}
		}
		remTokens = tokens[1:]
	case tokenizer.TokLabel:
		// should have an operator and a literal.
		if len(tokens) < 3 {
			err = ErrUnexpectedEOF
			return
		}
		switch tokens[1].Kind {
		case tokenizer.TokEq:
			if tokens[2].Kind == tokenizer.TokStringLiteral {
				if !validateOnly {
					sel = &LabelEqValueNode{tokens[0].Value, tokens[2].Value}
				}
				remTokens = tokens[3:]
			} else {
				err = ErrExpectedString
			}
		case tokenizer.TokNe:
			if tokens[2].Kind == tokenizer.TokStringLiteral {
				if !validateOnly {
					sel = &LabelNeValueNode{tokens[0].Value, tokens[2].Value}
				}
				remTokens = tokens[3:]
			} else {
				err = ErrExpectedString
			}
		case tokenizer.TokContains:
			if tokens[2].Kind == tokenizer.TokStringLiteral {
				if !validateOnly {
					sel = &LabelContainsValueNode{tokens[0].Value, tokens[2].Value}
				}
				remTokens = tokens[3:]
			} else {
				err = ErrExpectedString
			}
		case tokenizer.TokStartsWith:
			if tokens[2].Kind == tokenizer.TokStringLiteral {
				if !validateOnly {
					sel = &LabelStartsWithValueNode{tokens[0].Value, tokens[2].Value}
				}
				remTokens = tokens[3:]
			} else {
				err = ErrExpectedString
			}
		case tokenizer.TokEndsWith:
			if tokens[2].Kind == tokenizer.TokStringLiteral {
				if !validateOnly {
					sel = &LabelEndsWithValueNode{tokens[0].Value, tokens[2].Value}
				}
				remTokens = tokens[3:]
			} else {
				err = ErrExpectedString
			}
		case tokenizer.TokIn, tokenizer.TokNotIn:
			if tokens[2].Kind == tokenizer.TokLBrace {
				remTokens = tokens[3:]
				values := []string{}
				for {
					if remTokens[0].Kind == tokenizer.TokStringLiteral {
						value := remTokens[0].Value
						values = append(values, value)
						remTokens = remTokens[1:]
						if remTokens[0].Kind == tokenizer.TokComma {
							remTokens = remTokens[1:]
						} else {
							break
						}
					} else {
						break
					}
				}
				if remTokens[0].Kind != tokenizer.TokRBrace {
					err = ErrExpectedRBrace
				} else {
					// Skip over the }
					remTokens = remTokens[1:]

					labelName := tokens[0].Value
					set := ConvertToStringSetInPlace(values) // Mutates values.
					if tokens[1].Kind == tokenizer.TokIn {
						if !validateOnly {
							sel = &LabelInSetNode{labelName, set}
						}
					} else {
						if !validateOnly {
							sel = &LabelNotInSetNode{labelName, set}
						}
					}
				}
			} else {
				err = ErrExpectedSetLit
			}
		default:
			err = fmt.Errorf("expected == or != not: %v", tokens[1])
			return
		}
	case tokenizer.TokLParen:
		// We hit a paren, skip past it, then recurse.
		sel, remTokens, err = p.parseOrExpression(tokens[1:], validateOnly)
		if err != nil {
			return
		}
		// After parsing the nested expression, there should be
		// a matching paren.
		if len(remTokens) < 1 || remTokens[0].Kind != tokenizer.TokRParen {
			err = ErrExpectedRParen
			return
		}
		remTokens = remTokens[1:]
	default:
		err = fmt.Errorf("unexpected token: %v", tokens[0])
		return
	}
	if negated && err == nil {
		if !validateOnly {
			sel = &NotNode{sel}
		}
	}
	return
}
