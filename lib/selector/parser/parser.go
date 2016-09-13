// Copyright (c) 2016 Tigera, Inc. All rights reserved.

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

	log "github.com/Sirupsen/logrus"
	. "github.com/tigera/libcalico-go/lib/selector/tokenizer"
)

const parserDebug = false

// Parse a string representation of a selector expression into a Selector.
func Parse(selector string) (sel Selector, err error) {
	log.Debugf("Parsing %#v", selector)
	tokens, err := Tokenize(selector)
	if err != nil {
		return
	}
	if tokens[0].Kind == TokEof {
		return selectorRoot{root: AllNode{}}, nil
	}
	log.Debugf("Tokens %v", tokens)
	// The "||" operator has the lowest precedence so we start with that.
	node, remTokens, err := parseOrExpression(tokens)
	if err != nil {
		return
	}
	if len(remTokens) != 1 {
		err = errors.New(fmt.Sprint("unexpected content at end of selector ", remTokens))
		return
	}
	sel = selectorRoot{root: node}
	return
}

// parseOrExpression parses a one or more "&&" terms, separated by "||" operators.
func parseOrExpression(tokens []Token) (sel node, remTokens []Token, err error) {
	if parserDebug {
		log.Debugf("Parsing ||s from %v", tokens)
	}
	// Look for the first expression.
	andNodes := make([]node, 0)
	sel, remTokens, err = parseAndExpression(tokens)
	if err != nil {
		return
	}
	andNodes = append(andNodes, sel)

	// Then loop looking for "||" followed by an <expression>
	for {
		switch remTokens[0].Kind {
		case TokOr:
			remTokens = remTokens[1:]
			sel, remTokens, err = parseAndExpression(remTokens)
			if err != nil {
				return
			}
			andNodes = append(andNodes, sel)
		default:
			if len(andNodes) == 1 {
				sel = andNodes[0]
			} else {
				sel = OrNode{andNodes}
			}
			return
		}
	}
}

// parseAndExpression parses a one or more operations, separated by "&&" operators.
func parseAndExpression(tokens []Token) (sel node, remTokens []Token, err error) {
	if parserDebug {
		log.Debugf("Parsing &&s from %v", tokens)
	}
	// Look for the first operation.
	opNodes := make([]node, 0)
	sel, remTokens, err = parseOperation(tokens)
	if err != nil {
		return
	}
	opNodes = append(opNodes, sel)

	// Then loop looking for "&&" followed by another operation.
	for {
		switch remTokens[0].Kind {
		case TokAnd:
			remTokens = remTokens[1:]
			sel, remTokens, err = parseOperation(remTokens)
			if err != nil {
				return
			}
			opNodes = append(opNodes, sel)
		default:
			if len(opNodes) == 1 {
				sel = opNodes[0]
			} else {
				sel = AndNode{opNodes}
			}
			return
		}
	}
}

// parseOperations parses a single, possibly negated operation (i.e. ==, !=, has()).
// It also handles calling parseOrExpression recursively for parenthesized expressions.
func parseOperation(tokens []Token) (sel node, remTokens []Token, err error) {
	if parserDebug {
		log.Debugf("Parsing op from %v", tokens)
	}
	if len(tokens) == 0 {
		err = errors.New("Unexpected end of string looking for op")
		return
	}

	// First, collapse any leading "!" operators to a single boolean.
	negated := false
	for {
		if tokens[0].Kind == TokNot {
			negated = !negated
			tokens = tokens[1:]
		} else {
			break
		}
	}

	// Then, look for the various types of operator.
	switch tokens[0].Kind {
	case TokHas:
		sel = HasNode{tokens[0].Value.(string)}
		remTokens = tokens[1:]
	case TokAll:
		sel = AllNode{}
		remTokens = tokens[1:]
	case TokLabel:
		// should have an operator and a literal.
		if len(tokens) < 3 {
			err = errors.New(fmt.Sprint("Unexpected end of string in middle of op", tokens))
			return
		}
		switch tokens[1].Kind {
		case TokEq:
			if tokens[2].Kind == TokStringLiteral {
				sel = LabelEqValueNode{tokens[0].Value.(string), tokens[2].Value.(string)}
				remTokens = tokens[3:]
			} else {
				err = errors.New("Expected string")
			}
		case TokNe:
			if tokens[2].Kind == TokStringLiteral {
				sel = LabelNeValueNode{tokens[0].Value.(string), tokens[2].Value.(string)}
				remTokens = tokens[3:]
			} else {
				err = errors.New("Expected string")
			}
		case TokIn, TokNotIn:
			if tokens[2].Kind == TokLBrace {
				remTokens = tokens[3:]
				set := make(map[string]bool)
				for {
					if remTokens[0].Kind == TokStringLiteral {
						set[remTokens[0].Value.(string)] = true
						remTokens = remTokens[1:]
						if remTokens[0].Kind == TokComma {
							remTokens = remTokens[1:]
						} else {
							break
						}
					} else {
						break
					}
				}
				if remTokens[0].Kind != TokRBrace {
					err = errors.New("Expected }")
				} else {
					// Skip over the }
					remTokens = remTokens[1:]

					if tokens[1].Kind == TokIn {
						sel = LabelInSetNode{tokens[0].Value.(string), set}
					} else {
						sel = LabelNotInSetNode{tokens[0].Value.(string), set}
					}
				}
			} else {
				err = errors.New("Expected set literal")
			}
		default:
			err = errors.New(fmt.Sprint("Expected == or != not ", tokens[1]))
			return
		}
	case TokLParen:
		// We hit a paren, skip past it, then recurse.
		sel, remTokens, err = parseOrExpression(tokens[1:])
		if err != nil {
			return
		}
		// After parsing the nested expression, there should be
		// a matching paren.
		if len(remTokens) < 1 || remTokens[0].Kind != TokRParen {
			err = errors.New("Expected )")
			return
		}
		remTokens = remTokens[1:]
	default:
		err = errors.New(fmt.Sprint("Unexpected token: ", tokens[0]))
		return
	}
	if negated && err == nil {
		sel = NotNode{sel}
	}
	return
}
