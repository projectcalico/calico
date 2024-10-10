package main

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/doc"
	"go/parser"
	"go/token"
	"os"
	"regexp"
	"sort"
	"strings"
)

type docField struct {
	Name     string
	comment  string
	Doc      string
	DefaultV string
}

func main() {
	if len(os.Args) != 5 {
		fmt.Fprintf(os.Stderr, "Usage docs-parser <doc_file> <type> <def_file> <type>\n")
		return
	}

	fname := os.Args[1]
	tname := os.Args[2]
	fset := token.NewFileSet()

	astF, err := parser.ParseFile(fset, fname, nil, parser.ParseComments)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse the source file: %s\n", err)
		return
	}

	pkg, err := doc.NewFromFiles(fset, []*ast.File{astF}, "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate docs from source file: %s\n", err)
		return
	}

	var dt *doc.Type

	for _, t := range pkg.Types {
		if t.Name == tname {
			dt = t
			break
		}
	}

	if dt == nil {
		fmt.Fprintf(os.Stderr, "Source file does not contain type: %s\n", tname)
		return
	}

	fields := make(map[string]docField)
	defRegexp := regexp.MustCompile(`(.*)\s*\[[dD]efault:\s*(.*)\]`)

	ast.Inspect(dt.Decl, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.Field:
			f := docField{
				Name:    x.Names[0].Name,
				comment: x.Doc.Text(),
			}

			c := ""
			lines := strings.Split(f.comment, "\n")
			for i, l := range lines {
				if len(l) > 0 && l[0] != '+' {
					if i > 0 {
						c += " "
					}
					c += l
				}
			}

			m := defRegexp.FindStringSubmatch(c)
			if len(m) == 3 {
				f.Doc = m[1]
				f.DefaultV = m[2]
			} else {
				f.Doc = c
			}

			fields[x.Names[0].Name] = f
		}

		return true
	})

	fname = os.Args[3]
	tname = os.Args[4]
	fset = token.NewFileSet()

	astF, err = parser.ParseFile(fset, fname, nil, parser.ParseComments)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse the source file: %s\n", err)
		return
	}

	pkg, err = doc.NewFromFiles(fset, []*ast.File{astF}, "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate docs from source file: %s\n", err)
		return
	}

	dt = nil
	for _, t := range pkg.Types {
		if t.Name == tname {
			dt = t
			break
		}
	}

	if dt == nil {
		fmt.Fprintf(os.Stderr, "Source file does not contain type: %s\n", tname)
		return
	}

	tagRegexp := regexp.MustCompile(`.config:"[^;]*;([^;"]+)`)

	ast.Inspect(dt.Decl, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.Field:
			name := x.Names[0].Name
			f, ok := fields[name]
			if !ok {
				return true
			}
			if x.Tag == nil {
				return true
			}

			tag := x.Tag.Value
			m := tagRegexp.FindStringSubmatch(tag)
			if len(m) > 0 {
				f.DefaultV = m[1]
				fields[name] = f
			}
		}

		return true
	})

	list := make([]docField, 0, len(fields))

	for _, f := range fields {
		list = append(list, f)
	}

	sort.Slice(list, func(i, j int) bool {
		return list[i].Name < list[j].Name
	})

	jsonData, err := json.MarshalIndent(list, "", "    ")

	fmt.Println(string(jsonData))
}
