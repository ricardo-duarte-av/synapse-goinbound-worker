package pdustore

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

// TestReadOnly: every query here is a SELECT, apart from the one SET LOCAL
// that turns off sequential scans for a state group walk, and every
// transaction is opened read-only.
func TestReadOnly(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	queries := 0
	for _, pkg := range pkgs {
		for name, file := range pkg.Files {
			src, _ := os.ReadFile(name)
			ast.Inspect(file, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.ValueSpec:
					for i, id := range n.Names {
						if !strings.HasPrefix(id.Name, "q") || i >= len(n.Values) {
							continue
						}
						lit, ok := n.Values[i].(*ast.BasicLit)
						if !ok || lit.Kind != token.STRING {
							continue
						}
						sql, _ := strconv.Unquote(lit.Value)
						sql = strings.TrimSpace(sql)
						queries++
						if !strings.HasPrefix(strings.ToUpper(sql), "SELECT") &&
							!strings.HasPrefix(strings.ToUpper(sql), "WITH RECURSIVE") &&
							sql != "SET LOCAL enable_seqscan = off" {
							t.Errorf("%s: %s is not a read: %s", name, id.Name, sql)
						}
					}
				case *ast.CallExpr:
					sel, ok := n.Fun.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					switch sel.Sel.Name {
					case "BeginTx":
						call := string(src[fset.Position(n.Pos()).Offset:fset.Position(n.End()).Offset])
						if !strings.Contains(call, "pgx.ReadOnly") {
							t.Errorf("%s: transaction not opened read-only: %s", fset.Position(n.Pos()), call)
						}
					case "Begin", "CopyFrom", "SendBatch":
						t.Errorf("%s: calls %s", fset.Position(n.Pos()), sel.Sel.Name)
					}
				}
				return true
			})
		}
	}
	if queries == 0 {
		t.Fatal("found no queries")
	}
}
