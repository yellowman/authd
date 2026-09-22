package docsite

import (
	"io/fs"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"
)

// The tree, not a path registry or app-specific category switch, owns the index.
func TestIndexComesFromDirectoriesAndMarkdown(t *testing.T) {
	src := fstest.MapFS{
		"README.md":                           {Data: []byte("# A title authored in Markdown\n")},
		StartDocument:                         {Data: []byte("# Adding an app to authd\n")},
		"docs/operations/ZED.md":              {Data: []byte("# Zed\n")},
		"docs/operations/ALPHA.md":            {Data: []byte("# Alpha\n")},
		"docs/operations/no-heading.MD":       {Data: []byte("A document without a heading.\n")},
		"deploy/new-platform/notes/README.md": {Data: []byte("# A new deployment guide\n")},
		"docs/operations/result.log":          {Data: []byte("evidence is not a Markdown index row")},
	}
	l, err := New(src)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, group := range l.Groups("") {
		for _, e := range group.Entries {
			got = append(got, group.Name+"|"+e.Path)
		}
	}
	want := []string{
		".|README.md",
		"deploy/new-platform/notes|deploy/new-platform/notes/README.md",
		"docs|" + StartDocument,
		"docs/operations|docs/operations/ALPHA.md",
		"docs/operations|docs/operations/ZED.md",
		"docs/operations|docs/operations/no-heading.MD",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("directory/file listing:\n got %v\nwant %v", got, want)
	}
	d, _ := l.Document("README.md")
	if d.Title != "A title authored in Markdown" {
		t.Fatal("title did not come from source")
	}
	d, _ = l.Document("docs/operations/no-heading.MD")
	if d.Title != "no-heading.MD" {
		t.Fatal("missing filename fallback")
	}
	if l.Count() != 6 {
		t.Fatalf("Markdown count = %d", l.Count())
	}
}

func TestIndexFollowsAddedRenamedEditedAndRemovedFiles(t *testing.T) {
	src := fstest.MapFS{"docs/one.md": {Data: []byte("# Old heading\n")}}
	old, err := New(src)
	if err != nil {
		t.Fatal(err)
	}
	delete(src, "docs/one.md")
	src["docs/new-directory/two.md"] = &fstest.MapFile{Data: []byte("# New heading\n\nSearchable narwhal.\n")}
	next, err := New(src)
	if err != nil {
		t.Fatal(err)
	}
	if _, found := next.Document("docs/one.md"); found {
		t.Fatal("deleted path still published")
	}
	if _, found := old.Document("docs/one.md"); !found {
		t.Fatal("published release snapshot mutated")
	}
	groups := next.Groups("narwhal two.md")
	if len(groups) != 1 || groups[0].Name != "docs/new-directory" || len(groups[0].Entries) != 1 || groups[0].Entries[0].Title != "New heading" {
		t.Fatalf("new file not discovered: %+v", groups)
	}
	groups[0].Entries[0].Title = "mutated"
	if next.Groups("narwhal")[0].Entries[0].Title != "New heading" {
		t.Fatal("caller mutated directory index")
	}
}

func TestIndexOnlyListsMarkdownAndRejectsDocumentSymlinks(t *testing.T) {
	l, err := New(fstest.MapFS{
		"docs/one.md":                          {Data: []byte("# One")},
		"docs/empty-log-dir/result.log":        {Data: []byte("PASS")},
		"docs/not-markdown.md.txt":             {Data: []byte("# Not Markdown")},
		"docs/secret.env":                      {Data: []byte("secret")},
		"deploy/future-platform/runtime.json":  {Data: []byte(`{"secret":"not documentation"}`)},
		"deploy/future-platform/passwords.txt": {Data: []byte("not documentation")},
	})
	if err != nil {
		t.Fatal(err)
	}
	groups := l.Groups("")
	if len(groups) != 1 || groups[0].Name != "docs" || len(groups[0].Entries) != 1 {
		t.Fatalf("non-Markdown indexed: %+v", groups)
	}
	for _, name := range []string{"docs/secret.env", "deploy/future-platform/runtime.json", "deploy/future-platform/passwords.txt"} {
		if _, ok := l.Source(name); ok {
			t.Fatalf("non-document file exposed: %s", name)
		}
	}
	if _, err = New(fstest.MapFS{"docs/link.md": {Mode: fs.ModeSymlink, Data: []byte("/etc/passwd")}}); err == nil {
		t.Fatal("document symlink accepted")
	}
	if len(l.Groups(strings.Repeat("absent", 4))) != 0 {
		t.Fatal("unexpected search result")
	}
}
