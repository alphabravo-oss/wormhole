package filter

import (
	"testing"
)

func TestIncludeByPattern(t *testing.T) {
	var tests = []struct {
		filename string
		include  bool
	}{
		{filename: "/home/user/foo.go", include: true},
		{filename: "/home/user/foo.c", include: false},
		{filename: "/home/user/foobar", include: false},
		{filename: "/home/user/foobar/x", include: false},
		{filename: "/home/user/README", include: false},
		{filename: "/home/user/README.md", include: true},
	}

	patterns := []string{"*.go", "README.md"}

	for _, tc := range tests {
		t.Run(tc.filename, func(t *testing.T) {
			includeFunc := IncludeByPattern(patterns, nil)
			matched, _ := includeFunc(tc.filename)
			if matched != tc.include {
				t.Fatalf("wrong result for filename %v: want %v, got %v",
					tc.filename, tc.include, matched)
			}
		})
	}
}

func TestIncludeByInsensitivePattern(t *testing.T) {
	var tests = []struct {
		filename string
		include  bool
	}{
		{filename: "/home/user/foo.GO", include: true},
		{filename: "/home/user/foo.c", include: false},
		{filename: "/home/user/foobar", include: false},
		{filename: "/home/user/FOObar/x", include: false},
		{filename: "/home/user/README", include: false},
		{filename: "/home/user/readme.MD", include: true},
	}

	patterns := []string{"*.go", "README.md"}

	for _, tc := range tests {
		t.Run(tc.filename, func(t *testing.T) {
			includeFunc := IncludeByInsensitivePattern(patterns, nil)
			matched, _ := includeFunc(tc.filename)
			if matched != tc.include {
				t.Fatalf("wrong result for filename %v: want %v, got %v",
					tc.filename, tc.include, matched)
			}
		})
	}
}

func TestIncludeByPath(t *testing.T) {
	include := IncludeByPath([]string{"/var/lib/app/[literal]", "/var/lib/app/sub/file\nname"})
	tests := []struct {
		path, want string
	}{
		{"/var", "child"},
		{"/var/lib/app", "child"},
		{"/var/lib/app/[literal]", "match"},
		{"/var/lib/app/sub", "child"},
		{"/var/lib/app/sub/file\nname", "match"},
		{"/var/lib/app/other", "none"},
	}
	for _, test := range tests {
		matched, child := include(test.path)
		got := "none"
		if matched {
			got = "match"
		} else if child {
			got = "child"
		}
		if got != test.want {
			t.Errorf("%q: want %s, got %s", test.path, test.want, got)
		}
	}
}
