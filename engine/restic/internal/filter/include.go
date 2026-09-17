package filter

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/restic/restic/internal/errors"
	"github.com/spf13/pflag"
)

// IncludeByNameFunc is a function that takes a filename that should be included
// in the restore process and returns whether it should be included.
type IncludeByNameFunc func(item string) (matched bool, childMayMatch bool)

type IncludePatternOptions struct {
	Includes                []string
	InsensitiveIncludes     []string
	IncludeFiles            []string
	IncludeFilesRaw         []string
	InsensitiveIncludeFiles []string
}

func (opts *IncludePatternOptions) Add(f *pflag.FlagSet) {
	f.StringArrayVarP(&opts.Includes, "include", "i", nil, "include a `pattern` (can be specified multiple times)")
	f.StringArrayVar(&opts.InsensitiveIncludes, "iinclude", nil, "same as --include `pattern` but ignores the casing of filenames")
	f.StringArrayVar(&opts.IncludeFiles, "include-file", nil, "read include patterns from a `file` (can be specified multiple times)")
	f.StringArrayVar(&opts.IncludeFilesRaw, "include-file-raw", nil, "read exact NUL-terminated paths from a `file` (can be specified multiple times)")
	f.StringArrayVar(&opts.InsensitiveIncludeFiles, "iinclude-file", nil, "same as --include-file but ignores casing of `file`names in patterns")
}

func (opts *IncludePatternOptions) Empty() bool {
	return len(opts.Includes) == 0 && len(opts.InsensitiveIncludes) == 0 && len(opts.IncludeFiles) == 0 && len(opts.IncludeFilesRaw) == 0 && len(opts.InsensitiveIncludeFiles) == 0
}

func (opts IncludePatternOptions) CollectPatterns(warnf func(msg string, args ...any)) ([]IncludeByNameFunc, error) {
	var fs []IncludeByNameFunc
	if len(opts.IncludeFilesRaw) > 0 {
		paths, err := readRawPathsFromFiles(opts.IncludeFilesRaw)
		if err != nil {
			return nil, errors.Fatalf("--include-file-raw: %s", err)
		}
		fs = append(fs, IncludeByPath(paths))
	}

	if len(opts.IncludeFiles) > 0 {
		includePatterns, err := readPatternsFromFiles(opts.IncludeFiles)
		if err != nil {
			return nil, err
		}

		if err := ValidatePatterns(includePatterns); err != nil {
			return nil, errors.Fatalf("--include-file: %s", err)
		}

		opts.Includes = append(opts.Includes, includePatterns...)
	}

	if len(opts.InsensitiveIncludeFiles) > 0 {
		includePatterns, err := readPatternsFromFiles(opts.InsensitiveIncludeFiles)
		if err != nil {
			return nil, err
		}

		if err := ValidatePatterns(includePatterns); err != nil {
			return nil, errors.Fatalf("--iinclude-file: %s", err)
		}

		opts.InsensitiveIncludes = append(opts.InsensitiveIncludes, includePatterns...)
	}

	if len(opts.InsensitiveIncludes) > 0 {
		if err := ValidatePatterns(opts.InsensitiveIncludes); err != nil {
			return nil, errors.Fatalf("--iinclude: %s", err)
		}

		fs = append(fs, IncludeByInsensitivePattern(opts.InsensitiveIncludes, warnf))
	}

	if len(opts.Includes) > 0 {
		if err := ValidatePatterns(opts.Includes); err != nil {
			return nil, errors.Fatalf("--include: %s", err)
		}

		fs = append(fs, IncludeByPattern(opts.Includes, warnf))
	}
	return fs, nil
}

func readRawPathsFromFiles(files []string) ([]string, error) {
	var paths []string
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		if len(data) == 0 || data[len(data)-1] != 0 {
			return nil, errors.Errorf("%s: trailing zero byte missing", file)
		}
		for _, path := range bytes.Split(data[:len(data)-1], []byte{0}) {
			if len(path) == 0 {
				return nil, errors.Errorf("%s: empty path", file)
			}
			paths = append(paths, string(path))
		}
	}
	return paths, nil
}

// IncludeByPath selects exact paths while still descending through their parents.
// Unlike patterns, path names containing glob metacharacters are treated literally.
func IncludeByPath(paths []string) IncludeByNameFunc {
	cleaned := make([]string, 0, len(paths))
	for _, path := range paths {
		cleaned = append(cleaned, filepath.ToSlash(filepath.Clean(path)))
	}
	slices.Sort(cleaned)
	cleaned = slices.Compact(cleaned)

	return func(item string) (matched bool, childMayMatch bool) {
		item = filepath.ToSlash(filepath.Clean(item))
		_, matched = slices.BinarySearch(cleaned, item)
		prefix := item
		if prefix != "/" {
			prefix += "/"
		}
		i, _ := slices.BinarySearch(cleaned, prefix)
		return matched, i < len(cleaned) && strings.HasPrefix(cleaned[i], prefix)
	}
}

// IncludeByPattern returns an IncludeByNameFunc which includes files that match
// one of the patterns.
func IncludeByPattern(patterns []string, warnf func(msg string, args ...any)) IncludeByNameFunc {
	parsedPatterns := ParsePatterns(patterns)
	return func(item string) (matched bool, childMayMatch bool) {
		matched, childMayMatch, err := ListWithChild(parsedPatterns, item)
		if err != nil {
			warnf("error for include pattern: %v", err)
		}

		return matched, childMayMatch
	}
}

// IncludeByInsensitivePattern returns an IncludeByNameFunc which includes files that match
// one of the patterns, ignoring the casing of the filenames.
func IncludeByInsensitivePattern(patterns []string, warnf func(msg string, args ...any)) IncludeByNameFunc {
	lowerPatterns := make([]string, len(patterns))
	for index, path := range patterns {
		lowerPatterns[index] = strings.ToLower(path)
	}

	includeFunc := IncludeByPattern(lowerPatterns, warnf)
	return func(item string) (matched bool, childMayMatch bool) {
		return includeFunc(strings.ToLower(item))
	}
}
