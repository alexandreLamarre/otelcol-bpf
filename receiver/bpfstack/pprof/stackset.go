package pprof

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/google/pprof/profile"
)

// StackSet holds a set of stacks corresponding to a profile.
//
// Slices in StackSet and the types it contains are always non-nil,
// which makes Javascript code that uses the JSON encoding less error-prone.
type StackSet struct {
	Total   int64         // Total value of the profile.
	Scale   float64       // Multiplier to generate displayed value
	Type    string        // Profile type. E.g., "cpu".
	Unit    string        // One of "B", "s", "GCU", or "" (if unknown)
	Stacks  []Stack       // List of stored stacks
	Sources []StackSource // Mapping from source index to info
}

// Stack holds a single stack instance.
type Stack struct {
	Value   int64 // Total value for all samples of this stack.
	Sources []int // Indices in StackSet.Sources (callers before callees).
}

// StackSource holds function/location info for a stack entry.
type StackSource struct {
	FullName   string
	FileName   string
	UniqueName string // Disambiguates functions with same names
	Inlined    bool   // If true this source was inlined into its caller

	// Alternative names to display (with decreasing lengths) to make text fit.
	// Guaranteed to be non-empty.
	Display []string

	// Places holds the list of stack slots where this source occurs.
	// In particular, if [a,b] is an element in Places,
	// StackSet.Stacks[a].Sources[b] points to this source.
	//
	// No stack will be referenced twice in the Places slice for a given
	// StackSource. In case of recursion, Places will contain the outer-most
	// entry in the recursive stack. E.g., if stack S has source X at positions
	// 4,6,9,10, the Places entry for X will contain [S,4].
	Places []StackSlot

	// Combined count of stacks where this source is the leaf.
	Self int64

	// Color number to use for this source.
	// Colors with high numbers than supported may be treated as zero.
	Color int
}

// StackSlot identifies a particular StackSlot.
type StackSlot struct {
	Stack int // Index in StackSet.Stacks
	Pos   int // Index in Stack.Sources
}

func (s *StackSet) MakeInitialStacks(prof *profile.Profile, sampleValue sampleValueFunc) {
	type key struct {
		line    profile.Line
		inlined bool
	}
	srcs := map[key]int{} // Sources identified so far.
	seenFunctions := map[string]bool{}
	unknownIndex := 1
	getSrc := func(line profile.Line, inlined bool) int {
		k := key{line, inlined}
		if i, ok := srcs[k]; ok {
			return i
		}
		x := StackSource{Places: []StackSlot{}} // Ensure Places is non-nil
		if fn := line.Function; fn != nil {
			x.FullName = fn.Name
			x.FileName = fn.Filename
			if !seenFunctions[fn.Name] {
				x.UniqueName = fn.Name
				seenFunctions[fn.Name] = true
			} else {
				// Assign a different name so pivoting picks this function.
				x.UniqueName = fmt.Sprint(fn.Name, "#", fn.ID)
			}
		} else {
			x.FullName = fmt.Sprintf("?%d?", unknownIndex)
			x.UniqueName = x.FullName
			unknownIndex++
		}
		x.Inlined = inlined
		x.Display = shortNameList(x.FullName)
		s.Sources = append(s.Sources, x)
		srcs[k] = len(s.Sources) - 1
		return len(s.Sources) - 1
	}

	// Synthesized root location that will be placed at the beginning of each stack.
	s.Sources = []StackSource{{
		FullName: "root",
		Display:  []string{"root"},
		Places:   []StackSlot{},
	}}

	for _, sample := range prof.Sample {
		value := sampleValue(sample.Value)
		stack := Stack{Value: value, Sources: []int{0}} // Start with the root

		// Note: we need to reverse the order in the produced stack.
		for i := len(sample.Location) - 1; i >= 0; i-- {
			loc := sample.Location[i]
			for j := len(loc.Line) - 1; j >= 0; j-- {
				line := loc.Line[j]
				inlined := (j != len(loc.Line)-1)
				stack.Sources = append(stack.Sources, getSrc(line, inlined))
			}
		}

		leaf := stack.Sources[len(stack.Sources)-1]
		s.Sources[leaf].Self += value
		s.Stacks = append(s.Stacks, stack)
	}
}

func (s *StackSet) FillPlaces() {
	for i, stack := range s.Stacks {
		seenSrcs := map[int]bool{}
		for j, src := range stack.Sources {
			if seenSrcs[src] {
				continue
			}
			seenSrcs[src] = true
			s.Sources[src].Places = append(s.Sources[src].Places, StackSlot{i, j})
		}
	}
}

var sepRE = regexp.MustCompile(`::|\.`)

// shortNameList returns a non-empty sequence of shortened names
// (in decreasing preference) that can be used to represent name.
func shortNameList(name string) []string {
	name = ShortenFunctionName(name)
	seps := sepRE.FindAllStringIndex(name, -1)
	result := make([]string, 0, len(seps)+1)
	result = append(result, name)
	for _, sep := range seps {
		// Suffix starting just after sep
		if sep[1] < len(name) {
			result = append(result, name[sep[1]:])
		}
	}
	return result
}

// ShortenFunctionName returns a shortened version of a function's name.
func ShortenFunctionName(f string) string {
	f = cppAnonymousPrefixRegExp.ReplaceAllString(f, "")
	f = goVerRegExp.ReplaceAllString(f, `${1}${2}`)
	for _, re := range []*regexp.Regexp{goRegExp, javaRegExp, cppRegExp} {
		if matches := re.FindStringSubmatch(f); len(matches) >= 2 {
			return strings.Join(matches[1:], "")
		}
	}
	return f
}

var (
	// Removes package name and method arguments for Java method names.
	// See tests for examples.
	javaRegExp = regexp.MustCompile(`^(?:[a-z]\w*\.)*([A-Z][\w\$]*\.(?:<init>|[a-z][\w\$]*(?:\$\d+)?))(?:(?:\()|$)`)
	// Removes package name and method arguments for Go function names.
	// See tests for examples.
	goRegExp = regexp.MustCompile(`^(?:[\w\-\.]+\/)+([^.]+\..+)`)
	// Removes potential module versions in a package path.
	goVerRegExp = regexp.MustCompile(`^(.*?)/v(?:[2-9]|[1-9][0-9]+)([./].*)$`)
	// Strips C++ namespace prefix from a C++ function / method name.
	// NOTE: Make sure to keep the template parameters in the name. Normally,
	// template parameters are stripped from the C++ names but when
	// -symbolize=demangle=templates flag is used, they will not be.
	// See tests for examples.
	cppRegExp                = regexp.MustCompile(`^(?:[_a-zA-Z]\w*::)+(_*[A-Z]\w*::~?[_a-zA-Z]\w*(?:<.*>)?)`)
	cppAnonymousPrefixRegExp = regexp.MustCompile(`^\(anonymous namespace\)::`)
)

type sampleValueFunc func(s []int64) int64

// sampleFormat returns a function to extract values out of a profile.Sample,
// and the type/units of those values.
func SampleFormat(p *profile.Profile, sampleIndex string, mean bool) (value, meanDiv sampleValueFunc, v *profile.ValueType, err error) {
	if len(p.SampleType) == 0 {
		return nil, nil, nil, fmt.Errorf("profile has no samples")
	}
	index, err := p.SampleIndexByName(sampleIndex)
	if err != nil {
		return nil, nil, nil, err
	}
	value = valueExtractor(index)
	if mean {
		meanDiv = valueExtractor(0)
	}
	v = p.SampleType[index]
	return
}

func valueExtractor(ix int) sampleValueFunc {
	return func(v []int64) int64 {
		return v[ix]
	}
}
