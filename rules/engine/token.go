package engine

import (
	"errors"
	"time"
)

// Kind is the kind of a token.
type Kind uint8

const (
	Ident   Kind = iota // names and keywords
	Var                 // PHP variable, with its "$"
	Num                 // number literal
	Str                 // string literal (also PHP backtick commands and JS regex literals)
	Op                  // punctuation and operators
	Newline             // Python: end of a logical line
	Indent              // Python: the block gets deeper
	Dedent              // Python: the block ends
	Func                // a function literal the parser took out of an expression
)

// Token flags.
const (
	FlagOpen  uint8 = 1 << iota // the string or comment has no end (only accepted in rule patterns)
	FlagShell                   // PHP `command`
	FlagRegex                   // JS /regex/
	FlagNL                      // first token on its line (JS statement ends)
)

// Token is one lexical unit. Comments are dropped. A string literal keeps its raw
// content in Text (between the quotes, escapes untouched); its interpolations
// ("$x", "{$x}", f"{x}", `${x}`) are lexed as code into Parts.
type Token struct {
	Kind  Kind
	Flags uint8
	Line  int
	Text  string
	Parts []Part
	Fn    int // Func: index into the statement's function literals
}

// Part is an interpolation inside a string literal: Off is its byte offset in the
// string's Text, Toks the code it holds.
type Part struct {
	Off  int
	Toks []Token
}

func (t Token) is(kind Kind, text string) bool { return t.Kind == kind && t.Text == text }
func (t Token) op(text string) bool            { return t.Kind == Op && t.Text == text }
func (t Token) word(text string) bool          { return t.Kind == Ident && t.Text == text }

// Limits bound the work done on one file, so a huge or hostile file cannot stall a scan.
type Limits struct {
	MaxTokens int           // tokens per file, counting those inside string interpolations
	MaxTime   time.Duration // lexing, parsing and analysis of one file, all rules together
}

// DefaultLimits suit ordinary application files; the caller also caps file size.
var DefaultLimits = Limits{MaxTokens: 300_000, MaxTime: 3 * time.Second}

// ErrLimit means a file hit Limits and was only partly analysed.
var ErrLimit = errors.New("engine: file too large or too slow to analyse")

const maxNest = 24 // interpolation and block nesting; deeper code is read flat or skipped

type budget struct {
	tokens   int
	maxTok   int
	deadline time.Time
	steps    int
	hit      bool
}

func newBudget(l Limits) *budget {
	if l.MaxTokens <= 0 {
		l.MaxTokens = DefaultLimits.MaxTokens
	}
	if l.MaxTime <= 0 {
		l.MaxTime = DefaultLimits.MaxTime
	}
	return &budget{maxTok: l.MaxTokens, deadline: time.Now().Add(l.MaxTime)}
}

// token counts one token; false once the cap is hit.
func (b *budget) token() bool {
	if b == nil {
		return true
	}
	b.tokens++
	if b.tokens > b.maxTok {
		b.hit = true
	}
	return !b.hit
}

func (b *budget) hitLimit() bool { return b != nil && b.hit }

// step is called in every loop of the parser and analysis; false once time is up.
func (b *budget) step() bool {
	if b == nil {
		return true
	}
	if b.hit {
		return false
	}
	b.steps++
	if b.steps&1023 == 0 && time.Now().After(b.deadline) {
		b.hit = true
	}
	return !b.hit
}

// scanner is the cursor shared by the three lexers.
type scanner struct {
	src   string
	pos   int
	line  int
	nl    bool // next token starts a line
	toks  []Token
	b     *budget
	depth int // interpolation nesting
}

func (s *scanner) peek(off int) byte {
	if s.pos+off < len(s.src) {
		return s.src[s.pos+off]
	}
	return 0
}

func (s *scanner) has(prefix string) bool {
	return len(s.src)-s.pos >= len(prefix) && s.src[s.pos:s.pos+len(prefix)] == prefix
}

func (s *scanner) emit(t Token) bool {
	if s.nl {
		t.Flags |= FlagNL
		s.nl = false
	}
	s.toks = append(s.toks, t)
	return s.b.token()
}

// advance moves over n bytes, counting newlines.
func (s *scanner) advance(n int) {
	end := s.pos + n
	if end > len(s.src) {
		end = len(s.src)
	}
	for ; s.pos < end; s.pos++ {
		if s.src[s.pos] == '\n' {
			s.line++
		}
	}
}

// skipLine moves to the newline ending the line (not past it).
func (s *scanner) skipLine() {
	for s.pos < len(s.src) && s.src[s.pos] != '\n' {
		s.pos++
	}
}

// skipBlockComment moves past "*/", or to the end when there is none.
func (s *scanner) skipBlockComment() {
	s.advance(2)
	for s.pos < len(s.src) {
		if s.has("*/") {
			s.pos += 2
			return
		}
		s.advance(1)
	}
}

func isIdentStart(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= 0x80
}

func isIdentChar(c byte) bool { return isIdentStart(c) || c >= '0' && c <= '9' }

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// ident reads a name made of identifier characters (plus extra bytes such as '$' in JS).
func (s *scanner) ident(extra string) string {
	start := s.pos
	for s.pos < len(s.src) {
		c := s.src[s.pos]
		if !isIdentChar(c) && !containsByte(extra, c) {
			break
		}
		s.pos++
	}
	return s.src[start:s.pos]
}

// number reads a numeric literal loosely: identifier characters and '.', plus a
// sign after an exponent.
func (s *scanner) number() string {
	start := s.pos
	hex := s.has("0x") || s.has("0X")
	for s.pos < len(s.src) {
		c := s.src[s.pos]
		switch {
		case isIdentChar(c), c == '.' && isDigit(s.peek(1)):
		case (c == '+' || c == '-') && !hex && s.pos > start && (s.src[s.pos-1] == 'e' || s.src[s.pos-1] == 'E'):
		default:
			return s.src[start:s.pos]
		}
		s.pos++
	}
	return s.src[start:s.pos]
}

// operator reads the longest operator from ops (sorted longest first), or one byte.
func (s *scanner) operator(ops []string) string {
	for _, o := range ops {
		if s.has(o) {
			s.pos += len(o)
			return o
		}
	}
	s.pos++
	return s.src[s.pos-1 : s.pos]
}

func containsByte(set string, c byte) bool {
	for i := 0; i < len(set); i++ {
		if set[i] == c {
			return true
		}
	}
	return false
}
