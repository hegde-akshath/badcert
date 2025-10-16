package godebug

type Setting struct {
    name  string
    value string
}

var defaultSettings = map[string]string{
    "x509usepolicies"      : "0",
    "x509sha256skid"       : "1",
    "x509usefallbackroots" : "0",
    "x509rsacrt"           : "0",
    "x509negativeserial"   : "1",
}

func New(name string) *Setting {
     return &Setting{name: name}
}

func (s *Setting) Name() string {
     if s.name != "" && s.name[0] == '#' {
         return s.name[1:]
     }
     return s.name
}

func (s *Setting) Value() string {
     value, ok := defaultSettings[s.name]
     if ok {
	     return value
     } 
     return ""
}

func (s *Setting) IncNonDefault() {
    return
}
