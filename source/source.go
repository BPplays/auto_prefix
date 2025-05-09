package source

import "errors"

type Source struct{ slug string }

func (r Source) String() string { return r.slug }

var (
    Unknown   = Source{""}
    File     = Source{"File"}
    Url     = Source{"url"}
)

func FromString(s string) (Source, error) {
    switch s {
    case File.slug:
        return File, nil
    case Url.slug:
        return Url, nil
    }
    return Unknown, errors.New("unknown role: " + s)
}
