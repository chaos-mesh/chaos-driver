package build

var Targets map[string]Script = make(map[string]Script)

type Script interface {
	Script(release string, buildDir string, version uint16) (string, error)
}
