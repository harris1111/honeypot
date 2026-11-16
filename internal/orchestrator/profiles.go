package orchestrator

// TrapProfile defines an allowlisted container trap template pinned by image repo/tag.
type TrapProfile struct {
	Kind           string
	Image          string
	DefaultPort    uint32
	Protocol       string
	ContainerPort  string
	ExtraHostPorts map[string]uint32
	User           string
	AllowedEnv     []string
}

var BuiltinProfiles = map[string]TrapProfile{
	"cowrie": {
		Kind:           "cowrie",
		Image:          "cowrie/cowrie:latest",
		DefaultPort:    22,
		Protocol:       "tcp",
		ContainerPort:  "2222/tcp",
		ExtraHostPorts: map[string]uint32{"2223/tcp": 23},
		User:           "1000:1000",
		AllowedEnv:     []string{"COWRIE_SSH_ENABLED", "COWRIE_TELNET_ENABLED", "PYTHONDONTWRITEBYTECODE", "TZ"},
	},
	"heralding": {
		Kind:           "heralding",
		Image:          "honeypot/heralding:24.04.2",
		DefaultPort:    21,
		Protocol:       "tcp",
		ContainerPort:  "2121/tcp",
		ExtraHostPorts: map[string]uint32{"2525/tcp": 25, "2110/tcp": 110, "2143/tcp": 143},
		User:           "2000:2000",
		AllowedEnv:     []string{"HERALDING_FTP", "HERALDING_SMTP", "HERALDING_POP3", "HERALDING_IMAP", "PYTHONDONTWRITEBYTECODE", "TZ"},
	},
}
