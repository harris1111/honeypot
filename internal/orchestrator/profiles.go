package orchestrator

// TrapProfile defines an allowlisted container trap template pinned by image repo/tag.
type TrapProfile struct {
	Kind          string
	Image         string
	DefaultPort   uint32
	Protocol      string
	ContainerPort string
	User          string
	AllowedEnv    []string
}

var BuiltinProfiles = map[string]TrapProfile{
	"cowrie": {
		Kind:          "cowrie",
		Image:         "cowrie/cowrie:latest",
		DefaultPort:   22,
		Protocol:      "tcp",
		ContainerPort: "2222/tcp",
		User:          "1000:1000",
		AllowedEnv:    []string{"COWRIE_SSH_ENABLED", "COWRIE_TELNET_ENABLED", "TZ"},
	},
	"heralding": {
		Kind:          "heralding",
		Image:         "johnnykv/heralding:latest",
		DefaultPort:   21,
		Protocol:      "tcp",
		ContainerPort: "21/tcp",
		User:          "1000:1000",
		AllowedEnv:    []string{"HERALDING_FTP", "HERALDING_SMTP", "HERALDING_POP3", "HERALDING_IMAP", "TZ"},
	},
}
