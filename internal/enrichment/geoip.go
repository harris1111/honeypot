package enrichment

import (
	"net"

	"github.com/oschwald/maxminddb-golang"
)

// GeoResult holds offline country and ASN metadata for an attacker IP.
type GeoResult struct {
	CountryCode string `json:"country_code"`
	ASN         int    `json:"asn"`
	Org         string `json:"org"`
}

// GeoResolver performs offline MaxMind/IPinfo MMDB lookups when database files exist,
// falling back safely when running without local MMDB bundles.
type GeoResolver struct {
	cityDB *maxminddb.Reader
	asnDB  *maxminddb.Reader
}

// OpenGeoResolver opens optional MMDB files (nil paths or missing files are gracefully tolerated).
func OpenGeoResolver(cityMMDBPath, asnMMDBPath string) *GeoResolver {
	r := &GeoResolver{}
	if cityMMDBPath != "" {
		if db, err := maxminddb.Open(cityMMDBPath); err == nil {
			r.cityDB = db
		}
	}
	if asnMMDBPath != "" {
		if db, err := maxminddb.Open(asnMMDBPath); err == nil {
			r.asnDB = db
		}
	}
	return r
}

func (g *GeoResolver) Close() {
	if g == nil {
		return
	}
	if g.cityDB != nil {
		_ = g.cityDB.Close()
	}
	if g.asnDB != nil {
		_ = g.asnDB.Close()
	}
}

// Lookup resolves CountryCode and ASN strictly offline with zero external network IO.
func (g *GeoResolver) Lookup(ipStr string) GeoResult {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return GeoResult{}
	}
	var out GeoResult
	if g != nil && g.cityDB != nil {
		var rec struct {
			Country struct {
				ISOCode string `maxminddb:"iso_code"`
			} `maxminddb:"country"`
		}
		if err := g.cityDB.Lookup(ip, &rec); err == nil {
			out.CountryCode = rec.Country.ISOCode
		}
	}
	if g != nil && g.asnDB != nil {
		var rec struct {
			AutonomousSystemNumber       int    `maxminddb:"autonomous_system_number"`
			AutonomousSystemOrganization string `maxminddb:"autonomous_system_organization"`
		}
		if err := g.asnDB.Lookup(ip, &rec); err == nil {
			out.ASN = rec.AutonomousSystemNumber
			out.Org = rec.AutonomousSystemOrganization
		}
	}
	return out
}
