package enrichment

import (
	"hash/fnv"
	"net"
	"strings"

	"github.com/oschwald/maxminddb-golang"
)

// GeoResult holds offline country and ASN metadata for an attacker IP.
type GeoResult struct {
	CountryCode string `json:"country_code"`
	ASN         int    `json:"asn"`
	Org         string `json:"org"`
}

// GeoPoint provides offline coordinates and regional attribution for the Blue-Team Threat Radar map.
type GeoPoint struct {
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
	CountryCode string  `json:"country_code"`
	RegionLabel string  `json:"region_label"`
	Approximate bool    `json:"approximate"`
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

type geoAnchor struct {
	Code  string
	Label string
	Lat   float64
	Lon   float64
}

var countryCentroids = map[string]geoAnchor{
	"US": {Code: "US", Label: "United States", Lat: 39.04, Lon: -94.57},
	"CA": {Code: "CA", Label: "Canada", Lat: 56.13, Lon: -106.35},
	"MX": {Code: "MX", Label: "Mexico", Lat: 23.63, Lon: -102.55},
	"BR": {Code: "BR", Label: "Brazil", Lat: -14.23, Lon: -51.92},
	"AR": {Code: "AR", Label: "Argentina", Lat: -34.60, Lon: -58.38},
	"CL": {Code: "CL", Label: "Chile", Lat: -33.45, Lon: -70.67},
	"CO": {Code: "CO", Label: "Colombia", Lat: 4.71, Lon: -74.07},
	"PE": {Code: "PE", Label: "Peru", Lat: -12.04, Lon: -77.04},
	"EC": {Code: "EC", Label: "Ecuador", Lat: -0.18, Lon: -78.47},
	"VE": {Code: "VE", Label: "Venezuela", Lat: 10.48, Lon: -66.90},
	"PA": {Code: "PA", Label: "Panama", Lat: 8.98, Lon: -79.52},
	"GB": {Code: "GB", Label: "United Kingdom", Lat: 53.50, Lon: -2.20},
	"IE": {Code: "IE", Label: "Ireland", Lat: 53.35, Lon: -6.26},
	"FR": {Code: "FR", Label: "France", Lat: 46.23, Lon: 2.21},
	"DE": {Code: "DE", Label: "Germany", Lat: 51.16, Lon: 10.45},
	"NL": {Code: "NL", Label: "Netherlands", Lat: 52.13, Lon: 5.29},
	"BE": {Code: "BE", Label: "Belgium", Lat: 50.85, Lon: 4.35},
	"CH": {Code: "CH", Label: "Switzerland", Lat: 46.82, Lon: 8.23},
	"AT": {Code: "AT", Label: "Austria", Lat: 47.52, Lon: 14.55},
	"ES": {Code: "ES", Label: "Spain", Lat: 40.46, Lon: -3.75},
	"PT": {Code: "PT", Label: "Portugal", Lat: 39.40, Lon: -8.22},
	"IT": {Code: "IT", Label: "Italy", Lat: 42.83, Lon: 12.83},
	"PL": {Code: "PL", Label: "Poland", Lat: 51.92, Lon: 19.15},
	"CZ": {Code: "CZ", Label: "Czechia", Lat: 49.82, Lon: 15.47},
	"SK": {Code: "SK", Label: "Slovakia", Lat: 48.67, Lon: 19.70},
	"HU": {Code: "HU", Label: "Hungary", Lat: 47.16, Lon: 19.50},
	"RO": {Code: "RO", Label: "Romania", Lat: 45.94, Lon: 24.97},
	"BG": {Code: "BG", Label: "Bulgaria", Lat: 42.73, Lon: 25.49},
	"GR": {Code: "GR", Label: "Greece", Lat: 39.07, Lon: 21.82},
	"RS": {Code: "RS", Label: "Serbia", Lat: 44.02, Lon: 21.01},
	"HR": {Code: "HR", Label: "Croatia", Lat: 45.10, Lon: 15.20},
	"SI": {Code: "SI", Label: "Slovenia", Lat: 46.15, Lon: 14.99},
	"SE": {Code: "SE", Label: "Sweden", Lat: 59.33, Lon: 18.07},
	"FI": {Code: "FI", Label: "Finland", Lat: 61.92, Lon: 25.75},
	"NO": {Code: "NO", Label: "Norway", Lat: 60.47, Lon: 8.47},
	"DK": {Code: "DK", Label: "Denmark", Lat: 56.26, Lon: 9.50},
	"LT": {Code: "LT", Label: "Lithuania", Lat: 55.17, Lon: 23.88},
	"LV": {Code: "LV", Label: "Latvia", Lat: 56.88, Lon: 24.60},
	"EE": {Code: "EE", Label: "Estonia", Lat: 58.60, Lon: 25.01},
	"UA": {Code: "UA", Label: "Ukraine", Lat: 49.00, Lon: 31.40},
	"BY": {Code: "BY", Label: "Belarus", Lat: 53.71, Lon: 27.95},
	"MD": {Code: "MD", Label: "Moldova", Lat: 47.41, Lon: 28.37},
	"RU": {Code: "RU", Label: "Russia", Lat: 55.76, Lon: 45.62},
	"GE": {Code: "GE", Label: "Georgia", Lat: 42.32, Lon: 43.36},
	"AM": {Code: "AM", Label: "Armenia", Lat: 40.07, Lon: 45.04},
	"AZ": {Code: "AZ", Label: "Azerbaijan", Lat: 40.14, Lon: 47.58},
	"KZ": {Code: "KZ", Label: "Kazakhstan", Lat: 48.02, Lon: 66.92},
	"UZ": {Code: "UZ", Label: "Uzbekistan", Lat: 41.38, Lon: 64.59},
	"TR": {Code: "TR", Label: "Turkey", Lat: 39.93, Lon: 32.86},
	"IR": {Code: "IR", Label: "Iran", Lat: 32.43, Lon: 53.69},
	"IL": {Code: "IL", Label: "Israel", Lat: 31.05, Lon: 34.85},
	"AE": {Code: "AE", Label: "UAE", Lat: 24.45, Lon: 54.38},
	"SA": {Code: "SA", Label: "Saudi Arabia", Lat: 24.71, Lon: 46.68},
	"EG": {Code: "EG", Label: "Egypt", Lat: 30.04, Lon: 31.24},
	"MA": {Code: "MA", Label: "Morocco", Lat: 31.79, Lon: -7.09},
	"DZ": {Code: "DZ", Label: "Algeria", Lat: 28.03, Lon: 1.66},
	"TN": {Code: "TN", Label: "Tunisia", Lat: 33.89, Lon: 9.54},
	"ZA": {Code: "ZA", Label: "South Africa", Lat: -26.20, Lon: 28.05},
	"NG": {Code: "NG", Label: "Nigeria", Lat: 9.08, Lon: 8.68},
	"KE": {Code: "KE", Label: "Kenya", Lat: -1.29, Lon: 36.82},
	"IN": {Code: "IN", Label: "India", Lat: 20.59, Lon: 78.96},
	"PK": {Code: "PK", Label: "Pakistan", Lat: 30.38, Lon: 69.35},
	"BD": {Code: "BD", Label: "Bangladesh", Lat: 23.68, Lon: 90.36},
	"LK": {Code: "LK", Label: "Sri Lanka", Lat: 7.87, Lon: 80.77},
	"CN": {Code: "CN", Label: "China", Lat: 34.86, Lon: 112.20},
	"HK": {Code: "HK", Label: "Hong Kong", Lat: 22.32, Lon: 114.17},
	"TW": {Code: "TW", Label: "Taiwan", Lat: 23.70, Lon: 120.96},
	"JP": {Code: "JP", Label: "Japan", Lat: 36.20, Lon: 138.25},
	"KR": {Code: "KR", Label: "South Korea", Lat: 36.50, Lon: 127.80},
	"VN": {Code: "VN", Label: "Vietnam", Lat: 16.05, Lon: 108.20},
	"TH": {Code: "TH", Label: "Thailand", Lat: 13.75, Lon: 100.50},
	"SG": {Code: "SG", Label: "Singapore", Lat: 1.35, Lon: 103.82},
	"MY": {Code: "MY", Label: "Malaysia", Lat: 4.21, Lon: 101.98},
	"ID": {Code: "ID", Label: "Indonesia", Lat: -2.55, Lon: 118.01},
	"PH": {Code: "PH", Label: "Philippines", Lat: 12.88, Lon: 121.77},
	"KH": {Code: "KH", Label: "Cambodia", Lat: 12.57, Lon: 104.99},
	"AU": {Code: "AU", Label: "Australia", Lat: -28.27, Lon: 141.78},
	"NZ": {Code: "NZ", Label: "New Zealand", Lat: -40.90, Lon: 174.89},
}

var (
	apnicHubs = []geoAnchor{
		{Code: "SG", Label: "APNIC · Singapore Hub", Lat: 1.35, Lon: 103.82},
		{Code: "JP", Label: "APNIC · Tokyo Hub", Lat: 35.68, Lon: 139.69},
		{Code: "CN", Label: "APNIC · Shanghai Hub", Lat: 31.23, Lon: 121.47},
		{Code: "HK", Label: "APNIC · Hong Kong Hub", Lat: 22.32, Lon: 114.17},
		{Code: "KR", Label: "APNIC · Seoul Hub", Lat: 37.57, Lon: 126.98},
		{Code: "IN", Label: "APNIC · Mumbai Hub", Lat: 19.08, Lon: 72.88},
		{Code: "VN", Label: "APNIC · HCMC Hub", Lat: 10.82, Lon: 106.63},
		{Code: "AU", Label: "APNIC · Sydney Hub", Lat: -33.87, Lon: 151.21},
	}
	ripeHubs = []geoAnchor{
		{Code: "DE", Label: "RIPE · Frankfurt Hub", Lat: 50.11, Lon: 8.68},
		{Code: "NL", Label: "RIPE · Amsterdam Hub", Lat: 52.37, Lon: 4.90},
		{Code: "GB", Label: "RIPE · London Hub", Lat: 51.51, Lon: -0.13},
		{Code: "FR", Label: "RIPE · Paris Hub", Lat: 48.86, Lon: 2.35},
		{Code: "PL", Label: "RIPE · Warsaw Hub", Lat: 52.23, Lon: 21.01},
		{Code: "SE", Label: "RIPE · Stockholm Hub", Lat: 59.33, Lon: 18.07},
		{Code: "RO", Label: "RIPE · Bucharest Hub", Lat: 44.43, Lon: 26.10},
		{Code: "RU", Label: "RIPE · Moscow Hub", Lat: 55.76, Lon: 37.62},
		{Code: "UA", Label: "RIPE · Kyiv Hub", Lat: 50.45, Lon: 30.52},
	}
	lacnicHubs = []geoAnchor{
		{Code: "BR", Label: "LACNIC · Sao Paulo Hub", Lat: -23.55, Lon: -46.63},
		{Code: "AR", Label: "LACNIC · Buenos Aires Hub", Lat: -34.60, Lon: -58.38},
		{Code: "CO", Label: "LACNIC · Bogota Hub", Lat: 4.71, Lon: -74.07},
		{Code: "MX", Label: "LACNIC · Mexico City Hub", Lat: 19.43, Lon: -99.13},
		{Code: "CL", Label: "LACNIC · Santiago Hub", Lat: -33.45, Lon: -70.67},
	}
	afrinicHubs = []geoAnchor{
		{Code: "ZA", Label: "AFRINIC · Johannesburg Hub", Lat: -26.20, Lon: 28.05},
		{Code: "EG", Label: "AFRINIC · Cairo Hub", Lat: 30.04, Lon: 31.24},
		{Code: "NG", Label: "AFRINIC · Lagos Hub", Lat: 6.52, Lon: 3.38},
		{Code: "KE", Label: "AFRINIC · Nairobi Hub", Lat: -1.29, Lon: 36.82},
	}
	arinHubs = []geoAnchor{
		{Code: "US", Label: "ARIN · Ashburn VA Hub", Lat: 39.04, Lon: -77.49},
		{Code: "US", Label: "ARIN · San Jose CA Hub", Lat: 37.34, Lon: -121.89},
		{Code: "US", Label: "ARIN · Dallas TX Hub", Lat: 32.78, Lon: -96.80},
		{Code: "US", Label: "ARIN · New York Hub", Lat: 40.71, Lon: -74.01},
		{Code: "US", Label: "ARIN · Chicago IL Hub", Lat: 41.88, Lon: -87.63},
		{Code: "CA", Label: "ARIN · Toronto Hub", Lat: 43.65, Lon: -79.38},
	}
)

func deterministicJitter(ipStr string) (float64, float64) {
	h := fnv.New32a()
	_, _ = h.Write([]byte(ipStr))
	v := h.Sum32()
	dLat := (float64(v&0xff)/255.0 - 0.5) * 2.6
	dLon := (float64((v>>8)&0xff)/255.0 - 0.5) * 2.8
	return dLat, dLon
}

func clampCoord(lat, lon float64) (float64, float64) {
	if lat < -58 {
		lat = -58
	} else if lat > 72 {
		lat = 72
	}
	if lon < -170 {
		lon = -170
	} else if lon > 175 {
		lon = 175
	}
	return lat, lon
}

func rirHubsForOctet(firstByte byte) []geoAnchor {
	switch firstByte {
	case 1, 14, 27, 36, 39, 42, 43, 49, 58, 59, 60, 61, 101, 103, 106,
		110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126,
		175, 180, 182, 183, 202, 203, 210, 211, 218, 219, 220, 221, 222, 223:
		return apnicHubs
	case 2, 5, 31, 37, 46, 51, 57, 62,
		77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95,
		109, 141, 145, 151, 176, 178, 185, 188, 193, 194, 195, 212, 213, 217:
		return ripeHubs
	case 177, 179, 181, 186, 187, 189, 190, 191, 200, 201:
		return lacnicHubs
	case 41, 102, 105, 154, 196, 197:
		return afrinicHubs
	default:
		return arinHubs
	}
}

// ResolveIPGeoPoint maps an attacker IP and optional country code into offline SVG map coordinates.
// When countryCode is blank (no MMDB installed), it projects IANA RIR /8 allocation hubs deterministically.
func ResolveIPGeoPoint(ipStr, countryCode string) GeoPoint {
	cc := strings.ToUpper(strings.TrimSpace(countryCode))
	dLat, dLon := deterministicJitter(ipStr)
	if cc != "" {
		if anchor, ok := countryCentroids[cc]; ok {
			lat, lon := clampCoord(anchor.Lat+dLat, anchor.Lon+dLon)
			return GeoPoint{
				Lat:         lat,
				Lon:         lon,
				CountryCode: anchor.Code,
				RegionLabel: anchor.Label,
				Approximate: false,
			}
		}
	}

	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return GeoPoint{
			Lat:         37.34,
			Lon:         -121.89,
			CountryCode: "INT",
			RegionLabel: "Internal / Test Source",
			Approximate: true,
		}
	}

	var hubs []geoAnchor
	var idx int
	if ip4 := ip.To4(); ip4 != nil {
		hubs = rirHubsForOctet(ip4[0])
		idx = int(ip4[1]^ip4[2]^ip4[3]) % len(hubs)
	} else {
		allHubs := apnicHubs
		if ip[0] == 0x2a {
			allHubs = ripeHubs
		} else if ip[0] == 0x26 {
			allHubs = arinHubs
		} else if ip[0] == 0x28 {
			allHubs = lacnicHubs
		} else if ip[0] == 0x2c {
			allHubs = afrinicHubs
		}
		hubs = allHubs
		idx = int(ip[15]) % len(hubs)
	}
	chosen := hubs[idx]
	lat, lon := clampCoord(chosen.Lat+dLat, chosen.Lon+dLon)
	return GeoPoint{
		Lat:         lat,
		Lon:         lon,
		CountryCode: chosen.Code,
		RegionLabel: chosen.Label,
		Approximate: true,
	}
}

// ResolveSensorGeoPoint places a sensor target node using region hints or its public IP.
func ResolveSensorGeoPoint(region, publicIP string) GeoPoint {
	reg := strings.ToLower(strings.TrimSpace(region))
	switch {
	case strings.Contains(reg, "sg") || strings.Contains(reg, "ap-southeast"):
		return GeoPoint{Lat: 1.35, Lon: 103.82, CountryCode: "SG", RegionLabel: "Sensor · Singapore", Approximate: false}
	case strings.Contains(reg, "vn") || strings.Contains(reg, "hcm") || strings.Contains(reg, "han"):
		return GeoPoint{Lat: 10.82, Lon: 106.63, CountryCode: "VN", RegionLabel: "Sensor · Vietnam", Approximate: false}
	case strings.Contains(reg, "jp") || strings.Contains(reg, "tokyo"):
		return GeoPoint{Lat: 35.68, Lon: 139.69, CountryCode: "JP", RegionLabel: "Sensor · Tokyo", Approximate: false}
	case strings.Contains(reg, "eu") || strings.Contains(reg, "de") || strings.Contains(reg, "fra"):
		return GeoPoint{Lat: 50.11, Lon: 8.68, CountryCode: "DE", RegionLabel: "Sensor · Frankfurt", Approximate: false}
	case strings.Contains(reg, "nl") || strings.Contains(reg, "ams"):
		return GeoPoint{Lat: 52.37, Lon: 4.90, CountryCode: "NL", RegionLabel: "Sensor · Amsterdam", Approximate: false}
	case strings.Contains(reg, "uk") || strings.Contains(reg, "gb") || strings.Contains(reg, "lon"):
		return GeoPoint{Lat: 51.51, Lon: -0.13, CountryCode: "GB", RegionLabel: "Sensor · London", Approximate: false}
	case strings.Contains(reg, "us-west") || strings.Contains(reg, "sfo") || strings.Contains(reg, "sjc"):
		return GeoPoint{Lat: 37.34, Lon: -121.89, CountryCode: "US", RegionLabel: "Sensor · US West", Approximate: false}
	case strings.Contains(reg, "us"):
		return GeoPoint{Lat: 39.04, Lon: -77.49, CountryCode: "US", RegionLabel: "Sensor · US East", Approximate: false}
	}
	if strings.TrimSpace(publicIP) != "" {
		pt := ResolveIPGeoPoint(publicIP, "")
		pt.RegionLabel = "Sensor Target Node"
		return pt
	}
	return GeoPoint{Lat: 39.04, Lon: -77.49, CountryCode: "US", RegionLabel: "Primary Sensor Hub", Approximate: true}
}
