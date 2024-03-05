package dns

import (
	"net/netip"
	"strings"

	"github.com/metacubex/mihomo/component/geodata"
	"github.com/metacubex/mihomo/component/geodata/router"
	"github.com/metacubex/mihomo/component/mmdb"
	"github.com/metacubex/mihomo/component/trie"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

type fallbackIPFilter interface {
	Match(netip.Addr) bool
}

type geoipFilter struct {
	code string
}

var geoIPMatcherMap map[string]*router.GeoIPMatcher

func (gf *geoipFilter) Match(ip netip.Addr) bool {
	if C.GeodataMode {
		geoIPMatcher, ok := geoIPMatcherMap[gf.code]
		if !ok {
			geoIPMatcher, _, err := geodata.LoadGeoIPMatcher(gf.code)
			if err != nil {
				log.Errorln("[GeoIPFilter] LoadGeoIPMatcher error: %s", err.Error())
				return false
			}

			geoIPMatcherMap[gf.code] = geoIPMatcher
		}

		return geoIPMatcher.Match(ip)
	}

	codes := mmdb.IPInstance().LookupCode(ip.AsSlice())
	for _, code := range codes {
		if !strings.EqualFold(code, gf.code) && !ip.IsPrivate() {
			return false
		}
	}
	return true
}

type ipnetFilter struct {
	ipnet netip.Prefix
}

func (inf *ipnetFilter) Match(ip netip.Addr) bool {
	return inf.ipnet.Contains(ip)
}

type fallbackDomainFilter interface {
	Match(domain string) bool
}

type domainFilter struct {
	tree *trie.DomainTrie[struct{}]
}

func NewDomainFilter(domains []string) *domainFilter {
	df := domainFilter{tree: trie.New[struct{}]()}
	for _, domain := range domains {
		_ = df.tree.Insert(domain, struct{}{})
	}
	df.tree.Optimize()
	return &df
}

func (df *domainFilter) Match(domain string) bool {
	return df.tree.Search(domain) != nil
}

type geoSiteFilter struct {
	matchers []router.DomainMatcher
}

func NewGeoSite(group string) (fallbackDomainFilter, error) {
	if err := geodata.InitGeoSite(); err != nil {
		log.Errorln("can't initial GeoSite: %s", err)
		return nil, err
	}
	matcher, _, err := geodata.LoadGeoSiteMatcher(group)
	if err != nil {
		return nil, err
	}
	filter := &geoSiteFilter{
		matchers: []router.DomainMatcher{matcher},
	}
	return filter, nil
}

func (gsf *geoSiteFilter) Match(domain string) bool {
	for _, matcher := range gsf.matchers {
		if matcher.ApplyDomain(domain) {
			return true
		}
	}
	return false
}
