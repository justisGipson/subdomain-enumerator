package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	workerCount    = 1000
	bufferSize     = 10000
	httpTimeout    = 5
	resolverCount  = 10
	batchSize      = 100
	ctQueryTimeout = 10 * time.Second
	maxRetries     = 3
	retryDelay     = 2 * time.Second
	ctRateLimit    = 500 * time.Millisecond // Time between crt.sh requests
)

var (
	ctRateLimiter = time.NewTicker(ctRateLimit)
	lastCTQuery   = time.Now()
	ctMutex       sync.Mutex
)

var resolvers = []string{
	"8.8.8.8:53",         // Google
	"8.8.4.4:53",         // Google
	"1.1.1.1:53",         // Cloudflare
	"1.0.0.1:53",         // Cloudflare
	"9.9.9.9:53",         // Quad9
	"149.112.112.112:53", // Quad9
	"208.67.222.222:53",  // OpenDNS
	"208.67.220.220:53",  // OpenDNS
	"64.6.64.6:53",       // Verisign
	"64.6.65.6:53",       // Verisign
}

type CTSource struct {
	Name string
	URL  string
}

var ctSources = []CTSource{
	{"crt.sh", "https://crt.sh/?q=%%.%s&output=json"},
	{"certspotter", "https://api.certspotter.com/v1/issuances?domain=%s"},
	{"google", "https://www.gstatic.com/ct/log_list/v3/log_list.json?domain=%s"},
	{"facebook", "https://developers.facebook.com/tools/ct/?domain=%s"},
	{"entrust", "https://www.entrust.com/ct-logs?domain=%s"},
}

var globalCache = &DNSCache{
	cache: make(map[string]map[string][]string),
}

type DNSCache struct {
	cache  map[string]map[string][]string
	hits   uint64
	misses uint64
	mu     sync.RWMutex
}

func (c *DNSCache) Get(subdomain string) (map[string][]string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	records, exists := c.cache[subdomain]
	if exists {
		atomic.AddUint64(&c.hits, 1)
	} else {
		atomic.AddUint64(&c.misses, 1)
	}
	return records, exists
}

func (c *DNSCache) Set(subdomain string, records map[string][]string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache[subdomain] = records
}

func (c *DNSCache) GetStats() (hits, misses uint64) {
	return atomic.LoadUint64(&c.hits), atomic.LoadUint64(&c.misses)
}

type Result struct {
	Domain    string
	Subdomain string
	Records   map[string][]string
	Source    string
}

type DomainResults struct {
	Domain  string
	Results []Result
	mu      sync.Mutex
}

type ScanStats struct {
	StartTime    time.Time
	Duration     time.Duration
	TotalQueries uint64
	CacheHits    uint64
	CacheMisses  uint64
	CTFindings   map[string]int
	mu           sync.Mutex
}

func NewScanStats() *ScanStats {
	return &ScanStats{
		StartTime:  time.Now(),
		CTFindings: make(map[string]int),
	}
}

func (s *ScanStats) AddCTFindings(source string, count int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.CTFindings[source] = count
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: go run subdomain_enum.go <domain|domainlist> <wordlist>")
		fmt.Println("Examples:")
		fmt.Println("  Single domain:  go run subdomain_enum.go example.com wordlist.txt")
		fmt.Println("  Domain list:    go run subdomain_enum.go domains.txt wordlist.txt")
		os.Exit(1)
	}

	stats := NewScanStats()

	domainInput := os.Args[1]
	wordlistFile := os.Args[2]

	domains, err := readDomains(domainInput)
	if err != nil {
		fmt.Printf("Error reading domains: %v\n", err)
		os.Exit(1)
	}

	wordlist, err := readWordlistEfficient(wordlistFile)
	if err != nil {
		fmt.Printf("Error reading wordlist: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\n🔍 Starting enhanced subdomain enumeration for %d domain(s)\n", len(domains))
	fmt.Printf("📝 Using wordlist with %d entries\n\n", len(wordlist))

	results := make(map[string]*DomainResults)
	var wg sync.WaitGroup
	resultsMutex := sync.Mutex{}

	// Process domains concurrently
	for _, domain := range domains {
		wg.Add(1)
		results[domain] = &DomainResults{
			Domain:  domain,
			Results: make([]Result, 0),
		}

		go func(d string) {
			defer wg.Done()
			dr := processDomain(d, wordlist, stats)
			resultsMutex.Lock()
			results[d] = dr
			resultsMutex.Unlock()
		}(domain)
	}

	wg.Wait()
	stats.Duration = time.Since(stats.StartTime)
	printFinalResults(results, stats)
}

func processDomain(domain string, wordlist []string, stats *ScanStats) *DomainResults {
	results := &DomainResults{
		Domain:  domain,
		Results: make([]Result, 0),
	}

	// First try CT logs
	fmt.Printf("   🔍 Scanning CT logs for %s...\n", domain)
	ctResults := queryCTSource(domain, CTSource{Name: "crt.sh"})
	if len(ctResults) > 0 {
		results.mu.Lock()
		results.Results = append(results.Results, ctResults...)
		results.mu.Unlock()
		stats.AddCTFindings("crt.sh", len(ctResults))
	}

	// Always do DNS brute force as backup
	fmt.Printf("   🔄 Starting brute force scan for %s...\n", domain)

	subdomainChan := make(chan string, bufferSize)
	resultChan := make(chan Result, bufferSize)
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			resolver := createResolver(resolvers[workerID%resolverCount])
			for subdomain := range subdomainChan {
				if records := checkSubdomainWithResolver(subdomain, resolver); records != nil {
					resultChan <- Result{
						Domain:    domain,
						Subdomain: subdomain,
						Records:   records,
						Source:    "wordlist",
					}
				}
			}
		}(i)
	}

	// Start result collector
	done := make(chan bool)
	go func() {
		for result := range resultChan {
			results.mu.Lock()
			results.Results = append(results.Results, result)
			results.mu.Unlock()
		}
		done <- true
	}()

	// Feed subdomains
	for _, word := range wordlist {
		subdomainChan <- word + "." + domain
	}

	close(subdomainChan)
	wg.Wait()
	close(resultChan)
	<-done

	fmt.Printf("   ✅ Scan completed for %s\n", domain)
	return results
}

func queryCTSource(domain string, source CTSource) []Result {
	// Rate limiting
	ctMutex.Lock()
	timeSinceLastQuery := time.Since(lastCTQuery)
	if timeSinceLastQuery < ctRateLimit {
		time.Sleep(ctRateLimit - timeSinceLastQuery)
	}
	lastCTQuery = time.Now()
	ctMutex.Unlock()

	var resp *http.Response
	var body []byte

	// Retry logic
	for attempt := 1; attempt <= maxRetries; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), ctQueryTimeout)
		defer cancel()

		url := fmt.Sprintf("https://crt.sh/?q=%%.%s&output=json", domain)
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			fmt.Printf("   ⚠️  Error creating request for %s: %v\n", domain, err)
			return nil
		}

		// Add headers to look more like a browser
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")

		client := &http.Client{
			Timeout: ctQueryTimeout,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 100,
				IdleConnTimeout:     30 * time.Second,
				DisableKeepAlives:   false,
			},
		}

		resp, err = client.Do(req)
		if err != nil {
			if attempt == maxRetries {
				fmt.Printf("   ⚠️  Final attempt failed for %s: %v\n", domain, err)
				return nil
			}
			fmt.Printf("   ⚠️  Attempt %d failed for %s: %v\n", attempt, domain, err)
			time.Sleep(retryDelay * time.Duration(attempt))
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == 429 {
			if attempt == maxRetries {
				fmt.Printf("   ⚠️  Rate limit reached for %s after %d attempts\n", domain, attempt)
				return nil
			}
			waitTime := retryDelay * time.Duration(attempt)
			fmt.Printf("   ⚠️  Rate limited for %s, waiting %v before retry\n", domain, waitTime)
			time.Sleep(waitTime)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			if attempt == maxRetries {
				fmt.Printf("   ⚠️  Bad status code from crt.sh for %s: %d\n", domain, resp.StatusCode)
				return nil
			}
			time.Sleep(retryDelay * time.Duration(attempt))
			continue
		}

		body, err = io.ReadAll(resp.Body)
		if err != nil {
			if attempt == maxRetries {
				fmt.Printf("   ⚠️  Error reading response for %s: %v\n", domain, err)
				return nil
			}
			continue
		}

		// If we got here, we have a successful response
		break
	}

	// Process the response
	var entries []struct {
		NameValue string `json:"name_value"`
	}

	if err := json.Unmarshal(body, &entries); err != nil {
		fmt.Printf("   ⚠️  Error parsing JSON for %s: %v\n", domain, err)
		return nil
	}

	fmt.Printf("   📝 Found %d certificate entries for %s\n", len(entries), domain)

	seen := make(map[string]bool)
	results := make([]Result, 0)

	for _, entry := range entries {
		names := strings.Split(entry.NameValue, "\n")
		for _, name := range names {
			name = strings.ToLower(strings.TrimSpace(name))
			if strings.HasSuffix(name, "."+domain) && !seen[name] {
				seen[name] = true
				if records := checkSubdomainWithResolver(name, createResolver(resolvers[0])); records != nil {
					results = append(results, Result{
						Domain:    domain,
						Subdomain: name,
						Records:   records,
						Source:    "crt.sh",
					})
				}
			}
		}
	}

	fmt.Printf("   ✨ Verified %d active subdomains for %s\n", len(results), domain)
	return results
}

func checkSubdomainWithResolver(subdomain string, resolver *net.Resolver) map[string][]string {
	if records, exists := globalCache.Get(subdomain); exists {
		return records
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	records := make(map[string][]string)

	// Try A records
	if ips, err := resolver.LookupIPAddr(ctx, subdomain); err == nil {
		records["A"] = make([]string, 0, len(ips))
		for _, ip := range ips {
			if ip.IP.To4() != nil {
				records["A"] = append(records["A"], ip.IP.String())
			}
		}
	}

	// Try CNAME records
	if cname, err := resolver.LookupCNAME(ctx, subdomain); err == nil && cname != "" {
		records["CNAME"] = []string{cname}
	}

	if len(records) > 0 {
		globalCache.Set(subdomain, records)
		return records
	}

	return nil
}

func createBatches(wordlist []string, domain string, size int) [][]string {
	var batches [][]string
	batch := make([]string, 0, size)

	for _, word := range wordlist {
		subdomain := word + "." + domain
		batch = append(batch, subdomain)

		if len(batch) == size {
			batches = append(batches, batch)
			batch = make([]string, 0, size)
		}
	}

	if len(batch) > 0 {
		batches = append(batches, batch)
	}

	return batches
}

func processBatch(subdomains []string, resolver *net.Resolver, cache *DNSCache, domain string) []Result {
	results := make([]Result, 0)
	var wg sync.WaitGroup
	resultChan := make(chan Result, len(subdomains))

	for _, subdomain := range subdomains {
		wg.Add(1)
		go func(s string) {
			defer wg.Done()
			if records, exists := cache.Get(s); exists {
				resultChan <- Result{
					Domain:    domain,
					Subdomain: s,
					Records:   records,
					Source:    "wordlist",
				}
				return
			}

			if records := checkSubdomainWithResolver(s, resolver); records != nil {
				cache.Set(s, records)
				resultChan <- Result{
					Domain:    domain,
					Subdomain: s,
					Records:   records,
					Source:    "wordlist",
				}
			}
		}(subdomain)
	}

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	for result := range resultChan {
		results = append(results, result)
	}

	return results
}

func createResolver(resolverAddress string) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: time.Second * 2,
			}
			return d.DialContext(ctx, "udp", resolverAddress)
		},
	}
}

func readDomains(input string) ([]string, error) {
	if strings.HasSuffix(input, ".txt") {
		content, err := os.ReadFile(input)
		if err != nil {
			return nil, err
		}
		lines := strings.Split(strings.TrimSpace(string(content)), "\n")
		domains := make([]string, 0, len(lines))
		for _, line := range lines {
			if domain := strings.TrimSpace(line); domain != "" {
				domains = append(domains, domain)
			}
		}
		return domains, nil
	}
	return []string{input}, nil
}

func readWordlistEfficient(file string) ([]string, error) {
	content, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	wordlist := make([]string, 0, len(lines))
	for _, line := range lines {
		if word := strings.TrimSpace(line); word != "" {
			wordlist = append(wordlist, word)
		}
	}
	return wordlist, nil
}

func extractSubdomains(body []byte, domain string) []string {
	var subdomains = make(map[string]bool)

	// Try parsing as JSON first
	var data interface{}
	if err := json.Unmarshal(body, &data); err == nil {
		extractSubdomainsFromJSON(data, domain, subdomains)
	}

	// Also check for plain text matches
	bodyStr := string(body)
	for _, line := range strings.Split(bodyStr, "\n") {
		if strings.Contains(line, domain) {
			fields := strings.Fields(line)
			for _, field := range fields {
				if strings.HasSuffix(field, "."+domain) {
					subdomains[strings.TrimSpace(field)] = true
				}
			}
		}
	}

	result := make([]string, 0, len(subdomains))
	for subdomain := range subdomains {
		result = append(result, subdomain)
	}
	return result
}

func extractSubdomainsFromJSON(data interface{}, domain string, subdomains map[string]bool) {
	switch v := data.(type) {
	case map[string]interface{}:
		for _, value := range v {
			extractSubdomainsFromJSON(value, domain, subdomains)
		}
	case []interface{}:
		for _, value := range v {
			extractSubdomainsFromJSON(value, domain, subdomains)
		}
	case string:
		if strings.HasSuffix(v, "."+domain) {
			subdomains[strings.TrimSpace(v)] = true
		}
	}
}

func printFinalResults(results map[string]*DomainResults, stats *ScanStats) {
	fmt.Println("\n📊 ENUMERATION RESULTS")
	fmt.Println("═══════════════════════")

	totalSubdomains := 0
	for domain, domainResults := range results {
		fmt.Printf("\n🌐 Domain: %s\n", domain)
		fmt.Printf("   %s\n", strings.Repeat("─", len(domain)+8))

		if len(domainResults.Results) == 0 {
			fmt.Println("   No subdomains found")
			continue
		}

		// Group results by source
		sourceResults := make(map[string][]Result)
		for _, result := range domainResults.Results {
			sourceResults[result.Source] = append(sourceResults[result.Source], result)
		}

		// Print results by source
		for source, srcResults := range sourceResults {
			fmt.Printf("\n   📌 Source: %s (%d found)\n", source, len(srcResults))

			// Sort results within each source
			sort.Slice(srcResults, func(i, j int) bool {
				return srcResults[i].Subdomain < srcResults[j].Subdomain
			})

			for _, result := range srcResults {
				fmt.Printf("\n   └─📍 %s\n", result.Subdomain)
				for recordType, records := range result.Records {
					fmt.Printf("      ├─ %s:\n", recordType)
					for _, record := range records {
						fmt.Printf("      │  └─ %s\n", record)
					}
				}
			}
		}

		totalSubdomains += len(domainResults.Results)
		fmt.Printf("\n   Total subdomains found: %d\n", len(domainResults.Results))
		fmt.Println(strings.Repeat("═", 50))
	}

	// Print detailed statistics
	fmt.Println("\n📈 SCAN STATISTICS")
	fmt.Println("══════════════")
	fmt.Printf("🕒 Start time: %s\n", stats.StartTime.Format("2006-01-02 15:04:05 MST"))
	fmt.Printf("⏱️  Duration: %s\n", stats.Duration.Round(time.Millisecond))
	fmt.Printf("🎯 Domains scanned: %d\n", len(results))
	fmt.Printf("🔍 Total subdomains discovered: %d\n", totalSubdomains)

	// Print CT source statistics
	fmt.Println("\n📋 CT Log Sources:")
	for source, count := range stats.CTFindings {
		fmt.Printf("   ├─ %s: %d findings\n", source, count)
	}

	// Print cache statistics
	hits, misses := globalCache.GetStats()
	totalQueries := hits + misses
	var hitRate float64
	if totalQueries > 0 {
		hitRate = float64(hits) / float64(totalQueries) * 100
	}
	fmt.Printf("\n💾 Cache Performance:\n")
	fmt.Printf("   ├─ Hits: %d\n", hits)
	fmt.Printf("   ├─ Misses: %d\n", misses)
	fmt.Printf("   └─ Hit Rate: %.1f%%\n\n", hitRate)
}
