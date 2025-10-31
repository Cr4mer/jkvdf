package main

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	dem "github.com/markus-wa/demoinfocs-golang/v4/pkg/demoinfocs"
	"github.com/markus-wa/demoinfocs-golang/v4/pkg/demoinfocs/events"
	"github.com/klauspost/compress/zstd"
)

const (
	dataDirName       = "data"
	highlightsFile    = "highlights.json"
	leaderboardsFile  = "leaderboards.json"
	matchesFile       = "matches.json"
	stateFile         = "state.json"
	preSeconds        = 3.0
	postSeconds       = 4.0
	killGapSeconds    = 7.0
	maxHighlightsKeep = 500
	allTimeLimit      = 20

	demoDownloadMaxAttempts = 5
	demoDownloadBaseDelay   = time.Second
)

var faceitAPIKey string

var resolver = &net.Resolver{
	PreferGo: true,
	Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", "8.8.8.8:53")
	},
}

func init() {
	net.DefaultResolver = resolver
}

var httpClient = &http.Client{
	Timeout: 2 * time.Minute,
	Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			ips, err := resolver.LookupIPAddr(ctx, host)
			log.Printf("Resolving %s -> %v", host, ips)
			if err != nil {
				return nil, err
			}
			for _, ip := range ips {
				conn, dialErr := net.DialTimeout(network, net.JoinHostPort(ip.IP.String(), port), 30*time.Second)
				if dialErr == nil {
					return conn, nil
				}
				err = dialErr
			}
			return nil, err
		},
	},
}

type playerConfig struct {
	FaceitNickname string `json:"faceitNickname"`
	SteamID        string `json:"steamId"`
	SteamID64      uint64 `json:"-"`
}

type matchEntry struct {
	PlayerID       string `json:"playerId"`
	FaceitNickname string `json:"faceitNickname"`
	MatchID        string `json:"matchId"`
	GameMode       string `json:"gameMode"`
	Region         string `json:"region"`
	StartedAt      int64  `json:"startedAt"`
	FinishedAt     int64  `json:"finishedAt"`
	TeamsSize      int    `json:"teamsSize"`
	URLRoom        string `json:"urlRoom"`
	Map            string `json:"map"`
}

type matchesPayload struct {
	Matches []matchEntry `json:"matches"`
}

type highlight struct {
	ID               string  `json:"id"`
	MatchID          string  `json:"matchId"`
	PlayerID         string  `json:"playerId"`
	FaceitNickname   string  `json:"faceitNickname"`
	Map              string  `json:"map,omitempty"`
	Round            int     `json:"round"`
	TickStart        int     `json:"tickStart"`
	TickEnd          int     `json:"tickEnd"`
	TimeStartSeconds float64 `json:"timeStartSeconds"`
	TimeEndSeconds   float64 `json:"timeEndSeconds"`
	Kills            int     `json:"kills"`
	Headshots        int     `json:"headshots"`
	Score            float64 `json:"score"`
	Category         string  `json:"category"`
	Description      string  `json:"description"`
	MatchFinishedAt  string  `json:"matchFinishedAt"`
	RecordedAt       string  `json:"recordedAt"`
	DemoURL          string  `json:"demoUrl,omitempty"`
	ClipURL          string  `json:"clipUrl,omitempty"`
	SteamID          string  `json:"steamId,omitempty"`
	SteamID64        string  `json:"steamId64,omitempty"`
}

type highlightsPayload struct {
	Highlights []highlight `json:"highlights"`
}

type leaderboards struct {
	GeneratedAt string      `json:"generatedAt"`
	LastGame    []highlight `json:"lastGame"`
	Last10      []highlight `json:"last10"`
	AllTimeTop  []highlight `json:"allTimeTop"`
}

type groupedMatch struct {
	MatchID string
	Base    matchEntry
	Players map[string]matchEntry
}

type playerInfo struct {
	FaceitNickname string
	SteamID        string
	SteamID64      uint64
	PlayerID       string
}

type multiState struct {
	count      int
	headshots  int
	startTick  int
	lastTick   int
	startTime  float64
	lastTime   float64
	round      int
}

type highlightCandidate struct {
	SteamID64        uint64
	Round            int
	Kills            int
	Headshots        int
	TickStart        int
	TickEnd          int
	TimeStartSeconds float64
	TimeEndSeconds   float64
	Score            float64
	Category         string
	Description      string
}

type faceitMatchDetails struct {
	DemoURL []string `json:"demo_url"`
	Map     string   `json:"map"`
	Voting  struct {
		Map struct {
			Pick []string `json:"pick"`
		} `json:"map"`
	} `json:"voting"`
}

type faceitDownloadResponse struct {
	Payload struct {
		DownloadURL string `json:"download_url"`
	} `json:"payload"`
}

func main() {
	faceitKey := os.Getenv("FACEIT_API_KEY")
	if faceitKey == "" {
		log.Fatal("FACEIT_API_KEY is not set")
	}
	faceitAPIKey = faceitKey

	repoRoot, err := os.Getwd()
	if err != nil {
		log.Fatalf("getwd: %v", err)
	}

	dataDir := filepath.Join(repoRoot, dataDirName)
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		log.Fatalf("ensure data dir: %v", err)
	}

	players, err := loadPlayers(filepath.Join(repoRoot, "players.json"))
	if err != nil {
		log.Fatalf("load players: %v", err)
	}

	matchesPayload, err := loadMatches(filepath.Join(dataDir, matchesFile))
	if err != nil {
		log.Fatalf("load matches: %v", err)
	}

	if len(matchesPayload.Matches) == 0 {
		log.Println("No matches to process - exiting")
		return
	}

	existingHighlights := loadHighlights(filepath.Join(dataDir, highlightsFile))
	processedMatchIDs := make(map[string]struct{})
	for _, h := range existingHighlights.Highlights {
		if h.MatchID != "" {
			processedMatchIDs[h.MatchID] = struct{}{}
		}
	}

	matchGroups := groupMatches(matchesPayload.Matches)
	var newHighlights []highlight

	for matchID, group := range matchGroups {
		if _, alreadyDone := processedMatchIDs[matchID]; alreadyDone {
			continue
		}

		log.Printf("Processing match %s", matchID)
		details, err := fetchMatchDetails(faceitAPIKey, matchID)
		if err != nil {
			log.Printf("  failed to fetch match details: %v", err)
			continue
		}

		demoURL, mapName := extractDemoAndMap(details, group.Base)
		if demoURL == "" {
			log.Printf("  no demo URL available for %s", matchID)
			continue
		}
		if mapName != "" && group.Base.Map == "" {
			group.Base.Map = mapName
		}

		demoPath, err := downloadDemo(matchID, demoURL)
		if err != nil {
			log.Printf("  failed to download demo: %v", err)
			continue
		}
		defer os.Remove(demoPath)

		trackedPlayers := buildTrackedPlayers(group, players)
		if len(trackedPlayers) == 0 {
			log.Printf("  no whitelisted players found for this match")
			continue
		}

		matchHighlights, err := parseDemoForHighlights(demoPath, group, trackedPlayers, demoURL)
		if err != nil {
			log.Printf("  failed to parse demo: %v", err)
			continue
		}

		if len(matchHighlights) == 0 {
			log.Printf("  no highlight-worthy events found")
		} else {
			newHighlights = append(newHighlights, matchHighlights...)
			log.Printf("  collected %d highlight(s)", len(matchHighlights))
		}
	}

	if len(newHighlights) == 0 {
		log.Println("No new highlights produced (existing highlights remain unchanged)")
		leaderboards := buildLeaderboards(existingHighlights.Highlights)
		if err := saveLeaderboards(filepath.Join(dataDir, leaderboardsFile), leaderboards); err != nil {
			log.Fatalf("write leaderboards: %v", err)
		}
		return
	}

	mergedHighlights := mergeHighlights(existingHighlights.Highlights, newHighlights)
	if err := saveHighlights(filepath.Join(dataDir, highlightsFile), mergedHighlights); err != nil {
		log.Fatalf("write highlights: %v", err)
	}

	leaderboards := buildLeaderboards(mergedHighlights)
	if err := saveLeaderboards(filepath.Join(dataDir, leaderboardsFile), leaderboards); err != nil {
		log.Fatalf("write leaderboards: %v", err)
	}

	log.Printf("Done. Total highlights stored: %d", len(mergedHighlights))
}

func loadPlayers(path string) (map[string]playerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read players file: %w", err)
	}
	var raw []playerConfig
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("decode players: %w", err)
	}

	result := make(map[string]playerConfig, len(raw))
	for _, p := range raw {
		if p.FaceitNickname == "" || p.SteamID == "" {
			continue
		}
		steam64, err := steamTo64(p.SteamID)
		if err != nil {
			log.Printf("  warning: cannot convert steam ID %s for %s: %v", p.SteamID, p.FaceitNickname, err)
			continue
		}
		p.SteamID64 = steam64
		result[strings.ToLower(p.FaceitNickname)] = p
	}
	return result, nil
}

func loadMatches(path string) (matchesPayload, error) {
	var payload matchesPayload
	data, err := os.ReadFile(path)
	if err != nil {
		return payload, fmt.Errorf("read matches: %w", err)
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return payload, fmt.Errorf("decode matches: %w", err)
	}
	return payload, nil
}

func loadHighlights(path string) highlightsPayload {
	data, err := os.ReadFile(path)
	if err != nil {
		return highlightsPayload{Highlights: []highlight{}}
	}
	var payload highlightsPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		log.Printf("warning: corrupt highlights file, starting fresh: %v", err)
		return highlightsPayload{Highlights: []highlight{}}
	}
	return payload
}

func saveHighlights(path string, highlights []highlight) error {
	payload := highlightsPayload{Highlights: highlights}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return fmt.Errorf("encode highlights: %w", err)
	}
	return os.WriteFile(path, data, 0o644)
}

func saveLeaderboards(path string, lb leaderboards) error {
	data, err := json.MarshalIndent(lb, "", "  ")
	if err != nil {
		return fmt.Errorf("encode leaderboards: %w", err)
	}
	return os.WriteFile(path, data, 0o644)
}

func groupMatches(matches []matchEntry) map[string]*groupedMatch {
	groups := make(map[string]*groupedMatch)
	for _, m := range matches {
		if m.MatchID == "" {
			continue
		}
		key := m.MatchID
		g, exists := groups[key]
		if !exists {
			g = &groupedMatch{
				MatchID: key,
				Base:    m,
				Players: make(map[string]matchEntry),
			}
			groups[key] = g
		}
		nick := strings.ToLower(m.FaceitNickname)
		if nick != "" {
			g.Players[nick] = m
		}
		if g.Base.Map == "" && m.Map != "" {
			g.Base.Map = m.Map
		}
		if g.Base.FinishedAt == 0 && m.FinishedAt != 0 {
			g.Base.FinishedAt = m.FinishedAt
		}
	}
	return groups
}

func buildTrackedPlayers(group *groupedMatch, players map[string]playerConfig) map[uint64]playerInfo {
	result := make(map[uint64]playerInfo)
	for nick, entry := range group.Players {
		cfg, ok := players[nick]
		if !ok || cfg.SteamID64 == 0 || entry.PlayerID == "" {
			continue
		}
		result[cfg.SteamID64] = playerInfo{
			FaceitNickname: cfg.FaceitNickname,
			SteamID:        cfg.SteamID,
			SteamID64:      cfg.SteamID64,
			PlayerID:       entry.PlayerID,
		}
	}
	return result
}

func fetchMatchDetails(faceitKey, matchID string) (*faceitMatchDetails, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("https://open.faceit.com/data/v4/matches/%s", matchID), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+faceitKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("faceit response %d: %s", resp.StatusCode, string(body))
	}

	var details faceitMatchDetails
	if err := json.NewDecoder(resp.Body).Decode(&details); err != nil {
		return nil, fmt.Errorf("decode match details: %w", err)
	}
	return &details, nil
}

func extractDemoAndMap(details *faceitMatchDetails, base matchEntry) (string, string) {
	if details == nil {
		return "", base.Map
	}
	mapName := base.Map
	if mapName == "" {
		if details.Map != "" {
			mapName = details.Map
		} else if len(details.Voting.Map.Pick) > 0 {
			mapName = details.Voting.Map.Pick[0]
		}
	}
	var demoURL string
	if len(details.DemoURL) > 0 {
		demoURL = details.DemoURL[0]
	}
	return demoURL, mapName
}

func getSignedDemoURL(resource string) (string, error) {
	if faceitAPIKey == "" {
		return resource, fmt.Errorf("FACEIT_API_KEY not initialized")
	}

	payload := strings.NewReader(fmt.Sprintf(`{"type":"demo","resource":"%s"}`, resource))
	req, err := http.NewRequest("POST", "https://open.faceit.com/data/v4/downloads", payload)
	if err != nil {
		return resource, err
	}
	req.Header.Set("Authorization", "Bearer "+faceitAPIKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return resource, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return resource, fmt.Errorf("downloads API %d: %s", resp.StatusCode, string(body))
	}

	var decoded faceitDownloadResponse
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return resource, err
	}

	if decoded.Payload.DownloadURL == "" {
		return resource, fmt.Errorf("downloads API returned empty download_url")
	}

	return decoded.Payload.DownloadURL, nil
}

func downloadDemo(matchID, url string) (string, error) {
	signedURL, err := getSignedDemoURL(url)
	if err != nil {
		log.Printf("  warning: could not get signed URL (%v), using original URL", err)
	} else {
		url = signedURL
	}

	var lastErr error

	for attempt := 1; attempt <= demoDownloadMaxAttempts; attempt++ {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return "", err
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			lastErr = err
		} else if resp.StatusCode >= 400 {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			lastErr = fmt.Errorf("demo download %d: %s", resp.StatusCode, string(body))
		} else {
			defer resp.Body.Close()

			tmpFile, err := os.CreateTemp("", fmt.Sprintf("%s-*.dem", matchID))
			if err != nil {
				return "", err
			}
			defer tmpFile.Close()

			reader := io.Reader(resp.Body)
			lower := strings.ToLower(url)

			switch {
			case strings.HasSuffix(lower, ".gz") || strings.Contains(resp.Header.Get("Content-Type"), "gzip"):
				gzReader, err := gzip.NewReader(resp.Body)
				if err != nil {
					return "", fmt.Errorf("gzip reader: %w", err)
				}
				defer gzReader.Close()
				reader = gzReader

			case strings.HasSuffix(lower, ".zst") || strings.Contains(resp.Header.Get("Content-Type"), "zstd"):
				zReader, err := zstd.NewReader(resp.Body)
				if err != nil {
					return "", fmt.Errorf("zstd reader: %w", err)
				}
				defer zReader.Close()
				reader = zReader
			}

			if _, err := io.Copy(tmpFile, reader); err != nil {
				return "", fmt.Errorf("write demo: %w", err)
			}
			return tmpFile.Name(), nil
		}

		if attempt < demoDownloadMaxAttempts {
			backoff := demoDownloadBaseDelay * time.Duration(attempt*attempt)
			log.Printf("  download failed (attempt %d/%d): %v – retrying in %s", attempt, demoDownloadMaxAttempts, lastErr, backoff)
			time.Sleep(backoff)
		}
	}

	return "", fmt.Errorf("download failed after %d attempts: %w", demoDownloadMaxAttempts, lastErr)
}

func parseDemoForHighlights(demoPath string, group *groupedMatch, tracked map[uint64]playerInfo, demoURL string) ([]highlight, error) {
	f, err := os.Open(demoPath)
	if err != nil {
		return nil, fmt.Errorf("open demo: %w", err)
	}
	defer f.Close()

	parser := dem.NewParser(f)
	defer parser.Close()

	header, err := parser.ParseHeader()
	if err != nil {
		return nil, fmt.Errorf("parse header: %w", err)
	}

	tickRate := header.FrameRate()
	if tickRate <= 0 {
		tickRate = 64.0
	}

	preTicks := int(preSeconds * tickRate)
	postTicks := int(postSeconds * tickRate)
	killGapTicks := int(killGapSeconds * tickRate)

	multiStates := make(map[uint64]multiState)
	candidates := make(map[uint64]highlightCandidate)
	currentRound := 0

	parser.RegisterEventHandler(func(e events.RoundStart) {
		currentRound++
		multiStates = make(map[uint64]multiState)
	})

	parser.RegisterEventHandler(func(e events.Kill) {
		if e.Killer == nil || e.Victim == nil {
			return
		}
		if e.Killer.Team == e.Victim.Team {
			return
		}

		steamID := e.Killer.SteamID64
		if _, ok := tracked[steamID]; !ok {
			return
		}

		tick := parser.GameState().IngameTick()
		state := multiStates[steamID]

		if state.round != currentRound {
			state = multiState{}
		}
		if state.count > 0 && (tick-state.lastTick) > killGapTicks {
			state = multiState{}
		}
		if state.count == 0 {
			state.startTick = tick
			state.startTime = float64(tick) / tickRate
			state.headshots = 0
			state.round = currentRound
		}
		state.count++
		state.lastTick = tick
		state.lastTime = float64(tick) / tickRate
		if e.IsHeadshot {
			state.headshots++
		}
		multiStates[steamID] = state

		if state.count < 2 {
			return
		}

		score := scoreForState(state)
		existing := candidates[steamID]
		if score <= existing.Score {
			return
		}

		candidates[steamID] = highlightCandidate{
			SteamID64:        steamID,
			Round:            state.round,
			Kills:            state.count,
			Headshots:        state.headshots,
			TickStart:        clampInt(state.startTick-preTicks, 0),
			TickEnd:          state.lastTick + postTicks,
			TimeStartSeconds: clampFloat(state.startTime-preSeconds, 0),
			TimeEndSeconds:   state.lastTime + postSeconds,
			Score:            score,
			Category:         fmt.Sprintf("%dx multi-kill", state.count),
			Description:      fmt.Sprintf("%d kills with %d headshots in round %d", state.count, state.headshots, state.round),
		}
	})

	if err := parser.ParseToEnd(); err != nil && err != io.EOF {
		return nil, fmt.Errorf("parse demo: %w", err)
	}

	matchFinished := toMatchTime(group.Base.FinishedAt)
	mapName := group.Base.Map
	now := time.Now().UTC().Format(time.RFC3339)

	var results []highlight
	for steamID, candidate := range candidates {
		info := tracked[steamID]

		h := highlight{
			ID:               fmt.Sprintf("%s:%s", group.MatchID, info.PlayerID),
			MatchID:          group.MatchID,
			PlayerID
