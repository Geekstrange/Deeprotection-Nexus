// main.go
package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/gin-contrib/static"
	"github.com/gin-gonic/gin"
)

var listenAddr string

func init() {
	flag.StringVar(&listenAddr, "listen", "127.0.0.1:80", "listen address, e.g., 0.0.0.0:9090")
	flag.Parse()
}

//go:embed public/*
var staticFS embed.FS

const (
	ConfigPath        = "/etc/deeprotection/config.toml"
	LogPath           = "/var/log/audit.log"
	SessionCookieName = "dp_session"
)

// ============================================================
// TOML Config Structs
// ============================================================

type TomlConfig struct {
	Core  CoreConfig  `toml:"core" json:"core"`
	Auth  AuthConfig  `toml:"auth" json:"auth"`
	Paths PathsConfig `toml:"paths" json:"paths"`
	Rules []TomlRule  `toml:"rules" json:"rules"`
}

type CoreConfig struct {
	Mode string `toml:"mode" json:"mode"`
}

type AuthConfig struct {
	PasswordHash string `toml:"password_hash" json:"password_hash"`
}

type PathsConfig struct {
	Protect   []string `toml:"protect" json:"protect"`
	Allowlist []string `toml:"allowlist" json:"allowlist"`
}

type TomlRule struct {
	ID      string     `toml:"id" json:"id"`
	Name    string     `toml:"name" json:"name"`
	Pattern string     `toml:"pattern" json:"pattern"`
	Action  RuleAction `toml:"action" json:"action"`
	Enabled bool       `toml:"enabled" json:"enabled"`
}

type RuleAction struct {
	Block   *bool   `toml:"block,omitempty" json:"block,omitempty"`
	Replace *string `toml:"replace,omitempty" json:"replace,omitempty"`
}

type LogEntry struct {
	Timestamp  string `json:"timestamp"`
	Level      string `json:"level"`
	User       string `json:"user"`
	Mode       string `json:"mode"`
	Command    string `json:"command"`
	WorkingDir string `json:"working_dir"`
	PID        uint32 `json:"pid"`
	ExitCode   int    `json:"exit_code"`
	Message    string `json:"message"`
}

// ============================================================
// API Input Types
// ============================================================

type AddRuleInput struct {
	Pattern string     `json:"pattern"`
	Action  RuleAction `json:"action"`
	Name    string     `json:"name"`
	Enabled *bool      `json:"enabled"`
}

type UpdateRuleInput struct {
	Pattern *string     `json:"pattern"`
	Action  *RuleAction `json:"action"`
	Name    *string     `json:"name"`
	Enabled *bool       `json:"enabled"`
}

// ============================================================
// Auth Helpers
// ============================================================

func hashPassword(password string) string {
	sum := sha256.Sum256([]byte(password))
	return hex.EncodeToString(sum[:])
}

func generateSessionToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

var sessions = map[string]time.Time{}

func createSession() string {
	token := generateSessionToken()
	sessions[token] = time.Now().Add(24 * time.Hour)
	return token
}

func isValidSession(token string) bool {
	if token == "" {
		return false
	}
	expiry, ok := sessions[token]
	if !ok {
		return false
	}
	if time.Now().After(expiry) {
		delete(sessions, token)
		return false
	}
	return true
}

func deleteSession(token string) {
	delete(sessions, token)
}

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		token, _ := c.Cookie(SessionCookieName)
		if !isValidSession(token) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			return
		}
		c.Next()
	}
}

// ============================================================
// Auth Handlers
// ============================================================

func loginHandler(c *gin.Context) {
	var req struct {
		Password string `json:"password"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	conf, err := LoadConfig()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load configuration"})
		return
	}

	if conf.Auth.PasswordHash == "" {
		conf.Auth.PasswordHash = hashPassword(req.Password)
		if err := SaveConfig(conf); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save configuration"})
			return
		}
	} else if hashPassword(req.Password) != conf.Auth.PasswordHash {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid password."})
		return
	}

	token := createSession()
	c.SetCookie(SessionCookieName, token, 86400, "/", "", false, true)
	c.JSON(http.StatusOK, gin.H{"message": "Login successful"})
}

func logoutHandler(c *gin.Context) {
	token, _ := c.Cookie(SessionCookieName)
	deleteSession(token)
	c.SetCookie(SessionCookieName, "", -1, "/", "", false, true)
	c.JSON(http.StatusOK, gin.H{"message": "Logged out"})
}

func authStatusHandler(c *gin.Context) {
	token, _ := c.Cookie(SessionCookieName)
	c.JSON(http.StatusOK, gin.H{"authenticated": isValidSession(token)})
}

// POST /api/change-password
func changePasswordHandler(c *gin.Context) {
	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}
	if req.NewPassword == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "New password cannot be empty"})
		return
	}

	conf, err := LoadConfig()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load configuration"})
		return
	}

	if conf.Auth.PasswordHash != "" {
		if hashPassword(req.OldPassword) != conf.Auth.PasswordHash {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Old password is incorrect"})
			return
		}
	}

	conf.Auth.PasswordHash = hashPassword(req.NewPassword)
	if err := SaveConfig(conf); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save configuration"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Password changed successfully"})
}

// ============================================================
// Service Layer
// ============================================================

func generateID() string {
	b := make([]byte, 6)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func generateRuleName() string {
	return fmt.Sprintf("rule_%d_%s", time.Now().Unix(), generateID()[:4])
}

func LoadConfig() (*TomlConfig, error) {
	var conf TomlConfig
	if _, err := toml.DecodeFile(ConfigPath, &conf); err != nil {
		return nil, err
	}
	if conf.Paths.Protect == nil {
		conf.Paths.Protect = []string{}
	}
	if conf.Paths.Allowlist == nil {
		conf.Paths.Allowlist = []string{}
	}
	if conf.Rules == nil {
		conf.Rules = []TomlRule{}
	}
	return &conf, nil
}

func SaveConfig(conf *TomlConfig) error {
	if conf.Paths.Protect == nil {
		conf.Paths.Protect = []string{}
	}
	if conf.Paths.Allowlist == nil {
		conf.Paths.Allowlist = []string{}
	}
	if conf.Rules == nil {
		conf.Rules = []TomlRule{}
	}
	dir := filepath.Dir(ConfigPath)
	tmp, err := os.CreateTemp(dir, "deeprotection-*.toml.tmp")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpName := tmp.Name()
	if err := toml.NewEncoder(tmp).Encode(conf); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("encoding config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("closing temp file: %w", err)
	}
	if err := os.Rename(tmpName, ConfigPath); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("renaming temp file: %w", err)
	}
	return nil
}

func normalizeAction(a RuleAction) RuleAction {
	if a.Replace != nil {
		s := strings.TrimSpace(*a.Replace)
		a.Replace = &s
		a.Block = nil
		return a
	}
	t := true
	a.Block = &t
	a.Replace = nil
	return a
}

// Protected paths
func AddProtectedPath(path string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return fmt.Errorf("path cannot be empty")
	}
	if strings.Contains(path, "..") {
		return fmt.Errorf("path must not contain '..'")
	}
	conf, err := LoadConfig()
	if err != nil {
		return err
	}
	for _, p := range conf.Paths.Protect {
		if p == path {
			return fmt.Errorf("path already exists")
		}
	}
	conf.Paths.Protect = append(conf.Paths.Protect, path)
	return SaveConfig(conf)
}

func RemoveProtectedPath(path string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return fmt.Errorf("path cannot be empty")
	}
	conf, err := LoadConfig()
	if err != nil {
		return err
	}
	newPaths := make([]string, 0, len(conf.Paths.Protect))
	found := false
	for _, p := range conf.Paths.Protect {
		if p == path {
			found = true
			continue
		}
		newPaths = append(newPaths, p)
	}
	if !found {
		return fmt.Errorf("path not found")
	}
	conf.Paths.Protect = newPaths
	return SaveConfig(conf)
}

// Command allowlist
func AddAllowlistCommand(cmd string) error {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return fmt.Errorf("command cannot be empty")
	}
	conf, err := LoadConfig()
	if err != nil {
		return err
	}
	for _, c := range conf.Paths.Allowlist {
		if c == cmd {
			return fmt.Errorf("command already exists in allowlist")
		}
	}
	conf.Paths.Allowlist = append(conf.Paths.Allowlist, cmd)
	return SaveConfig(conf)
}

func RemoveAllowlistCommand(cmd string) error {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return fmt.Errorf("command cannot be empty")
	}
	conf, err := LoadConfig()
	if err != nil {
		return err
	}
	newList := make([]string, 0, len(conf.Paths.Allowlist))
	found := false
	for _, c := range conf.Paths.Allowlist {
		if c == cmd {
			found = true
			continue
		}
		newList = append(newList, c)
	}
	if !found {
		return fmt.Errorf("command not found in allowlist")
	}
	conf.Paths.Allowlist = newList
	return SaveConfig(conf)
}

// Command rules
func AddCommandRule(input *AddRuleInput) (*TomlRule, error) {
	pattern := strings.TrimSpace(input.Pattern)
	if pattern == "" {
		return nil, fmt.Errorf("pattern cannot be empty")
	}
	if strings.Contains(pattern, "..") {
		return nil, fmt.Errorf("pattern must not contain '..'")
	}
	name := strings.TrimSpace(input.Name)
	if name == "" {
		name = generateRuleName()
	}
	enabled := true
	if input.Enabled != nil {
		enabled = *input.Enabled
	}
	rule := TomlRule{
		ID:      generateID(),
		Name:    name,
		Pattern: pattern,
		Action:  normalizeAction(input.Action),
		Enabled: enabled,
	}
	conf, err := LoadConfig()
	if err != nil {
		return nil, err
	}
	conf.Rules = append(conf.Rules, rule)
	if err := SaveConfig(conf); err != nil {
		return nil, err
	}
	return &rule, nil
}

func FullUpdateCommandRule(id string, input *AddRuleInput) (*TomlRule, error) {
	conf, err := LoadConfig()
	if err != nil {
		return nil, err
	}
	for i, r := range conf.Rules {
		if r.ID != id {
			continue
		}
		pattern := strings.TrimSpace(input.Pattern)
		if pattern == "" {
			return nil, fmt.Errorf("pattern cannot be empty")
		}
		name := strings.TrimSpace(input.Name)
		if name == "" {
			name = r.Name
		}
		enabled := r.Enabled
		if input.Enabled != nil {
			enabled = *input.Enabled
		}
		conf.Rules[i] = TomlRule{
			ID:      id,
			Name:    name,
			Pattern: pattern,
			Action:  normalizeAction(input.Action),
			Enabled: enabled,
		}
		if err := SaveConfig(conf); err != nil {
			return nil, err
		}
		updated := conf.Rules[i]
		return &updated, nil
	}
	return nil, fmt.Errorf("rule not found")
}

func PatchCommandRule(id string, input *UpdateRuleInput) (*TomlRule, error) {
	conf, err := LoadConfig()
	if err != nil {
		return nil, err
	}
	for i, r := range conf.Rules {
		if r.ID != id {
			continue
		}
		if input.Pattern != nil {
			p := strings.TrimSpace(*input.Pattern)
			if p == "" {
				return nil, fmt.Errorf("pattern cannot be empty")
			}
			conf.Rules[i].Pattern = p
		}
		if input.Name != nil {
			conf.Rules[i].Name = strings.TrimSpace(*input.Name)
		}
		if input.Enabled != nil {
			conf.Rules[i].Enabled = *input.Enabled
		}
		if input.Action != nil {
			conf.Rules[i].Action = normalizeAction(*input.Action)
		}
		if err := SaveConfig(conf); err != nil {
			return nil, err
		}
		updated := conf.Rules[i]
		return &updated, nil
	}
	return nil, fmt.Errorf("rule not found")
}

func DeleteCommandRule(id string) error {
	conf, err := LoadConfig()
	if err != nil {
		return err
	}
	newRules := make([]TomlRule, 0, len(conf.Rules))
	found := false
	for _, r := range conf.Rules {
		if r.ID == id {
			found = true
			continue
		}
		newRules = append(newRules, r)
	}
	if !found {
		return fmt.Errorf("rule not found")
	}
	conf.Rules = newRules
	return SaveConfig(conf)
}

// ============================================================
// Main
// ============================================================

func main() {
	gin.SetMode(gin.ReleaseMode)

	r := gin.Default()

	embeddedStaticFS, err := static.EmbedFolder(staticFS, "public")
	if err != nil {
		log.Fatalf("Failed to create embed folder: %v", err)
	}
	r.Use(static.Serve("/", embeddedStaticFS))

	r.GET("/login", func(c *gin.Context) {
		token, _ := c.Cookie(SessionCookieName)
		if isValidSession(token) {
			c.Redirect(http.StatusFound, "/")
			return
		}
		c.FileFromFS("public/login.html", http.FS(staticFS))
	})

	api := r.Group("/api")
	{
		api.POST("/login", loginHandler)
		api.POST("/logout", logoutHandler)
		api.GET("/auth/status", authStatusHandler)

		protected := api.Group("/", authMiddleware())
		{
			protected.GET("/config", getConfigHandler)
			protected.POST("/config", updateBasicConfigHandler)
			protected.POST("/change-password", changePasswordHandler)

			protected.GET("/stats", getStatsHandler)
			protected.GET("/logs", logStreamHandler)

			protected.GET("/protected-paths", listProtectedPathsHandler)
			protected.POST("/protected-paths", addProtectedPathHandler)
			protected.DELETE("/protected-paths", deleteProtectedPathHandler)

			protected.GET("/command-allowlist", listAllowlistHandler)
			protected.POST("/command-allowlist", addAllowlistHandler)
			protected.DELETE("/command-allowlist", deleteAllowlistHandler)

			protected.GET("/command-rules", listCommandRulesHandler)
			protected.POST("/command-rules", addCommandRuleHandler)
			protected.PUT("/command-rules/:id", putCommandRuleHandler)
			protected.PATCH("/command-rules/:id", patchCommandRuleHandler)
			protected.DELETE("/command-rules/:id", deleteCommandRuleHandler)

			protected.GET("/plugins", listPluginsHandler)
			protected.POST("/plugins/toggle", togglePluginHandler)
			protected.DELETE("/plugins/:id", deletePluginHandler)
			protected.POST("/plugins/install", installPluginHandler)
		}
	}

	log.Printf("Starting Deeprotection Nexus on %s", listenAddr)
	if err := r.Run(listenAddr); err != nil {
		log.Fatal(err)
	}
}

// ============================================================
// Config Handlers
// ============================================================

func getConfigHandler(c *gin.Context) {
	conf, err := LoadConfig()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"basic":             gin.H{"mode": conf.Core.Mode},
		"protected_paths":   conf.Paths.Protect,
		"command_allowlist": conf.Paths.Allowlist,
		"command_rules":     conf.Rules,
	})
}

func updateBasicConfigHandler(c *gin.Context) {
	var req map[string]interface{}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}
	conf, err := LoadConfig()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if basicRaw, ok := req["basic"]; ok {
		if basicMap, ok := basicRaw.(map[string]interface{}); ok {
			if mode, ok := basicMap["mode"].(string); ok {
				conf.Core.Mode = mode
			}
		}
	}
	if err := SaveConfig(conf); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Configuration updated successfully"})
}

// ============================================================
// Stats Handler
// ============================================================

func getStatsHandler(c *gin.Context) {
	count, err := countLogLines()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to count log lines"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"protection_count": count})
}

func countLogLines() (int, error) {
	file, err := os.Open(LogPath)
	if err != nil {
		return 0, err
	}
	defer file.Close()
	count := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		count++
	}
	return count, scanner.Err()
}

// ============================================================
// Protected Path Handlers
// ============================================================

func listProtectedPathsHandler(c *gin.Context) {
	conf, err := LoadConfig()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": conf.Paths.Protect})
}

func addProtectedPathHandler(c *gin.Context) {
	var req struct {
		Path string `json:"path"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}
	if err := AddProtectedPath(req.Path); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Path added successfully", "data": gin.H{"path": strings.TrimSpace(req.Path)}})
}

func deleteProtectedPathHandler(c *gin.Context) {
	path := c.Query("path")
	if path == "" {
		var req struct {
			Path string `json:"path"`
		}
		if err := c.BindJSON(&req); err == nil {
			path = req.Path
		}
	}
	if err := RemoveProtectedPath(path); err != nil {
		status := http.StatusBadRequest
		if err.Error() == "path not found" {
			status = http.StatusNotFound
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Path removed successfully"})
}

// ============================================================
// Command Allowlist Handlers
// ============================================================

func listAllowlistHandler(c *gin.Context) {
	conf, err := LoadConfig()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": conf.Paths.Allowlist})
}

func addAllowlistHandler(c *gin.Context) {
	var req struct {
		Command string `json:"command"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}
	if err := AddAllowlistCommand(req.Command); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Command added to allowlist", "data": gin.H{"command": strings.TrimSpace(req.Command)}})
}

func deleteAllowlistHandler(c *gin.Context) {
	cmd := c.Query("command")
	if cmd == "" {
		var req struct {
			Command string `json:"command"`
		}
		if err := c.BindJSON(&req); err == nil {
			cmd = req.Command
		}
	}
	if err := RemoveAllowlistCommand(cmd); err != nil {
		status := http.StatusBadRequest
		if err.Error() == "command not found in allowlist" {
			status = http.StatusNotFound
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Command removed from allowlist"})
}

// ============================================================
// Command Rule Handlers
// ============================================================

func listCommandRulesHandler(c *gin.Context) {
	conf, err := LoadConfig()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": conf.Rules})
}

func addCommandRuleHandler(c *gin.Context) {
	var input AddRuleInput
	if err := c.BindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}
	rule, err := AddCommandRule(&input)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Rule created successfully", "data": rule})
}

func putCommandRuleHandler(c *gin.Context) {
	id := c.Param("id")
	var input AddRuleInput
	if err := c.BindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}
	rule, err := FullUpdateCommandRule(id, &input)
	if err != nil {
		status := http.StatusBadRequest
		if err.Error() == "rule not found" {
			status = http.StatusNotFound
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Rule updated successfully", "data": rule})
}

func patchCommandRuleHandler(c *gin.Context) {
	id := c.Param("id")
	var input UpdateRuleInput
	if err := c.BindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}
	rule, err := PatchCommandRule(id, &input)
	if err != nil {
		status := http.StatusBadRequest
		if err.Error() == "rule not found" {
			status = http.StatusNotFound
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Rule patched successfully", "data": rule})
}

func deleteCommandRuleHandler(c *gin.Context) {
	id := c.Param("id")
	if err := DeleteCommandRule(id); err != nil {
		status := http.StatusBadRequest
		if err.Error() == "rule not found" {
			status = http.StatusNotFound
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Rule deleted successfully"})
}

// ============================================================
// Log Stream Handler (SSE)
// ============================================================

func logStreamHandler(c *gin.Context) {
	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Writer.Flush()

	file, err := os.Open(LogPath)
	if err != nil {
		c.SSEvent("error", fmt.Sprintf("Error opening log file: %v", err))
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		sendLogLine(c, scanner.Text())
	}

	lastPos, _ := file.Seek(0, io.SeekCurrent)
	lastSize := lastPos

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	clientGone := c.Writer.CloseNotify()

	for {
		select {
		case <-clientGone:
			return
		case <-ticker.C:
			fileInfo, err := os.Stat(LogPath)
			if err != nil {
				c.SSEvent("error", fmt.Sprintf("Error getting file info: %v", err))
				continue
			}
			currentSize := fileInfo.Size()
			if currentSize < lastSize {
				lastPos = 0
				lastSize = currentSize
				file.Close()
				file, err = os.Open(LogPath)
				if err != nil {
					c.SSEvent("error", fmt.Sprintf("Error reopening log file: %v", err))
					return
				}
				scanner = bufio.NewScanner(file)
				for scanner.Scan() {
					sendLogLine(c, scanner.Text())
				}
				lastPos, _ = file.Seek(0, io.SeekCurrent)
				lastSize = lastPos
				continue
			}
			if currentSize <= lastPos {
				continue
			}
			file.Seek(lastPos, io.SeekStart)
			scanner = bufio.NewScanner(file)
			for scanner.Scan() {
				sendLogLine(c, scanner.Text())
			}
			newPos, _ := file.Seek(0, io.SeekCurrent)
			lastPos = newPos
			lastSize = currentSize
		}
	}
}

func sendLogLine(c *gin.Context, rawLine string) {
	var entry LogEntry
	if err := json.Unmarshal([]byte(rawLine), &entry); err == nil {
		c.SSEvent("log", formatLogEntry(&entry))
	} else {
		c.SSEvent("log", rawLine)
	}
	c.Writer.Flush()
}

func formatLogEntry(entry *LogEntry) string {
	t, err := time.Parse(time.RFC3339, entry.Timestamp)
	timeStr := entry.Timestamp
	if err == nil {
		timeStr = t.Format("2006-01-02 15:04:05")
	}
	return fmt.Sprintf("[%s] %s - user %s executed \"%s\" (mode: %s, pid: %d) - %s",
		timeStr, entry.Level, entry.User, entry.Command, entry.Mode, entry.PID, entry.Message)
}

// ============================================================
// Plugins
// ============================================================

type PluginMeta struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Version     string `json:"version"`
	Author      string `json:"author"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
	Entrypoint  string `json:"entrypoint"`
	Type        string `json:"type"`
}

const PluginsPath = "/etc/deeprotection/plugins"

func ListPlugins() ([]PluginMeta, error) {
	entries, err := os.ReadDir(PluginsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return []PluginMeta{}, nil
		}
		return nil, err
	}
	var plugins []PluginMeta
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		metaPath := filepath.Join(PluginsPath, entry.Name(), "plugin.json")
		data, err := os.ReadFile(metaPath)
		if err != nil {
			continue
		}
		var meta PluginMeta
		if err := json.Unmarshal(data, &meta); err != nil {
			continue
		}
		plugins = append(plugins, meta)
	}
	return plugins, nil
}

func SavePluginMeta(pluginDir string, meta *PluginMeta) error {
	metaPath := filepath.Join(pluginDir, "plugin.json")
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(metaPath, data, 0644)
}

func TogglePlugin(id string, enabled bool) error {
	plugins, err := ListPlugins()
	if err != nil {
		return err
	}
	for _, p := range plugins {
		if p.ID == id {
			p.Enabled = enabled
			pluginDir := filepath.Join(PluginsPath, id)
			return SavePluginMeta(pluginDir, &p)
		}
	}
	return fmt.Errorf("plugin not found")
}

func DeletePlugin(id string) error {
	pluginDir := filepath.Join(PluginsPath, id)
	return os.RemoveAll(pluginDir)
}

func listPluginsHandler(c *gin.Context) {
	plugins, err := ListPlugins()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": plugins})
}

func togglePluginHandler(c *gin.Context) {
	var req struct {
		ID      string `json:"id"`
		Enabled bool   `json:"enabled"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}
	if err := TogglePlugin(req.ID, req.Enabled); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Plugin toggled"})
}

func deletePluginHandler(c *gin.Context) {
	id := c.Param("id")
	if err := DeletePlugin(id); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Plugin deleted"})
}

func installPluginHandler(c *gin.Context) {
	file, header, err := c.Request.FormFile("plugin")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing plugin file"})
		return
	}
	defer file.Close()

	if !strings.HasSuffix(strings.ToLower(header.Filename), ".zip") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Only .zip files are allowed"})
		return
	}

	zipData, err := io.ReadAll(file)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read uploaded file"})
		return
	}

	zipReader, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid zip archive"})
		return
	}

	var meta PluginMeta
	metaFound := false
	for _, f := range zipReader.File {
		if f.Name == "plugin.json" {
			rc, err := f.Open()
			if err != nil {
				continue
			}
			data, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				continue
			}
			if err := json.Unmarshal(data, &meta); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid plugin.json: " + err.Error()})
				return
			}
			metaFound = true
			break
		}
	}
	if !metaFound {
		c.JSON(http.StatusBadRequest, gin.H{"error": "plugin.json not found in archive root"})
		return
	}

	if meta.ID == "" || meta.Name == "" || meta.Version == "" || meta.Entrypoint == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "plugin.json missing required fields (id, name, version, entrypoint)"})
		return
	}

	pluginDir := filepath.Join(PluginsPath, meta.ID)
	if _, err := os.Stat(pluginDir); err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "Plugin with this ID already exists"})
		return
	}

	if err := os.MkdirAll(pluginDir, 0755); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create plugin directory"})
		return
	}

	for _, f := range zipReader.File {
		name := filepath.Clean(f.Name)
		if strings.Contains(name, "..") {
			continue
		}
		targetPath := filepath.Join(pluginDir, name)
		rel, err := filepath.Rel(pluginDir, targetPath)
		if err != nil || strings.HasPrefix(rel, "..") {
			continue
		}

		if f.FileInfo().IsDir() {
			os.MkdirAll(targetPath, 0755)
			continue
		}

		if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			continue
		}
		outFile, err := os.Create(targetPath)
		if err != nil {
			rc.Close()
			continue
		}
		_, err = io.Copy(outFile, rc)
		outFile.Close()
		rc.Close()
		if err != nil {
		}
	}

	meta.Enabled = true
	if err := SavePluginMeta(pluginDir, &meta); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save plugin metadata"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Plugin installed successfully", "data": meta})
}
