package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/AnimeshRy/pindrop/internal/cliauth"
)

// AuthStyles builds lipgloss styles for auth command output.
func AuthStyles(color bool) styles {
	return newStyles(color)
}

// AuthStatusLine renders a one-line login identity marker for stderr.
func AuthStatusLine(styles styles, loggedIn bool, email, provider string) string {
	if !loggedIn {
		return styles.dim.Render("Not logged in — run: pindrop login")
	}
	line := fmt.Sprintf("%s Logged in as %s", markDone, email)
	if provider != "" {
		line += fmt.Sprintf(" (%s)", strings.ToLower(provider))
	}
	return styles.done.Render(line)
}

// LoggedInLine renders the signed-in marker from stored credentials.
func LoggedInLine(styles styles, creds cliauth.Credentials) string {
	return AuthStatusLine(styles, true, creds.DisplayEmail(), creds.DisplayProvider())
}

// SyncAsLine renders the identity line shown at the start of sync.
func SyncAsLine(styles styles, creds cliauth.Credentials) string {
	line := fmt.Sprintf("Syncing as %s", creds.DisplayEmail())
	if p := creds.DisplayProvider(); p != "" {
		line += fmt.Sprintf(" (%s)", strings.ToLower(p))
	}
	return styles.title.Render(line)
}

// LoggedOutLine renders confirmation after logout.
func LoggedOutLine(styles styles, email string) string {
	return styles.done.Render(fmt.Sprintf("%s Logged out of %s", markDone, email))
}

// LoginSuccessLine renders confirmation after a successful login.
func LoginSuccessLine(styles styles, creds cliauth.Credentials) string {
	return LoggedInLine(styles, creds)
}

// loginStageMsg carries a cliauth stage into the bubbletea model.
type loginStageMsg struct {
	stage  cliauth.LoginStage
	detail string
}

// loginDoneMsg tells the model to render its final frame.
type loginDoneMsg struct{}

// loginModel is the bubbletea model for browser OAuth progress.
type loginModel struct {
	stage   cliauth.LoginStage
	detail  string
	styles  styles
	frame   int
	quit    bool
	provider string
}

func (m loginModel) Init() tea.Cmd { return tick() }

func (m loginModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tickMsg:
		if m.quit {
			return m, nil
		}
		m.frame++
		return m, tick()
	case loginStageMsg:
		m.stage = msg.stage
		m.detail = msg.detail
		if msg.stage == cliauth.LoginStageManualURL {
			m.quit = true
		}
		return m, nil
	case loginDoneMsg:
		m.quit = true
		return m, tea.Quit
	}
	return m, nil
}

func (m loginModel) View() string {
	var b strings.Builder
	fmt.Fprintf(&b, "\n  %s %s\n\n", m.styles.title.Render("Signing in"), m.styles.dim.Render("via "+m.providerLabel()))

	mark, style, status := m.rowState()
	b.WriteString(fmt.Sprintf("  %s %s\n\n", style.Render(mark), m.styles.name.Render(status)))

	if m.stage == cliauth.LoginStageManualURL {
		b.WriteString(m.styles.dim.Render("  Open this URL in your browser to sign in:") + "\n")
		b.WriteString(m.styles.dim.Render("  (full URL printed below)") + "\n\n")
		b.WriteString(m.styles.dim.Render("  Return here after you finish signing in.") + "\n")
	} else {
		b.WriteString(m.styles.dim.Render("  Complete sign-in in your browser, then return here.") + "\n")
	}
	return b.String()
}

func (m loginModel) providerLabel() string {
	switch strings.ToLower(m.provider) {
	case "github":
		return "GitHub"
	case "google":
		return "Google"
	default:
		return m.provider
	}
}

func (m loginModel) rowState() (mark string, style lipglossStyle, status string) {
	switch m.stage {
	case cliauth.LoginStageVerifying:
		return spinnerFrames[m.frame%len(spinnerFrames)], m.styles.running, "Verifying session…"
	case cliauth.LoginStageManualURL:
		return markPending, m.styles.dim, "Open this URL in your browser"
	case cliauth.LoginStageWaitingBrowser:
		return spinnerFrames[m.frame%len(spinnerFrames)], m.styles.running, "Waiting for you to finish signing in…"
	case cliauth.LoginStageOpeningBrowser:
		return spinnerFrames[m.frame%len(spinnerFrames)], m.styles.running, "Opening browser…"
	default:
		return markPending, m.styles.dim, "Starting…"
	}
}

// LoginSession reports browser OAuth progress. It implements cliauth.LoginProgress.
type LoginSession struct {
	*Session
	provider string
	plain    map[string]bool
}

// StartLogin begins reporting a browser OAuth flow.
func StartLogin(provider string, opts Options) *LoginSession {
	model := loginModel{
		styles:   newStyles(opts.Color),
		provider: provider,
	}
	session := start(opts, model)
	return &LoginSession{
		Session:  session,
		provider: provider,
		plain:    map[string]bool{},
	}
}

// Progress implements [cliauth.LoginProgress].
func (s *LoginSession) Progress(stage cliauth.LoginStage, detail string) {
	s.send(loginStageMsg{stage: stage, detail: detail})

	if stage == cliauth.LoginStageManualURL && detail != "" && s.firstPlain("manual_url") {
		// Never embed the authorize URL in a bubbletea frame — inline redraws
		// truncate to terminal width and drop provider / redirect_to params.
		_, _ = fmt.Fprintf(s.opts.out(),
			"\n  Open this URL in your browser to sign in:\n\n  %s\n\n  Return here after you finish signing in.\n",
			detail)
	}

	if s.opts.Mode != ModePlain {
		return
	}

	key := string(stage)
	if s.plain[key] {
		return
	}
	s.plain[key] = true

	switch stage {
	case cliauth.LoginStageOpeningBrowser:
		s.printfPlain("Opening browser…\n")
	case cliauth.LoginStageWaitingBrowser:
		s.printfPlain("Waiting for you to finish signing in…\n")
	case cliauth.LoginStageManualURL:
		// URL printed above for all modes.
	case cliauth.LoginStageVerifying:
		s.printfPlain("Verifying session…\n")
	}
}

// Stop finishes the display.
func (s *LoginSession) Stop() {
	s.send(loginDoneMsg{})
	s.Session.Stop()
	s.separate()
}

// PrintAuthLine writes a styled auth status line to stderr.
func PrintAuthLine(opts Options, loggedIn bool, email, provider string) {
	styles := newStyles(opts.Color)
	line := AuthStatusLine(styles, loggedIn, email, provider)
	if opts.Mode == ModeSilent {
		return
	}
	_, _ = fmt.Fprintln(opts.out(), line)
}

// PrintLine writes an arbitrary styled line to stderr.
func PrintLine(opts Options, line string) {
	if opts.Mode == ModeSilent {
		return
	}
	_, _ = fmt.Fprintln(opts.out(), line)
}

// CLIAuthOptions builds [Options] for auth commands from global CLI flags.
func CLIAuthOptions(stderrIsTerminal bool, term, logLevel string, color bool) Options {
	return Options{
		Out:   nil, // defaults to stderr
		Mode:  ResolveMode("", stderrIsTerminal, term, logLevel),
		Color: color,
	}
}
