package cliauth

// LoginStage reports where the browser OAuth flow is in [Login].
type LoginStage string

const (
	// LoginStageOpeningBrowser means the CLI is launching the system browser.
	LoginStageOpeningBrowser LoginStage = "opening_browser"
	// LoginStageWaitingBrowser means the user should finish signing in.
	LoginStageWaitingBrowser LoginStage = "waiting_browser"
	// LoginStageManualURL means the user should open Detail in a browser (WSL or
	// when auto-open failed).
	LoginStageManualURL LoginStage = "manual_url"
	// LoginStageVerifying means the authorization code is being exchanged.
	LoginStageVerifying LoginStage = "verifying"
)

// LoginProgress receives stage updates from [Login]. It must be concurrency-safe
// when used with a terminal renderer; implementations should not block.
type LoginProgress func(stage LoginStage, detail string)
