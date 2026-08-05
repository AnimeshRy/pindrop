// Deliberately vulnerable HTTP handlers.
//
// Every function here exists to trip exactly one bundled Opengrep rule. Do not
// "fix" anything in this file; see ../README.md for the expected findings.
//
// There is intentionally no go.mod in this directory, and the package name is
// not importable from the module root: adding a manifest would give Trivy and
// OSV-Scanner a new dependency source and change their golden finding counts.
package admin

import (
	"database/sql"
	"fmt"
	"net/http"
	"os/exec"
)

// lookupHandler trips go-sql-query-from-sprintf.
func lookupHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenant := r.URL.Query().Get("tenant")
		rows, err := db.Query(fmt.Sprintf("SELECT id, email FROM users WHERE tenant = '%s'", tenant))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer func() { _ = rows.Close() }()
		fmt.Fprintln(w, "ok")
	}
}

// lookupHandlerSafely is the parameterized form of the same query and must NOT
// be reported.
func lookupHandlerSafely(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenant := r.URL.Query().Get("tenant")
		rows, err := db.Query("SELECT id, email FROM users WHERE tenant = $1", tenant)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer func() { _ = rows.Close() }()
		fmt.Fprintln(w, "ok")
	}
}

// backupHandler trips go-exec-command-from-request.
func backupHandler(w http.ResponseWriter, r *http.Request) {
	target := r.FormValue("target")
	out, err := exec.Command("/bin/sh", "-c", "tar czf /tmp/backup.tgz "+target).Output()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_, _ = w.Write(out)
}
