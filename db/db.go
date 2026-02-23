package db

import (
	"database/sql"
	"fmt"
	_ "modernc.org/sqlite"
)

// LogEntry represents an entry in the audit log
type LogEntry struct {
	Timestamp   string
	ClientIP    string
	Method      string
	URL         string
	Host        string
	Reason      string
	ReqHeaders  string
	ReqBody     []byte
	RespStatus  int
	RespHeaders string
	RespBody    []byte
	Action      string
	Error       string
}

type DB struct {
	conn *sql.DB
}

// Init creates or opens the SQLite database and sets up the schema
func Init(path string) (*DB, error) {
	conn, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	schema := `
	CREATE TABLE IF NOT EXISTS audit_log (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		client_ip TEXT,
		method TEXT,
		url TEXT,
		host TEXT,
		reason TEXT,
		req_headers TEXT,
		req_body BLOB,
		resp_status INTEGER,
		resp_headers TEXT,
		resp_body BLOB,
		action TEXT,
		error TEXT
	);
	CREATE INDEX IF NOT EXISTS idx_timestamp ON audit_log(timestamp);
	CREATE INDEX IF NOT EXISTS idx_action ON audit_log(action);
	CREATE INDEX IF NOT EXISTS idx_host ON audit_log(host);
	`
	if _, err := conn.Exec(schema); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to create schema: %w", err)
	}

	return &DB{conn: conn}, nil
}

func (d *DB) LogRequest(ip, method, url, host, reason, headers string, body []byte) (int64, error) {
	// Truncate
	if len(body) > 4096 { body = body[:4096] }
	
	res, err := d.conn.Exec(`
		INSERT INTO audit_log (client_ip, method, url, host, reason, req_headers, req_body, action)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, ip, method, url, host, reason, headers, body, "PENDING")

	if err != nil {
		return 0, fmt.Errorf("db insert error: %w", err)
	}
	return res.LastInsertId()
}

func (d *DB) LogResponse(id int64, status int, headers string, body []byte) error {
	if len(body) > 4096 { body = body[:4096] }
	
	_, err := d.conn.Exec(`
		UPDATE audit_log 
		SET resp_status = ?, resp_headers = ?, resp_body = ?, action = 'ALLOW'
		WHERE id = ?
	`, status, headers, body, id)
	return err
}

func (d *DB) UpdateAction(id int64, action, errorMsg string) error {
	_, err := d.conn.Exec("UPDATE audit_log SET action = ?, error = ? WHERE id = ?", action, errorMsg, id)
	return err
}

func (d *DB) Close() error {
	return d.conn.Close()
}
