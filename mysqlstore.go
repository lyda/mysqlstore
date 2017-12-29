// Gorilla Sessions backend for MySQL.
//
// Copyright (c) 2013 Contributors. See the list of contributors in the
// CONTRIBUTORS file for details.
//
// This software is licensed under a MIT style license available in the
// LICENSE file.

package mysqlstore

import (
	"database/sql"
	"errors"
	"fmt"
	"github.com/go-sql-driver/mysql"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"net/http"
	"strings"
)

// MySQLStore stores the connection details for a session.
type MySQLStore struct {
	db          *sql.DB
	stmtInsert  *sql.Stmt
	stmtDelete  *sql.Stmt
	stmtUpdate  *sql.Stmt
	stmtSelect  *sql.Stmt
	stmtCleanup *sql.Stmt

	Codecs  []securecookie.Codec
	Options *sessions.Options
	table   string
}

type sessionRow struct {
	id   string
	data string
}

// NewMySQLStore creates a new MySQLStore from a MySQL DSN.
func NewMySQLStore(endpoint string, tableName string, path string, maxAge int, keyPairs ...[]byte) (*MySQLStore, error) {
	db, err := sql.Open("mysql", endpoint)
	if err != nil {
		return nil, err
	}

	return NewMySQLStoreFromConnection(db, tableName, path, maxAge, keyPairs...)
}

// NewMySQLStoreFromConnection creates a new MySQLStore from an existing
// MySQL database connection.
func NewMySQLStoreFromConnection(db *sql.DB, tableName string, path string, maxAge int, keyPairs ...[]byte) (*MySQLStore, error) {
	// Make sure table name is enclosed.
	tableName = "`" + strings.Trim(tableName, "`") + "`"

	cTableQ := "CREATE TABLE IF NOT EXISTS " +
		tableName + " (id INT NOT NULL AUTO_INCREMENT, " +
		"session_data LONGBLOB, " +
		"created_on TIMESTAMP DEFAULT NOW(), " +
		"modified_on TIMESTAMP DEFAULT NOW() ON UPDATE CURRENT_TIMESTAMP, " +
		"expires_on TIMESTAMP DEFAULT NOW(), PRIMARY KEY(`id`)) ENGINE=InnoDB"
	if _, err := db.Exec(cTableQ); err != nil {
		switch err.(type) {
		case *mysql.MySQLError:
			// Error 1142 means permission denied for create command
			if err.(*mysql.MySQLError).Number == 1142 {
				break
			} else {
				return nil, err
			}
		default:
			return nil, err
		}
	}

	insQ := "INSERT INTO " + tableName + "(id, session_data, expires_on) VALUES" +
		fmt.Sprintf(" (NULL, ?, ADDDATE(NOW(), INTERVAL %d SECOND))", maxAge)
	stmtInsert, stmtErr := db.Prepare(insQ)
	if stmtErr != nil {
		return nil, stmtErr
	}

	delQ := "DELETE FROM " + tableName + " WHERE id = ?"
	stmtDelete, stmtErr := db.Prepare(delQ)
	if stmtErr != nil {
		return nil, stmtErr
	}

	updQ := "UPDATE " + tableName + " SET session_data = ? WHERE id = ?"
	stmtUpdate, stmtErr := db.Prepare(updQ)
	if stmtErr != nil {
		return nil, stmtErr
	}

	selQ := "SELECT id, session_data, expires_on < NOW() FROM " +
		tableName + " WHERE id = ?"
	stmtSelect, stmtErr := db.Prepare(selQ)
	if stmtErr != nil {
		return nil, stmtErr
	}

	cleanQ := "DELETE FROM " + tableName + " WHERE expires_on < NOW()"
	stmtCleanup, stmtErr := db.Prepare(cleanQ)
	if stmtErr != nil {
		return nil, stmtErr
	}

	return &MySQLStore{
		db:          db,
		stmtInsert:  stmtInsert,
		stmtDelete:  stmtDelete,
		stmtUpdate:  stmtUpdate,
		stmtSelect:  stmtSelect,
		stmtCleanup: stmtCleanup,
		Codecs:      securecookie.CodecsFromPairs(keyPairs...),
		Options: &sessions.Options{
			Path:   path,
			MaxAge: maxAge,
		},
		table: tableName,
	}, nil
}

// Close closes all resources.
func (m *MySQLStore) Close() {
	m.stmtSelect.Close()
	m.stmtUpdate.Close()
	m.stmtDelete.Close()
	m.stmtInsert.Close()
	m.stmtCleanup.Close()
	m.db.Close()
}

// Get gets session data.
func (m *MySQLStore) Get(r *http.Request, name string) (*sessions.Session, error) {
	return sessions.GetRegistry(r).Get(m, name)
}

// New creates a new session.
func (m *MySQLStore) New(r *http.Request, name string) (*sessions.Session, error) {
	session := sessions.NewSession(m, name)
	session.Options = &sessions.Options{
		Path:     m.Options.Path,
		Domain:   m.Options.Domain,
		MaxAge:   m.Options.MaxAge,
		Secure:   m.Options.Secure,
		HttpOnly: m.Options.HttpOnly,
	}
	session.IsNew = true
	var err error
	if cook, errCookie := r.Cookie(name); errCookie == nil {
		err = securecookie.DecodeMulti(name, cook.Value, &session.ID, m.Codecs...)
		if err == nil {
			err = m.load(session)
			if err == nil {
				session.IsNew = false
			} else {
				err = nil
			}
		}
	}
	return session, err
}

// Save saves the session.
func (m *MySQLStore) Save(r *http.Request, w http.ResponseWriter, session *sessions.Session) error {
	var err error
	if session.ID == "" {
		if err = m.insert(session); err != nil {
			return err
		}
	} else if err = m.save(session); err != nil {
		return err
	}
	encoded, err := securecookie.EncodeMulti(session.Name(), session.ID, m.Codecs...)
	if err != nil {
		return err
	}
	http.SetCookie(w, sessions.NewCookie(session.Name(), encoded, session.Options))
	return nil
}

func (m *MySQLStore) insert(session *sessions.Session) error {
	encoded, encErr := securecookie.EncodeMulti(session.Name(), session.Values, m.Codecs...)
	if encErr != nil {
		return encErr
	}
	res, insErr := m.stmtInsert.Exec(encoded)
	if insErr != nil {
		return insErr
	}
	lastInserted, lInsErr := res.LastInsertId()
	if lInsErr != nil {
		return lInsErr
	}
	session.ID = fmt.Sprintf("%d", lastInserted)
	return nil
}

// Delete deletes a session.
func (m *MySQLStore) Delete(r *http.Request, w http.ResponseWriter, session *sessions.Session) error {

	// Set cookie to expire.
	options := *session.Options
	options.MaxAge = -1
	http.SetCookie(w, sessions.NewCookie(session.Name(), "", &options))
	// Clear session values.
	for k := range session.Values {
		delete(session.Values, k)
	}

	_, delErr := m.stmtDelete.Exec(session.ID)
	if delErr != nil {
		return delErr
	}
	return nil
}

func (m *MySQLStore) save(session *sessions.Session) error {
	if session.IsNew == true {
		return m.insert(session)
	}

	encoded, encErr := securecookie.EncodeMulti(session.Name(), session.Values, m.Codecs...)
	if encErr != nil {
		return encErr
	}
	_, updErr := m.stmtUpdate.Exec(encoded, session.ID)
	if updErr != nil {
		return updErr
	}
	return nil
}

func (m *MySQLStore) load(session *sessions.Session) error {
	row := m.stmtSelect.QueryRow(session.ID)
	sess := sessionRow{}
	var expired bool
	scanErr := row.Scan(&sess.id, &sess.data, &expired)
	if scanErr != nil {
		return scanErr
	}
	if expired {
		return errors.New("Session expired")
	}
	err := securecookie.DecodeMulti(session.Name(), sess.data, &session.Values, m.Codecs...)
	if err != nil {
		return err
	}
	return nil

}
