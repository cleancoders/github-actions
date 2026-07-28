(ns fixtures.sql-injection-safe
  (:require [next.jdbc :as jdbc]))

(defn find-user [db name]
  (jdbc/execute! db ["SELECT * FROM users WHERE name = ?" name]))

(def ^:private +sortable+ {"created" "created_at" "title" "title"})

;; Deliberately still builds a string with `str`: this proves the rule keys on
;; a (str ...) form reaching an execute call, not on `str` appearing near SQL
;; text. The identifier is allowlisted, so the query is safe.
(defn list-sorted [db col]
  (let [safe-col (get +sortable+ col "created_at")]
    (jdbc/execute! db [(str "SELECT * FROM posts ORDER BY " safe-col)])))
