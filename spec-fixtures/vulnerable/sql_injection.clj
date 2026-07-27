(ns fixtures.sql-injection
  (:require [next.jdbc :as jdbc]
            [next.jdbc :as sql]))

(defn find-user [db name]
  (jdbc/execute! db (str "SELECT * FROM users WHERE name = '" name "'")))

(defn list-sorted [db col]
  ;; The dynamic-identifier trap: parameters cannot help here.
  (jdbc/execute! db (str "SELECT * FROM posts ORDER BY " col)))

;; A second alias for the same namespace — guards the enumerated alias list.
(defn count-by-type [db t]
  (sql/execute-one! db (str "SELECT count(*) FROM events WHERE type = '" t "'")))
