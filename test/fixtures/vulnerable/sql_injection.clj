(ns fixtures.sql-injection
  (:require [next.jdbc :as jdbc]))

(defn find-user [db name]
  (jdbc/execute! db (str "SELECT * FROM users WHERE name = '" name "'")))

(defn list-sorted [db col]
  ;; The dynamic-identifier trap: parameters cannot help here.
  (jdbc/execute! db (str "SELECT * FROM posts ORDER BY " col)))
