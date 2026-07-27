(ns fixtures.triage-low-safe
  (:require [clojure.java.io :as io]
            [clojure.tools.logging :as log]))

(def ^:private +docs+ {"terms" "terms.md" "privacy" "privacy.md"})

;; Allowlist lookup: no request text ever reaches the path.
(defn read-doc [k]
  (when-let [f (get +docs+ k)] (slurp (io/resource (str "docs/" f)))))

;; Fails CLOSED, narrow catch, logged.
(defn authorized? [user]
  (try (check-permissions user)
       (catch java.sql.SQLException e
         (log/warn e "permission lookup failed")
         false)))
