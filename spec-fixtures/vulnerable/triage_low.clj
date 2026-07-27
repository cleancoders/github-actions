(ns fixtures.triage-low
  (:require [clojure.java.io :as io]
            [clojure.java.io :as jio]
            [clojure.tools.logging :as log]))

(defn read-upload [params]
  (slurp (io/file "uploads" (:name params))))

;; Second alias for the same sink — guards the enumerated alias list.
(defn read-attachment [params]
  (slurp (jio/file "attachments" (:filename params))))

(defn authorized? [user]
  ;; Fails OPEN: an exception in the permission lookup grants access.
  (try (check-permissions user)
       (catch Exception _ true)))

(defn audit! [event]
  ;; Swallows the failure; the caller reads nil as "no problem".
  (try (write-audit-log! event)
       (catch Exception _ nil)))

(defn log-it [e] (log/warn e "ignored"))
