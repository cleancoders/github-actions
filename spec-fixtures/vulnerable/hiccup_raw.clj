(ns fixtures.hiccup-raw
  (:require [hiccup.util :as hu]
            [hiccup.core :as h]))

;; Two DIFFERENT aliases for the same sink, on purpose. semgrep cannot resolve
;; namespace aliases, so the rule enumerates them explicitly. If someone trims
;; that list, one of these stops matching and bin/test-rules.sh fails — which is
;; the entire safety net for choosing semgrep over clj-holmes.
(defn render-bio [user]
  [:div.bio (hu/raw-string (:bio user))])

(defn render-post [post]
  [:article (h/raw (:body post))])

;; Fully-qualified, no alias at all.
(defn render-footer [site]
  [:footer (hiccup.util/raw-string (:footer-html site))])
