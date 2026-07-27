(ns fixtures.hiccup-raw
  (:require [hiccup.util :as hu]
            [hiccup.core :as h]))

;; Aliased call — the whole reason this repo uses clj-holmes rather than
;; semgrep. Semgrep's experimental Clojure tree-sitter cannot resolve `hu` back
;; to hiccup.util and would need one literal pattern per alias.
(defn render-bio [user]
  [:div.bio (hu/raw-string (:bio user))])

(defn render-post [post]
  [:article (h/raw (:body post))])
