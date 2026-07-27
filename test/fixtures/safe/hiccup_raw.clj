(ns fixtures.hiccup-raw-safe)

;; Ordinary hiccup auto-escapes string content — no raw call at all.
(defn render-bio [user]
  [:div.bio (:bio user)])

;; A constant divider expressed as data rather than raw markup.
(defn divider [] [:hr.rule])

;; NOTE: a `raw-string` call on a compile-time constant is genuinely safe, but
;; it is deliberately NOT in this corpus. clj-holmes has no dataflow analysis,
;; so it cannot distinguish a constant argument from a request-derived one and
;; will fire on both. That limitation is documented in the rule's message and
;; triaged by /security-audit, not papered over by loosening the pattern.
