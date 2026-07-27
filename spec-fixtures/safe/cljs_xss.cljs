(ns fixtures.cljs-xss-safe)

;; textContent escapes; no HTML parsing occurs.
(defn show-note [el note]
  (set! (.-textContent el) note))

;; Reagent escapes string children by default.
(defn bio-panel [user]
  [:div.bio (:bio user)])

;; Dispatch through a hard-coded map, never eval.
(def ^:private +actions+ {"greet" (fn [] "hi") "bye" (fn [] "bye")})

(defn run-action [k]
  (when-let [f (get +actions+ k)] (f)))
