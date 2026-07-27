(ns fixtures.cljs-xss
  (:require [dommy.core :as dommy]))

(defn show-note [el note]
  (set! (.-innerHTML el) note))

(defn show-via-dommy [el note]
  (dommy/set-html! el note))

;; Second alias for the same sink — guards the rule's enumerated alias list.
(defn show-via-d [el note]
  (d/set-html! el note))

(defn run-expr [expr]
  (js/eval expr))

(defn make-fn [src]
  ((js/Function. "x" src) 1))

(defn bio-panel [user]
  [:div {:dangerouslySetInnerHTML #js {:__html (:bio user)}}])
