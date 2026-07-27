(ns fixtures.error-leak
  (:require [clojure.spec.alpha :as s]
            [malli.error :as me]))

(defn create-user [req]
  (if (s/valid? ::user (:body req))
    {:status 201}
    {:status 400 :body (s/explain-data ::user (:body req))}))

;; Second namespace/alias for the same class of leak.
(defn update-user [_req errors]
  {:status 400 :body (me/humanize errors)})
