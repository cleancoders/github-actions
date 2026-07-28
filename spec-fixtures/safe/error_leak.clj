(ns fixtures.error-leak-safe
  (:require [clojure.spec.alpha :as s]
            [clojure.tools.logging :as log]))

(defn- field-names [ed]
  (mapv #(-> % :path first name) (::s/problems ed)))

;; explain-data IS called — but its output never reaches :body. Only field
;; names go back to the client; the detail is logged server-side.
(defn create-user [req]
  (if (s/valid? ::user (:body req))
    {:status 201}
    (let [ed (s/explain-data ::user (:body req))]
      (log/warn "validation failed" {:fields (field-names ed)})
      {:status 400 :body {:errors (field-names ed)}})))
