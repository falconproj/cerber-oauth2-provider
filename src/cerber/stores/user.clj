(ns cerber.stores.user
  (:require [mount.core :refer [defstate]]
            [cerber
             [db :as db]
             [error :as error]
             [helpers :as helpers]
             [store :refer :all]]
            [failjure.core :as f]))

(def user-store (atom :not-initialized))

(defrecord User [id login email name password enabled? created-at modified-at activated-at blocked-at])

(defrecord SqlUserStore [normalizer]
  Store
  (fetch-one [this [login]]
    (-> (db/call 'find-user {:login login})
        first
        normalizer))
  (revoke-one! [this [login]]
    (db/call 'delete-user {:login login}))
  (store! [this k user]
    (when (= 1 (db/call 'insert-user user)) user))
  (modify! [this k user]
    (if (:enabled? user)
      (db/call 'enable-user user)
      (db/call 'disable-user user)))
  (purge! [this]
    (db/call 'clear-users)))

(defn normalize
  [user]
  (when-let [{:keys [id login email name password roles permissions created_at modified_at activated_at blocked_at enabled]} user]
    (map->User {:id id
                :login login
                :email email
                :name name
                :password password
                :enabled? enabled
                :created-at created_at
                :modified-at modified_at
                :activated-at activated_at
                :blocked-at blocked_at
                :roles (helpers/str->coll #{} roles)
                :permissions (helpers/str->coll #{} permissions)})))

(defmulti create-user-store (fn [type config] type))

(defmethod create-user-store :in-memory [_ _]
  (->MemoryStore "users" (atom {})))

(defmethod create-user-store :redis [_ redis-spec]
  (->RedisStore "users" redis-spec))

(defmethod create-user-store :sql [_ jdbc-spec]
  (db/init-pool jdbc-spec)
  (->SqlUserStore normalize))

(defn create-user
  "Creates new user."

  ([user password]
   (create-user user password nil nil))
  ([user password roles permissions]
   (let [enabled (:enabled? user true)
         merged  (merge-with
                  #(or %2 %1)
                  user
                  {:id (helpers/uuid)
                   :name nil
                   :email nil
                   :enabled? enabled
                   :password (and password (helpers/bcrypt-hash password))
                   :roles (helpers/coll->str roles)
                   :permissions (helpers/coll->str permissions)
                   :activated-at (when enabled (helpers/now))
                   :created-at (helpers/now)})]

     (if (store! @user-store [:login] merged)
       (map->User merged)
       (error/internal-error "Cannot store user")))))

(defn find-user
  "Returns users with given login, if found or nil otherwise."

  [login]
  (if-let [found (and login (fetch-one @user-store [login]))]
    (map->User found)))

(defn revoke-user
  "Removes user from store"

  [user]
  (revoke-one! @user-store [(:login user)]))

(defn enable-user
  "Enables user. Returns true if user has been enabled successfully or false otherwise."

  [user]
  (= 1 (modify! @user-store [:login] (assoc user :enabled? true :activated-at (helpers/now)))))

(defn disable-user
  "Disables user. Returns true if user has been disabled successfully or false otherwise."

  [user]
  (= 1 (modify! @user-store [:login] (assoc user :enabled? false :blocked-at (helpers/now)))))

(defn purge-users
  "Removes users from store."

  []
  (purge! @user-store))

(defn valid-password?
  "Verifies that given password matches the hashed one."

  [password hashed]
  (and password hashed (helpers/bcrypt-check password hashed)))

(defn init-store
  "Initializes user store according to given connection spec."

  [type {:keys [jdbc-spec redis-spec]}]
  (if-let [spec (or jdbc-spec redis-spec (= type :in-memory))]
    (reset! user-store (create-user-store type spec))
    (println (str "Connection spec missing for " type " type of store."))))
