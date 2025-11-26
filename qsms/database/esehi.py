from qsms.database.user_management import DBUserStore
store = DBUserStore()

# Add a user
store.add_user("dimpal", "correct horse battery staple")
# -> no output on success (raises ValueError if user exists)

# Fetch user for auth (fields are base64 / ints for the auth protocol)
rec = store.get("dimpal")
print(rec)
# -> UserRecord(username='alice', salt_b64='...', pbkdf2_iter=200000, password_hash_b64='...')

# Verify credentials
print(store.verify_credentials("alice", "correct horse battery staple"))
# -> True
print(store.verify_credentials("alice", "wrong"))
# -> False

# Record an auth attempt in audit log
store.record_login("alice", ok=True, ip="127.0.0.1")
# -> no output, but a row is written to auth_audit

# Update password
store.update_password("alice", "new strong password", pbkdf2_iter=300_000)
print(store.verify_credentials("alice", "new strong password"))
# -> True

# Delete user (optional)
store.delete_user("alice")
# -> True (and related rows cascade if present)
