# check_user.py
from Backend.auth_service import login_user, register_user

uname = "Archit"
pw = "archit@123"

ok, payload = login_user(uname, pw)
print("login_user ->", ok, payload)

# Optionally try to register (uncomment to create if absent):
# success, msg = register_user(uname, "archit@example.com", pw)
# print("register_user ->", success, msg)
