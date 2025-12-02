import bcrypt
import os

USER_FILE = "users.txt"

def hash_pw(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_pw(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed.encode())

def user_exists(username):
    if not os.path.exists(USER_FILE):
        return False
    with open(USER_FILE, 'r') as f:
        for line in f:
            if line.startswith(username + ","):
                return True
    return False

def register(username, password):
    if user_exists(username):
        print(f"Error: User '{username}' exists!")
        return False
    hashed = hash_pw(password)
    with open(USER_FILE, 'a') as f:
        f.write(f"{username},{hashed}\n")
    print(f"Success: User '{username}' registered!")
    return True

def login(username, password):
    if not os.path.exists(USER_FILE):
        print("No users registered!")
        return False
    with open(USER_FILE, 'r') as f:
        for line in f:
            parts = line.strip().split(',')
            if len(parts) == 2 and parts[0] == username:
                if verify_pw(password, parts[1]):
                    print(f"Success: Welcome {username}!")
                    return True
                else:
                    print("Error: Wrong password!")
                    return False
    print("Error: User not found!")
    return False

def validate_username(username):
    if len(username) < 3 or len(username) > 20:
        return False, "Username must be 3-20 chars"
    if not username.isalnum():
        return False, "Username must be alphanumeric"
    return True, ""

def validate_password(password):
    if len(password) < 6:
        return False, "Password must be at least 6 chars"
    if not any(c.isdigit() for c in password):
        return False, "Password needs at least 1 digit"
    if not any(c.isupper() for c in password):
        return False, "Password needs at least 1 uppercase letter"
    return True, ""

def main():
    print("\n=== Secure Auth System ===\n")
    
    while True:
        print("[1] Register")
        print("[2] Login")
        print("[3] Exit")
        choice = input("Choice: ").strip()
        
        if choice == '1':
            print("\n--- Register ---")
            username = input("Username: ").strip()
            ok, msg = validate_username(username)
            if not ok:
                print(f"Error: {msg}")
                continue
                
            password = input("Password: ").strip()
            ok, msg = validate_password(password)
            if not ok:
                print(f"Error: {msg}")
                continue
                
            confirm = input("Confirm password: ").strip()
            if password != confirm:
                print("Error: Passwords don't match!")
                continue
                
            register(username, password)
            
        elif choice == '2':
            print("\n--- Login ---")
            username = input("Username: ").strip()
            password = input("Password: ").strip()
            login(username, password)
            
        elif choice == '3':
            print("Goodbye!")
            break
        else:
            print("Invalid choice!")

if __name__ == "__main__":
    main()