"""
auth.py - Week 9: register and log in from the terminal.

Passwords are hashed with bcrypt. Users are kept in DATA/users.txt, one per line:
username,hash

Run it:  python auth.py
"""

from pathlib import Path

import bcrypt  # library that hashes passwords safely

# Path to the users file: the DATA folder next to this auth.py file
USERS_FILE = Path(__file__).parent / "DATA" / "users.txt"


def generate_hash(password):
    """Turn a password into a bcrypt hash (returned as text)."""
    byte_password = password.encode("utf-8")   # bcrypt needs bytes, not a string
    salt = bcrypt.gensalt()                    # random salt: same password gives a different hash each time
    hashed = bcrypt.hashpw(byte_password, salt)  # scramble the password with the salt
    return hashed.decode("utf-8")              # back to text so it can be saved in a file


def is_valid_hash(password, hashed):
    """True if the password matches the stored hash."""
    # checkpw(password, hash): password first, hash second, both as bytes
    return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))


def user_exists(username, path=USERS_FILE):
    """True if this username is already in the file."""
    if not path.exists():            # first run: no file yet, so nobody exists
        return False
    with open(path, "r") as file:    # "r" = read the file
        for line in file:            # each line is: username,hash
            if "," not in line:
                continue             # skip blank or broken lines
            stored_name, _ = line.strip().split(",", 1)  # split at the first comma only
            if stored_name.lower() == username.lower():  # ignore capital letters
                return True
    return False


def register_user(username, password, path=USERS_FILE):
    """Add a new user. Returns (True or False, a message)."""
    username = username.strip()      # remove spaces at the start and end
    if username == "" or "," in username:
        return False, "Username cannot be empty or contain a comma."  # a comma would break the file format
    if len(password) < 8:
        return False, "Password must be at least 8 characters."
    if user_exists(username, path):
        return False, "That username is already taken."

    path.parent.mkdir(exist_ok=True)  # create the DATA folder if it is missing
    with open(path, "a") as file:     # "a" = append: add a line at the end
        file.write(f"{username},{generate_hash(password)}\n")  # save the hash, never the password
    return True, "Registered. You can log in now."


def login_user(username, password, path=USERS_FILE):
    """Check a username and password. Returns (True or False, a message)."""
    if path.exists():
        with open(path, "r") as file:
            for line in file:
                if "," not in line:
                    continue
                stored_name, stored_hash = line.strip().split(",", 1)
                if stored_name.lower() == username.strip().lower():  # found the user
                    if is_valid_hash(password, stored_hash):         # check the password against the hash
                        return True, "Welcome back!"
                    break  # right user, wrong password: stop looking
    # same message for an unknown user and a wrong password, on purpose:
    # it does not tell an attacker which usernames exist
    return False, "Wrong username or password."


def main():
    """A small menu to try it out."""
    while True:                                  # keep showing the menu until the user exits
        print("\n1. Register\n2. Log in\n3. Exit")
        choice = input("> ")
        if choice == "3":
            print("Goodbye!")
            break                                # leave the loop and end the program
        if choice in ("1", "2"):
            name = input("Username: ")
            password = input("Password: ")
            if choice == "1":
                ok, message = register_user(name, password)
            else:
                ok, message = login_user(name, password)
            print(("OK: " if ok else "NO: ") + message)


# Run main() only when this file is run directly (python auth.py),
# not when it is imported by the notebook test
if __name__ == "__main__":
    main()
