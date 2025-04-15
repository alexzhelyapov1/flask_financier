# db_api.py

import sqlite3
import datetime
import hashlib
import os
from typing import List, Optional, Dict, Any, Tuple, Union
from zoneinfo import ZoneInfo  # Requires Python 3.9+ and tzdata package (`pip install tzdata`)

# --- Constants ---
# Operation Types for Accounting table
OP_INCOME = 1
OP_SPEND = 2
OPERATION_TYPES = {"Income": OP_INCOME, "Spend": OP_SPEND}
OPERATION_TYPES_REVERSE = {v: k for k, v in OPERATION_TYPES.items()}

# Define the timezone (GMT+3)
TZ_INFO = ZoneInfo("Etc/GMT-3") # Or "Europe/Moscow" etc. if appropriate

# --- Helper Functions ---

def _list_to_str(id_list: Optional[List[int]]) -> Optional[str]:
    """Converts a list of integers to a comma-separated string."""
    if id_list is None:
        return None
    if not id_list: # Handle empty list
        return ""
    return ",".join(map(str, sorted(list(set(id_list))))) # Ensure unique, sorted IDs

def _str_to_list(id_str: Optional[str]) -> List[int]:
    """Converts a comma-separated string to a list of integers."""
    if not id_str:
        return []
    try:
        # Filter out empty strings that might result from splitting " " or ",,"
        return [int(x) for x in id_str.split(',') if x.strip()]
    except (ValueError, TypeError):
        # Handle cases where the string might be corrupted or None
        return []

def _hash_password(password: str) -> str:
    """Hashes a password using SHA256."""
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def _get_current_datetime() -> str:
    """Returns the current datetime as an ISO 8601 string in GMT+3."""
    return datetime.datetime.now(TZ_INFO).isoformat()

# --- Database API Class ---

class DatabaseAPI:
    """
    API for interacting with the application's SQLite database.
    Handles data validation, permissions, and abstracts database operations.
    """

    def __init__(self, db_path: str = "app_database.db"):
        """
        Initializes the DatabaseAPI, connects to the SQLite database,
        and ensures tables are created.

        Args:
            db_path (str): The path to the SQLite database file.
        """
        self.db_path = db_path
        self._conn = None
        self._cursor = None
        try:
            self._conn = sqlite3.connect(db_path, check_same_thread=False) # Allow multithreading if needed later
            self._conn.row_factory = sqlite3.Row # Return rows as dictionary-like objects
            self._cursor = self._conn.cursor()
            self._cursor.execute("PRAGMA foreign_keys = ON;") # Enforce foreign keys if defined (though not explicitly here)
            self._create_tables()
            print(f"Database connection established to {db_path}")
        except sqlite3.Error as e:
            print(f"Database connection error: {e}")
            raise  # Re-raise the exception to signal failure

    def _create_tables(self):
        """Creates the database tables if they don't exist."""
        try:
            # Users Table
            self._cursor.execute("""
                CREATE TABLE IF NOT EXISTS Users (
                    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    admin INTEGER NOT NULL CHECK (admin IN (0, 1)),
                    login TEXT NOT NULL UNIQUE,
                    password TEXT NOT NULL,
                    friends TEXT NOT NULL, -- Comma-separated list of user_ids
                    description TEXT
                );
            """)

            # Spheres Table
            self._cursor.execute("""
                CREATE TABLE IF NOT EXISTS Spheres (
                    sphere_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    description TEXT,
                    user_id INTEGER NOT NULL,
                    user_read_ids TEXT NOT NULL, -- Comma-separated list of user_ids
                    user_edit_ids TEXT NOT NULL, -- Comma-separated list of user_ids
                    FOREIGN KEY (user_id) REFERENCES Users(user_id) ON DELETE CASCADE
                );
            """)
            # Add indexes for faster lookups involving user IDs
            self._cursor.execute("CREATE INDEX IF NOT EXISTS idx_sphere_user ON Spheres (user_id);")


            # Locations Table
            self._cursor.execute("""
                CREATE TABLE IF NOT EXISTS Locations (
                    location_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    description TEXT,
                    user_id INTEGER NOT NULL,
                    user_read_ids TEXT NOT NULL, -- Comma-separated list of user_ids
                    user_edit_ids TEXT NOT NULL, -- Comma-separated list of user_ids
                    FOREIGN KEY (user_id) REFERENCES Users(user_id) ON DELETE CASCADE
                );
            """)
            self._cursor.execute("CREATE INDEX IF NOT EXISTS idx_location_user ON Locations (user_id);")

            # Accounting Table
            self._cursor.execute("""
                CREATE TABLE IF NOT EXISTS Accounting (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, -- Simple auto-incrementing PK
                    accounting_id INTEGER NOT NULL, -- ID for grouping transfers
                    user_id INTEGER NOT NULL,
                    user_read_ids TEXT NOT NULL, -- Comma-separated list of user_ids
                    user_edit_ids TEXT NOT NULL, -- Comma-separated list of user_ids
                    operation_type INTEGER NOT NULL CHECK (operation_type IN (1, 2)), -- 1: Income, 2: Spend
                    is_transfer INTEGER NOT NULL CHECK (is_transfer IN (0, 1)),
                    sphere_id INTEGER, -- Nullable only for specific transfer types
                    location_id INTEGER NOT NULL, -- Nullable only for specific transfer types? No, requirement says always mandatory except specific transfer case
                    sum REAL NOT NULL,
                    description TEXT,
                    date TEXT NOT NULL, -- Store as ISO 8601 Text recommended for SQLite
                    FOREIGN KEY (user_id) REFERENCES Users(user_id) ON DELETE CASCADE,
                    FOREIGN KEY (sphere_id) REFERENCES Spheres(sphere_id) ON DELETE SET NULL, -- Allow deletion of sphere
                    FOREIGN KEY (location_id) REFERENCES Locations(location_id) ON DELETE SET NULL -- Allow deletion of location
                );
            """)
            # Add indexes
            self._cursor.execute("CREATE INDEX IF NOT EXISTS idx_accounting_user ON Accounting (user_id);")
            self._cursor.execute("CREATE INDEX IF NOT EXISTS idx_accounting_acc_id ON Accounting (accounting_id);")
            self._cursor.execute("CREATE INDEX IF NOT EXISTS idx_accounting_sphere ON Accounting (sphere_id);")
            self._cursor.execute("CREATE INDEX IF NOT EXISTS idx_accounting_location ON Accounting (location_id);")
            self._cursor.execute("CREATE INDEX IF NOT EXISTS idx_accounting_date ON Accounting (date);")


            self._conn.commit()
        except sqlite3.Error as e:
            print(f"Error creating tables: {e}")
            self._conn.rollback()
            raise

    def close(self):
        """Commits any pending changes and closes the database connection."""
        if self._conn:
            try:
                self._conn.commit()
                self._conn.close()
                print("Database connection closed.")
            except sqlite3.Error as e:
                print(f"Error closing database connection: {e}")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    # --- Permission Helpers ---

    def _get_user_info(self, user_id: int) -> Optional[sqlite3.Row]:
        """Fetches user information (admin flag, friends)."""
        if not isinstance(user_id, int):
            return None
        try:
            self._cursor.execute("SELECT user_id, admin, friends FROM Users WHERE user_id = ?", (user_id,))
            return self._cursor.fetchone()
        except sqlite3.Error as e:
            print(f"Error getting user info for {user_id}: {e}")
            return None

    def get_user_friends(self, user_id: int) -> List[int]:
        """Gets the list of friends for a given user."""
        user_info = self._get_user_info(user_id)
        if user_info:
            return _str_to_list(user_info['friends'])
        return []

    def _is_admin(self, user_id: int) -> bool:
        """Checks if a user is an administrator."""
        user_info = self._get_user_info(user_id)
        return user_info and user_info['admin'] == 1

    def _check_ownership_and_permissions(
        self,
        acting_user_id: int,
        resource: sqlite3.Row, # Row object for Sphere, Location, or Accounting record
        action: str = 'read' # 'read', 'edit', 'delete'
    ) -> bool:
        """
        Checks if the acting user has permission for the action on the resource.
        Handles admin override, ownership, and read/edit lists.
        """
        if not resource:
            return False # Resource doesn't exist

        # 1. Admin can do anything
        if self._is_admin(acting_user_id):
            return True

        # 2. Owner can do anything with their own record
        owner_id = resource['user_id']
        if acting_user_id == owner_id:
            return True

        # 3. Check permission lists based on action
        read_ids = _str_to_list(resource['user_read_ids'])
        edit_ids = _str_to_list(resource['user_edit_ids'])

        if action == 'read':
            return acting_user_id in read_ids or acting_user_id in edit_ids
        elif action == 'edit' or action == 'delete':
            return acting_user_id in edit_ids
        else:
            return False # Unknown action

    def _validate_friend_list(self, owner_id: int, potential_friend_ids: List[int]) -> bool:
        """Checks if all potential friends are actual friends of the owner."""
        if not potential_friend_ids:
            return True # Empty list is valid
        owner_friends = self.get_user_friends(owner_id)
        return all(friend_id in owner_friends for friend_id in potential_friend_ids)

    # --- User Management ---

    def add_user(self, acting_user_id: Optional[int], login: str, password: str, admin: bool = False, description: Optional[str] = None) -> Optional[int]:
        """
        Adds a new user. Only Admins or the system (acting_user_id=None) can add users.
        Returns the new user_id or None on failure.
        """
        # Permission Check: Only admin or system (None) can add users
        if acting_user_id is not None and not self._is_admin(acting_user_id):
            print(f"Permission Denied: User {acting_user_id} cannot add users.")
            return None

        if not login or not password:
             print("Error: Login and password cannot be empty.")
             return None

        hashed_password = _hash_password(password)
        sql = """
            INSERT INTO Users (admin, login, password, friends, description)
            VALUES (?, ?, ?, ?, ?)
        """
        try:
            self._cursor.execute(sql, (int(admin), login, hashed_password, "", description)) # Start with empty friends list
            self._conn.commit()
            new_user_id = self._cursor.lastrowid
            print(f"User '{login}' added with ID {new_user_id}.")
            return new_user_id
        except sqlite3.IntegrityError:
            print(f"Error: Login '{login}' already exists.")
            self._conn.rollback()
            return None
        except sqlite3.Error as e:
            print(f"Error adding user: {e}")
            self._conn.rollback()
            return None
    
    def get_all_users(self, acting_user_id: int) -> List[Dict[str, Any]]:
        """Gets a list of all users (ID, login). Only for admins."""
        if not self._is_admin(acting_user_id):
            print(f"Permission Denied: User {acting_user_id} cannot get all users.")
            return []
        try:
            self._cursor.execute("SELECT user_id, login, admin FROM Users ORDER BY login")
            users = self._cursor.fetchall()
            return [dict(user) for user in users]
        except sqlite3.Error as e:
            print(f"Error getting all users: {e}")
            return []

    def get_user_by_id(self, acting_user_id: int, target_user_id: int) -> Optional[Dict[str, Any]]:
        """Gets user details by ID. Anyone can get any user's basic info (excluding password)."""
        # Basic permission: Check if acting user exists (or could be relaxed depending on requirements)
        # if not self._get_user_info(acting_user_id):
        #     print(f"Permission Denied: Acting user {acting_user_id} not found.")
        #     return None
        # No specific permission needed beyond being logged in (implied by having acting_user_id)

        try:
            self._cursor.execute("SELECT user_id, admin, login, friends, description FROM Users WHERE user_id = ?", (target_user_id,))
            user_row = self._cursor.fetchone()
            if user_row:
                user_dict = dict(user_row)
                user_dict['friends'] = _str_to_list(user_dict['friends'])
                return user_dict
            else:
                print(f"User with ID {target_user_id} not found.")
                return None
        except sqlite3.Error as e:
            print(f"Error getting user {target_user_id}: {e}")
            return None

    def get_user_by_login(self, login: str) -> Optional[Dict[str, Any]]:
        """Gets user details by login (excluding password). Useful for login process."""
        try:
            self._cursor.execute("SELECT user_id, admin, login, password, friends, description FROM Users WHERE login = ?", (login,))
            user_row = self._cursor.fetchone()
            if user_row:
                user_dict = dict(user_row)
                user_dict['friends'] = _str_to_list(user_dict['friends'])
                # Return password hash only when fetching by login (for authentication)
                return user_dict
            else:
                print(f"User with login '{login}' not found.")
                return None
        except sqlite3.Error as e:
            print(f"Error getting user by login '{login}': {e}")
            return None

    def update_user(self, acting_user_id: int, target_user_id: int, updates: Dict[str, Any]) -> bool:
        """
        Updates user details. Only admin or the user themselves can update.
        Cannot change user_id or login. Admin status can only be changed by admin.
        Friends list can be updated by the user or admin.
        """
        target_user = self.get_user_by_id(acting_user_id, target_user_id) # Use get_user_by_id for initial fetch
        if not target_user:
            return False # User not found

        is_admin = self._is_admin(acting_user_id)
        is_self = acting_user_id == target_user_id

        # Permission Check
        if not (is_admin or is_self):
            print(f"Permission Denied: User {acting_user_id} cannot update user {target_user_id}.")
            return False

        allowed_fields = {'password', 'friends', 'description'}
        if is_admin:
            allowed_fields.add('admin') # Admin can change admin status

        update_clauses = []
        update_values = []

        for key, value in updates.items():
            if key not in allowed_fields:
                print(f"Warning: Field '{key}' cannot be updated or does not exist.")
                continue

            # Specific handling
            if key == 'password':
                if value: # Only update if a new password is provided
                    update_clauses.append("password = ?")
                    update_values.append(_hash_password(value))
                else:
                    print("Warning: Empty password ignored.")
            elif key == 'friends':
                if isinstance(value, list):
                     # Validate friend IDs exist? Maybe too complex for now. Assume IDs are valid user_ids.
                     # We could add a check here:
                     # existing_users = self._get_multiple_user_ids(value)
                     # if len(existing_users) != len(set(value)):
                     #     print(f"Error: One or more friend IDs in {value} do not exist.")
                     #     return False # Or just filter invalid ones? Let's filter for robustness.
                     # valid_friend_ids = [u['user_id'] for u in existing_users]
                     # We won't implement _get_multiple_user_ids for brevity now, assume valid user ids passed
                    update_clauses.append("friends = ?")
                    update_values.append(_list_to_str(value))
                else:
                    print("Warning: 'friends' update ignored, value must be a list.")
            elif key == 'admin':
                 if is_admin: # Only admin can change admin status
                    update_clauses.append("admin = ?")
                    update_values.append(int(bool(value)))
                 else:
                     print("Permission Denied: Only admins can change admin status.")
                     # Technically already covered by permission check, but good explicit message.
            elif key == 'description':
                update_clauses.append("description = ?")
                update_values.append(value)

        if not update_clauses:
            print("No valid fields provided for update.")
            return False

        sql = f"UPDATE Users SET {', '.join(update_clauses)} WHERE user_id = ?"
        update_values.append(target_user_id)

        try:
            self._cursor.execute(sql, tuple(update_values))
            self._conn.commit()
            if self._cursor.rowcount > 0:
                print(f"User {target_user_id} updated successfully.")
                return True
            else:
                # Should not happen if initial check passed, but good to have
                print(f"Error: User {target_user_id} update failed (maybe already deleted?).")
                return False
        except sqlite3.Error as e:
            print(f"Error updating user {target_user_id}: {e}")
            self._conn.rollback()
            return False

    def delete_user(self, acting_user_id: int, target_user_id: int) -> bool:
        """
        Deletes a user. Only Admin or the user themselves can delete.
        Note: Associated records in other tables might be deleted or set to NULL
              based on FOREIGN KEY constraints (ON DELETE CASCADE/SET NULL).
        """
        target_user = self.get_user_by_id(acting_user_id, target_user_id) # Use get_user_by_id for initial fetch
        if not target_user:
            return False

        is_admin = self._is_admin(acting_user_id)
        is_self = acting_user_id == target_user_id

        # Permission Check
        if not (is_admin or is_self):
            print(f"Permission Denied: User {acting_user_id} cannot delete user {target_user_id}.")
            return False

        # Consider implications: Deleting a user might orphan records or trigger cascades.
        # If cascade is not desired for some tables, handle cleanup manually before deleting user.

        try:
            # Also remove user from all friends lists
            self._cursor.execute("SELECT user_id, friends FROM Users WHERE friends LIKE ?", ('%' + str(target_user_id) + '%',))
            users_with_friend = self._cursor.fetchall()
            for user_row in users_with_friend:
                current_friends = _str_to_list(user_row['friends'])
                if target_user_id in current_friends:
                    current_friends.remove(target_user_id)
                    self._cursor.execute("UPDATE Users SET friends = ? WHERE user_id = ?",
                                         (_list_to_str(current_friends), user_row['user_id']))

            # Now delete the user
            self._cursor.execute("DELETE FROM Users WHERE user_id = ?", (target_user_id,))
            self._conn.commit()
            if self._cursor.rowcount > 0:
                print(f"User {target_user_id} deleted successfully.")
                return True
            else:
                print(f"Error: User {target_user_id} not found for deletion.")
                return False # User might have been deleted in another request
        except sqlite3.Error as e:
            print(f"Error deleting user {target_user_id}: {e}")
            self._conn.rollback()
            return False

    def add_friend(self, acting_user_id: int, friend_id: int) -> bool:
        """Adds friend_id to acting_user_id's friend list."""
        if acting_user_id == friend_id:
            print("Error: Cannot add self as friend.")
            return False

        # Check if both users exist
        user_info = self._get_user_info(acting_user_id)
        friend_info = self._get_user_info(friend_id)
        if not user_info or not friend_info:
            print(f"Error: User {acting_user_id} or {friend_id} not found.")
            return False

        current_friends = _str_to_list(user_info['friends'])
        if friend_id in current_friends:
            print(f"User {friend_id} is already a friend of {acting_user_id}.")
            return True # Already friends, consider success

        current_friends.append(friend_id)
        new_friends_str = _list_to_str(current_friends)

        try:
            self._cursor.execute("UPDATE Users SET friends = ? WHERE user_id = ?", (new_friends_str, acting_user_id))
            self._conn.commit()
            if self._cursor.rowcount > 0:
                print(f"User {friend_id} added as a friend to user {acting_user_id}.")
                return True
            else:
                 print(f"Error: Failed to update friends list for user {acting_user_id}.")
                 return False
        except sqlite3.Error as e:
            print(f"Error adding friend: {e}")
            self._conn.rollback()
            return False

    def remove_friend(self, acting_user_id: int, friend_id: int) -> bool:
        """Removes friend_id from acting_user_id's friend list."""
        user_info = self._get_user_info(acting_user_id)
        if not user_info:
            print(f"Error: User {acting_user_id} not found.")
            return False

        current_friends = _str_to_list(user_info['friends'])
        if friend_id not in current_friends:
            print(f"User {friend_id} is not a friend of {acting_user_id}.")
            return True # Not a friend, consider removal successful

        current_friends.remove(friend_id)
        new_friends_str = _list_to_str(current_friends)

        try:
            self._cursor.execute("UPDATE Users SET friends = ? WHERE user_id = ?", (new_friends_str, acting_user_id))
            self._conn.commit()
            if self._cursor.rowcount > 0:
                 print(f"User {friend_id} removed from friends list of user {acting_user_id}.")
                 return True
            else:
                 print(f"Error: Failed to update friends list for user {acting_user_id}.")
                 return False
        except sqlite3.Error as e:
            print(f"Error removing friend: {e}")
            self._conn.rollback()
            return False

    # --- Sphere Management ---

    def _get_sphere_raw(self, sphere_id: int) -> Optional[sqlite3.Row]:
        """Internal helper to fetch raw sphere data."""
        try:
            self._cursor.execute("SELECT * FROM Spheres WHERE sphere_id = ?", (sphere_id,))
            return self._cursor.fetchone()
        except sqlite3.Error as e:
            print(f"Error fetching sphere {sphere_id}: {e}")
            return None

    def add_sphere(self, acting_user_id: int, name: str, user_read_ids: List[int], user_edit_ids: List[int], description: Optional[str] = None) -> Optional[int]:
        """
        Adds a new sphere record.
        Owner (acting_user_id) can only add their friends to read/edit lists.
        """
        if not self._get_user_info(acting_user_id):
             print(f"Error: User {acting_user_id} not found.")
             return None
        if not name:
            print("Error: Sphere name cannot be empty.")
            return None

        # Validate that read/edit users are friends of the owner
        if not self._validate_friend_list(acting_user_id, user_read_ids):
            print(f"Error: Not all user_read_ids are friends of owner {acting_user_id}.")
            return None
        if not self._validate_friend_list(acting_user_id, user_edit_ids):
            print(f"Error: Not all user_edit_ids are friends of owner {acting_user_id}.")
            return None

        read_ids_str = _list_to_str(user_read_ids)
        edit_ids_str = _list_to_str(user_edit_ids)

        sql = """
            INSERT INTO Spheres (name, description, user_id, user_read_ids, user_edit_ids)
            VALUES (?, ?, ?, ?, ?)
        """
        try:
            self._cursor.execute(sql, (name, description, acting_user_id, read_ids_str, edit_ids_str))
            self._conn.commit()
            new_sphere_id = self._cursor.lastrowid
            print(f"Sphere '{name}' added with ID {new_sphere_id}.")
            return new_sphere_id
        except sqlite3.Error as e:
            print(f"Error adding sphere: {e}")
            self._conn.rollback()
            return None

    def get_sphere(self, acting_user_id: int, sphere_id: int) -> Optional[Dict[str, Any]]:
        """Gets sphere details if the user has read permission."""
        sphere_row = self._get_sphere_raw(sphere_id)
        if not sphere_row:
            print(f"Sphere {sphere_id} not found.")
            return None

        if not self._check_ownership_and_permissions(acting_user_id, sphere_row, 'read'):
            print(f"Permission Denied: User {acting_user_id} cannot read sphere {sphere_id}.")
            return None

        sphere_dict = dict(sphere_row)
        sphere_dict['user_read_ids'] = _str_to_list(sphere_dict['user_read_ids'])
        sphere_dict['user_edit_ids'] = _str_to_list(sphere_dict['user_edit_ids'])
        return sphere_dict

    def get_spheres_for_user(self, acting_user_id: int) -> List[Dict[str, Any]]:
        """Gets all spheres owned by or visible to the user."""
        if not self._get_user_info(acting_user_id):
             print(f"Error: User {acting_user_id} not found.")
             return []

        results = []
        try:
            # Optimization: Use LIKE checks which are faster than fetching all and filtering in Python
            # Need to handle different ways user ID can appear in the comma-separated list
            user_id_str = str(acting_user_id)
            user_id_clause = f"(user_id = ? OR user_read_ids = '{user_id_str}' OR user_read_ids LIKE '%,{user_id_str}' OR user_read_ids LIKE '{user_id_str},%' OR user_read_ids LIKE '%,{user_id_str},%' OR user_edit_ids = '{user_id_str}' OR user_edit_ids LIKE '%,{user_id_str}' OR user_edit_ids LIKE '{user_id_str},%' OR user_edit_ids LIKE '%,{user_id_str},%')"

            if self._is_admin(acting_user_id):
                 # Admin sees all spheres
                 self._cursor.execute("SELECT * FROM Spheres ORDER BY name")
            else:
                 # Regular user sees owned or shared
                 self._cursor.execute(f"SELECT * FROM Spheres WHERE {user_id_clause} ORDER BY name", (acting_user_id,))

            for row in self._cursor.fetchall():
                sphere_dict = dict(row)
                sphere_dict['user_read_ids'] = _str_to_list(sphere_dict['user_read_ids'])
                sphere_dict['user_edit_ids'] = _str_to_list(sphere_dict['user_edit_ids'])
                results.append(sphere_dict)
            return results
        except sqlite3.Error as e:
            print(f"Error getting spheres for user {acting_user_id}: {e}")
            return []


    def update_sphere(self, acting_user_id: int, sphere_id: int, updates: Dict[str, Any]) -> bool:
        """Updates sphere details if the user has edit permission."""
        sphere_row = self._get_sphere_raw(sphere_id)
        if not sphere_row:
            print(f"Sphere {sphere_id} not found.")
            return False

        if not self._check_ownership_and_permissions(acting_user_id, sphere_row, 'edit'):
            print(f"Permission Denied: User {acting_user_id} cannot edit sphere {sphere_id}.")
            return False

        allowed_fields = {'name', 'description', 'user_read_ids', 'user_edit_ids'}
        update_clauses = []
        update_values = []
        owner_id = sphere_row['user_id'] # Get owner ID for friend validation

        for key, value in updates.items():
            if key not in allowed_fields:
                print(f"Warning: Field '{key}' cannot be updated or does not exist for Spheres.")
                continue

            if key == 'name':
                 if not value:
                     print("Error: Sphere name cannot be empty.")
                     return False
                 update_clauses.append("name = ?")
                 update_values.append(value)
            elif key == 'description':
                 update_clauses.append("description = ?")
                 update_values.append(value)
            elif key == 'user_read_ids':
                if isinstance(value, list):
                    if not self._validate_friend_list(owner_id, value):
                        print(f"Error: Not all user_read_ids are friends of owner {owner_id}.")
                        return False
                    update_clauses.append("user_read_ids = ?")
                    update_values.append(_list_to_str(value))
                else:
                     print("Warning: 'user_read_ids' update ignored, value must be a list.")
            elif key == 'user_edit_ids':
                if isinstance(value, list):
                    if not self._validate_friend_list(owner_id, value):
                        print(f"Error: Not all user_edit_ids are friends of owner {owner_id}.")
                        return False
                    update_clauses.append("user_edit_ids = ?")
                    update_values.append(_list_to_str(value))
                else:
                    print("Warning: 'user_edit_ids' update ignored, value must be a list.")


        if not update_clauses:
            print("No valid fields provided for sphere update.")
            return False

        sql = f"UPDATE Spheres SET {', '.join(update_clauses)} WHERE sphere_id = ?"
        update_values.append(sphere_id)

        try:
            self._cursor.execute(sql, tuple(update_values))
            self._conn.commit()
            if self._cursor.rowcount > 0:
                print(f"Sphere {sphere_id} updated successfully.")
                return True
            else:
                print(f"Error: Sphere {sphere_id} update failed (maybe already deleted?).")
                return False
        except sqlite3.Error as e:
            print(f"Error updating sphere {sphere_id}: {e}")
            self._conn.rollback()
            return False

    def delete_sphere(self, acting_user_id: int, sphere_id: int) -> bool:
        """Deletes a sphere if the user has edit/delete permission."""
        sphere_row = self._get_sphere_raw(sphere_id)
        if not sphere_row:
            print(f"Sphere {sphere_id} not found.")
            return False # Or True if idempotent deletion is desired

        if not self._check_ownership_and_permissions(acting_user_id, sphere_row, 'delete'):
            print(f"Permission Denied: User {acting_user_id} cannot delete sphere {sphere_id}.")
            return False

        try:
            # Foreign key constraint ON DELETE SET NULL should handle Accounting references
            self._cursor.execute("DELETE FROM Spheres WHERE sphere_id = ?", (sphere_id,))
            self._conn.commit()
            if self._cursor.rowcount > 0:
                print(f"Sphere {sphere_id} deleted successfully.")
                return True
            else:
                print(f"Error: Sphere {sphere_id} not found for deletion.")
                return False
        except sqlite3.Error as e:
            print(f"Error deleting sphere {sphere_id}: {e}")
            self._conn.rollback()
            return False

    # --- Location Management (Similar to Sphere Management) ---

    def _get_location_raw(self, location_id: int) -> Optional[sqlite3.Row]:
        """Internal helper to fetch raw location data."""
        try:
            self._cursor.execute("SELECT * FROM Locations WHERE location_id = ?", (location_id,))
            return self._cursor.fetchone()
        except sqlite3.Error as e:
            print(f"Error fetching location {location_id}: {e}")
            return None

    def add_location(self, acting_user_id: int, name: str, user_read_ids: List[int], user_edit_ids: List[int], description: Optional[str] = None) -> Optional[int]:
        """
        Adds a new location record.
        Owner (acting_user_id) can only add their friends to read/edit lists.
        """
        if not self._get_user_info(acting_user_id):
             print(f"Error: User {acting_user_id} not found.")
             return None
        if not name:
            print("Error: Location name cannot be empty.")
            return None

        # Validate that read/edit users are friends of the owner
        if not self._validate_friend_list(acting_user_id, user_read_ids):
            print(f"Error: Not all user_read_ids are friends of owner {acting_user_id}.")
            return None
        if not self._validate_friend_list(acting_user_id, user_edit_ids):
            print(f"Error: Not all user_edit_ids are friends of owner {acting_user_id}.")
            return None

        read_ids_str = _list_to_str(user_read_ids)
        edit_ids_str = _list_to_str(user_edit_ids)

        sql = """
            INSERT INTO Locations (name, description, user_id, user_read_ids, user_edit_ids)
            VALUES (?, ?, ?, ?, ?)
        """
        try:
            self._cursor.execute(sql, (name, description, acting_user_id, read_ids_str, edit_ids_str))
            self._conn.commit()
            new_location_id = self._cursor.lastrowid
            print(f"Location '{name}' added with ID {new_location_id}.")
            return new_location_id
        except sqlite3.Error as e:
            print(f"Error adding location: {e}")
            self._conn.rollback()
            return None

    def get_location(self, acting_user_id: int, location_id: int) -> Optional[Dict[str, Any]]:
        """Gets location details if the user has read permission."""
        location_row = self._get_location_raw(location_id)
        if not location_row:
            print(f"Location {location_id} not found.")
            return None

        if not self._check_ownership_and_permissions(acting_user_id, location_row, 'read'):
            print(f"Permission Denied: User {acting_user_id} cannot read location {location_id}.")
            return None

        location_dict = dict(location_row)
        location_dict['user_read_ids'] = _str_to_list(location_dict['user_read_ids'])
        location_dict['user_edit_ids'] = _str_to_list(location_dict['user_edit_ids'])
        return location_dict

    def get_locations_for_user(self, acting_user_id: int) -> List[Dict[str, Any]]:
        """Gets all locations owned by or visible to the user."""
        if not self._get_user_info(acting_user_id):
             print(f"Error: User {acting_user_id} not found.")
             return []

        results = []
        try:
            # Use similar LIKE clauses as for spheres
            user_id_str = str(acting_user_id)
            user_id_clause = f"(user_id = ? OR user_read_ids = '{user_id_str}' OR user_read_ids LIKE '%,{user_id_str}' OR user_read_ids LIKE '{user_id_str},%' OR user_read_ids LIKE '%,{user_id_str},%' OR user_edit_ids = '{user_id_str}' OR user_edit_ids LIKE '%,{user_id_str}' OR user_edit_ids LIKE '{user_id_str},%' OR user_edit_ids LIKE '%,{user_id_str},%')"

            if self._is_admin(acting_user_id):
                self._cursor.execute("SELECT * FROM Locations ORDER BY name")
            else:
                self._cursor.execute(f"SELECT * FROM Locations WHERE {user_id_clause} ORDER BY name", (acting_user_id,))

            for row in self._cursor.fetchall():
                loc_dict = dict(row)
                loc_dict['user_read_ids'] = _str_to_list(loc_dict['user_read_ids'])
                loc_dict['user_edit_ids'] = _str_to_list(loc_dict['user_edit_ids'])
                results.append(loc_dict)
            return results
        except sqlite3.Error as e:
            print(f"Error getting locations for user {acting_user_id}: {e}")
            return []


    def update_location(self, acting_user_id: int, location_id: int, updates: Dict[str, Any]) -> bool:
        """Updates location details if the user has edit permission."""
        location_row = self._get_location_raw(location_id)
        if not location_row:
            print(f"Location {location_id} not found.")
            return False

        if not self._check_ownership_and_permissions(acting_user_id, location_row, 'edit'):
            print(f"Permission Denied: User {acting_user_id} cannot edit location {location_id}.")
            return False

        allowed_fields = {'name', 'description', 'user_read_ids', 'user_edit_ids'}
        update_clauses = []
        update_values = []
        owner_id = location_row['user_id'] # Get owner ID for friend validation

        for key, value in updates.items():
            if key not in allowed_fields:
                print(f"Warning: Field '{key}' cannot be updated or does not exist for Locations.")
                continue

            if key == 'name':
                 if not value:
                     print("Error: Location name cannot be empty.")
                     return False
                 update_clauses.append("name = ?")
                 update_values.append(value)
            elif key == 'description':
                 update_clauses.append("description = ?")
                 update_values.append(value)
            elif key == 'user_read_ids':
                 if isinstance(value, list):
                     if not self._validate_friend_list(owner_id, value):
                         print(f"Error: Not all user_read_ids are friends of owner {owner_id}.")
                         return False
                     update_clauses.append("user_read_ids = ?")
                     update_values.append(_list_to_str(value))
                 else:
                     print("Warning: 'user_read_ids' update ignored, value must be a list.")
            elif key == 'user_edit_ids':
                 if isinstance(value, list):
                     if not self._validate_friend_list(owner_id, value):
                         print(f"Error: Not all user_edit_ids are friends of owner {owner_id}.")
                         return False
                     update_clauses.append("user_edit_ids = ?")
                     update_values.append(_list_to_str(value))
                 else:
                     print("Warning: 'user_edit_ids' update ignored, value must be a list.")

        if not update_clauses:
            print("No valid fields provided for location update.")
            return False

        sql = f"UPDATE Locations SET {', '.join(update_clauses)} WHERE location_id = ?"
        update_values.append(location_id)

        try:
            self._cursor.execute(sql, tuple(update_values))
            self._conn.commit()
            if self._cursor.rowcount > 0:
                print(f"Location {location_id} updated successfully.")
                return True
            else:
                print(f"Error: Location {location_id} update failed (maybe already deleted?).")
                return False
        except sqlite3.Error as e:
            print(f"Error updating location {location_id}: {e}")
            self._conn.rollback()
            return False

    def delete_location(self, acting_user_id: int, location_id: int) -> bool:
        """Deletes a location if the user has edit/delete permission."""
        location_row = self._get_location_raw(location_id)
        if not location_row:
            print(f"Location {location_id} not found.")
            return False

        if not self._check_ownership_and_permissions(acting_user_id, location_row, 'delete'):
            print(f"Permission Denied: User {acting_user_id} cannot delete location {location_id}.")
            return False

        try:
            # Foreign key constraint ON DELETE SET NULL should handle Accounting references
            self._cursor.execute("DELETE FROM Locations WHERE location_id = ?", (location_id,))
            self._conn.commit()
            if self._cursor.rowcount > 0:
                print(f"Location {location_id} deleted successfully.")
                return True
            else:
                print(f"Error: Location {location_id} not found for deletion.")
                return False
        except sqlite3.Error as e:
            print(f"Error deleting location {location_id}: {e}")
            self._conn.rollback()
            return False

    # --- Accounting Management ---

    def _get_next_accounting_id(self) -> int:
        """Gets the next available accounting_id (simple MAX + 1 approach)."""
        try:
            self._cursor.execute("SELECT MAX(accounting_id) FROM Accounting")
            max_id = self._cursor.fetchone()[0]
            return (max_id or 0) + 1
        except sqlite3.Error as e:
            print(f"Error getting next accounting_id: {e}")
            raise # Propagate error, critical for record creation

    def _get_accounting_record_raw(self, internal_id: int) -> Optional[sqlite3.Row]:
         """Internal helper to fetch a single accounting record by its primary key."""
         try:
             self._cursor.execute("SELECT * FROM Accounting WHERE id = ?", (internal_id,))
             return self._cursor.fetchone()
         except sqlite3.Error as e:
             print(f"Error fetching accounting record by internal id {internal_id}: {e}")
             return None

    def _get_accounting_records_by_acc_id(self, accounting_id: int) -> List[sqlite3.Row]:
        """Internal helper to fetch all records sharing an accounting_id (for transfers)."""
        try:
            self._cursor.execute("SELECT * FROM Accounting WHERE accounting_id = ?", (accounting_id,))
            return self._cursor.fetchall()
        except sqlite3.Error as e:
            print(f"Error fetching accounting records by accounting_id {accounting_id}: {e}")
            return []

    def add_accounting_record(
        self,
        acting_user_id: int,
        operation_type_str: str, # "Income" or "Spend"
        sum_val: float,
        location_id: int,
        sphere_id: Optional[int] = None, # Mandatory for non-transfers
        is_transfer: bool = False,
        transfer_peer_location_id: Optional[int] = None, # Used only if is_transfer and location transfer
        transfer_peer_sphere_id: Optional[int] = None, # Used only if is_transfer and sphere transfer
        user_read_ids: Optional[List[int]] = None, # If None, defaults to owner only
        user_edit_ids: Optional[List[int]] = None, # If None, defaults to owner only
        description: Optional[str] = None,
        date: Optional[str] = None # ISO 8601 format string, defaults to now() if None
    ) -> Optional[int]:
        """
        Adds one (Income/Spend) or two (Transfer) records to the Accounting table.
        Handles validation, permissions, and transfer logic.
        Returns the accounting_id of the created record(s) or None on failure.
        """
        # --- Basic Validations ---
        if not self._get_user_info(acting_user_id):
             print(f"Error: User {acting_user_id} not found.")
             return None

        if operation_type_str not in OPERATION_TYPES:
            print(f"Error: Invalid operation_type '{operation_type_str}'. Must be 'Income' or 'Spend'.")
            return None
        op_type = OPERATION_TYPES[operation_type_str]

        if not isinstance(sum_val, (int, float)) or sum_val <= 0:
             print(f"Error: Sum must be a positive number, got {sum_val}.")
             return None

        # Date handling
        record_date = date if date else _get_current_datetime()
        # Basic validation of date format if provided? Could use try-except with datetime.fromisoformat

        # Permission list handling (default to empty = owner only)
        read_ids = user_read_ids if user_read_ids is not None else []
        edit_ids = user_edit_ids if user_edit_ids is not None else []

        # Validate friends
        if not self._validate_friend_list(acting_user_id, read_ids):
            print(f"Error: Not all user_read_ids are friends of owner {acting_user_id}.")
            return None
        if not self._validate_friend_list(acting_user_id, edit_ids):
            print(f"Error: Not all user_edit_ids are friends of owner {acting_user_id}.")
            return None

        read_ids_str = _list_to_str(read_ids)
        edit_ids_str = _list_to_str(edit_ids)

        # Check existence and access for sphere/location
        # Owner must have edit access to the source location/sphere
        source_location = self.get_location(acting_user_id, location_id)
        if not source_location:
             print(f"Error: Source Location {location_id} not found or user {acting_user_id} has no access.")
             return None
        if not self._check_ownership_and_permissions(acting_user_id, self._get_location_raw(location_id), 'edit'):
             print(f"Permission Denied: User {acting_user_id} cannot use Location {location_id} as source.")
             return None

        # If sphere_id is provided (mandatory for non-transfer or location-transfer)
        if sphere_id is not None:
             source_sphere = self.get_sphere(acting_user_id, sphere_id)
             if not source_sphere:
                 print(f"Error: Source Sphere {sphere_id} not found or user {acting_user_id} has no access.")
                 return None
             if not self._check_ownership_and_permissions(acting_user_id, self._get_sphere_raw(sphere_id), 'edit'):
                 print(f"Permission Denied: User {acting_user_id} cannot use Sphere {sphere_id} as source.")
                 return None


        # --- Transfer Logic ---
        if is_transfer:
            is_location_transfer = transfer_peer_location_id is not None
            is_sphere_transfer = transfer_peer_sphere_id is not None

            # Validate transfer parameters
            if not (is_location_transfer ^ is_sphere_transfer): # XOR: Exactly one must be true
                print("Error: For transfer, provide exactly one of 'transfer_peer_location_id' or 'transfer_peer_sphere_id'.")
                return None

            if is_location_transfer:
                if sphere_id is None:
                    print("Error: 'sphere_id' is required for transfers between locations.")
                    return None
                if location_id == transfer_peer_location_id:
                    print("Error: Source and destination location cannot be the same for transfer.")
                    return None
                # Check destination location
                dest_location = self.get_location(acting_user_id, transfer_peer_location_id)
                if not dest_location:
                    print(f"Error: Destination Location {transfer_peer_location_id} not found or user {acting_user_id} has no access.")
                    return None
                if not self._check_ownership_and_permissions(acting_user_id, self._get_location_raw(transfer_peer_location_id), 'edit'):
                     print(f"Permission Denied: User {acting_user_id} cannot use Location {transfer_peer_location_id} as destination.")
                     return None

                # Prepare records for location transfer
                acc_id = self._get_next_accounting_id()
                spend_record = (acc_id, acting_user_id, read_ids_str, edit_ids_str, OP_SPEND, 1, sphere_id, location_id, sum_val, description, record_date)
                income_record = (acc_id, acting_user_id, read_ids_str, edit_ids_str, OP_INCOME, 1, sphere_id, transfer_peer_location_id, sum_val, description, record_date)

            else: # is_sphere_transfer
                # Requirement: "In all other cases [non-transfer] they [sphere_id, location_id] are always non-empty"
                # Requirement: "This [transfer] is the only scenario where one of sphere_id or location_id may be empty."
                # This implies location_id MUST be provided for sphere transfers.
                if location_id is None: # Check explicitly based on interpretation
                     print("Error: 'location_id' is required for transfers between spheres.")
                     return None
                if sphere_id == transfer_peer_sphere_id:
                    print("Error: Source and destination sphere cannot be the same for transfer.")
                    return None
                # Check destination sphere
                dest_sphere = self.get_sphere(acting_user_id, transfer_peer_sphere_id)
                if not dest_sphere:
                     print(f"Error: Destination Sphere {transfer_peer_sphere_id} not found or user {acting_user_id} has no access.")
                     return None
                if not self._check_ownership_and_permissions(acting_user_id, self._get_sphere_raw(transfer_peer_sphere_id), 'edit'):
                      print(f"Permission Denied: User {acting_user_id} cannot use Sphere {transfer_peer_sphere_id} as destination.")
                      return None

                # Prepare records for sphere transfer
                acc_id = self._get_next_accounting_id()
                spend_record = (acc_id, acting_user_id, read_ids_str, edit_ids_str, OP_SPEND, 1, sphere_id, location_id, sum_val, description, record_date)
                income_record = (acc_id, acting_user_id, read_ids_str, edit_ids_str, OP_INCOME, 1, transfer_peer_sphere_id, location_id, sum_val, description, record_date)

            # Insert transfer records (Spend + Income) in a transaction
            sql_insert = """
                INSERT INTO Accounting (accounting_id, user_id, user_read_ids, user_edit_ids,
                                       operation_type, is_transfer, sphere_id, location_id,
                                       sum, description, date)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """
            try:
                self._cursor.execute(sql_insert, spend_record)
                self._cursor.execute(sql_insert, income_record)
                self._conn.commit()
                print(f"Transfer (ID: {acc_id}) recorded successfully between {'locations' if is_location_transfer else 'spheres'}.")
                return acc_id
            except sqlite3.Error as e:
                print(f"Error adding transfer record: {e}")
                self._conn.rollback()
                return None

        # --- Non-Transfer Logic ---
        else:
            if sphere_id is None or location_id is None:
                print("Error: 'sphere_id' and 'location_id' are required for non-transfer operations.")
                return None

            acc_id = self._get_next_accounting_id()
            sql = """
                INSERT INTO Accounting (accounting_id, user_id, user_read_ids, user_edit_ids,
                                       operation_type, is_transfer, sphere_id, location_id,
                                       sum, description, date)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """
            record_data = (acc_id, acting_user_id, read_ids_str, edit_ids_str, op_type, 0, sphere_id, location_id, sum_val, description, record_date)

            try:
                self._cursor.execute(sql, record_data)
                self._conn.commit()
                print(f"{operation_type_str} record (ID: {acc_id}) added successfully.")
                return acc_id
            except sqlite3.Error as e:
                print(f"Error adding accounting record: {e}")
                self._conn.rollback()
                return None

    def get_accounting_record(self, acting_user_id: int, internal_id: int) -> Optional[Dict[str, Any]]:
        """
        Gets a single accounting record by its internal primary key `id`,
        if the user has read permission.
        """
        record_row = self._get_accounting_record_raw(internal_id)
        if not record_row:
            print(f"Accounting record with internal id {internal_id} not found.")
            return None

        if not self._check_ownership_and_permissions(acting_user_id, record_row, 'read'):
            print(f"Permission Denied: User {acting_user_id} cannot read accounting record {internal_id}.")
            return None

        record_dict = dict(record_row)
        record_dict['user_read_ids'] = _str_to_list(record_dict['user_read_ids'])
        record_dict['user_edit_ids'] = _str_to_list(record_dict['user_edit_ids'])
        record_dict['operation_type'] = OPERATION_TYPES_REVERSE.get(record_dict['operation_type'], 'Unknown')
        record_dict['is_transfer'] = bool(record_dict['is_transfer'])
        return record_dict

    def get_accounting_records_for_user(self, acting_user_id: int, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """Gets accounting records visible to the user, ordered by date descending."""
        if not self._get_user_info(acting_user_id):
             print(f"Error: User {acting_user_id} not found.")
             return []

        results = []
        try:
            user_id_str = str(acting_user_id)
            user_id_clause = f"(user_id = ? OR user_read_ids = '{user_id_str}' OR user_read_ids LIKE '%,{user_id_str}' OR user_read_ids LIKE '{user_id_str},%' OR user_read_ids LIKE '%,{user_id_str},%' OR user_edit_ids = '{user_id_str}' OR user_edit_ids LIKE '%,{user_id_str}' OR user_edit_ids LIKE '{user_id_str},%' OR user_edit_ids LIKE '%,{user_id_str},%')"

            sql = f"""
                SELECT * FROM Accounting
                WHERE {user_id_clause if not self._is_admin(acting_user_id) else '1=1'}
                ORDER BY date DESC
                LIMIT ? OFFSET ?
            """
            params = []
            if not self._is_admin(acting_user_id):
                params.append(acting_user_id)
            params.extend([limit, offset])


            self._cursor.execute(sql, tuple(params))

            for row in self._cursor.fetchall():
                record_dict = dict(row)
                record_dict['user_read_ids'] = _str_to_list(record_dict['user_read_ids'])
                record_dict['user_edit_ids'] = _str_to_list(record_dict['user_edit_ids'])
                record_dict['operation_type'] = OPERATION_TYPES_REVERSE.get(record_dict['operation_type'], 'Unknown')
                record_dict['is_transfer'] = bool(record_dict['is_transfer'])
                results.append(record_dict)
            return results
        except sqlite3.Error as e:
            print(f"Error getting accounting records for user {acting_user_id}: {e}")
            return []

    def update_accounting_record(self, acting_user_id: int, internal_id: int, updates: Dict[str, Any]) -> bool:
        """
        Updates a *non-transfer* accounting record if the user has edit permission.
        Updating transfer records is complex and currently disallowed by this method.
        """
        record_row = self._get_accounting_record_raw(internal_id)
        if not record_row:
            print(f"Accounting record {internal_id} not found.")
            return False

        if record_row['is_transfer'] == 1:
            print("Error: Updating transfer records directly is not supported via this method. Delete and recreate if necessary.")
            return False

        if not self._check_ownership_and_permissions(acting_user_id, record_row, 'edit'):
            print(f"Permission Denied: User {acting_user_id} cannot edit accounting record {internal_id}.")
            return False

        allowed_fields = {'operation_type', 'sum', 'location_id', 'sphere_id',
                          'user_read_ids', 'user_edit_ids', 'description', 'date'}
        update_clauses = []
        update_values = []
        owner_id = record_row['user_id']

        for key, value in updates.items():
            if key not in allowed_fields:
                print(f"Warning: Field '{key}' cannot be updated or does not exist for Accounting.")
                continue

            if key == 'operation_type':
                if value in OPERATION_TYPES:
                    update_clauses.append("operation_type = ?")
                    update_values.append(OPERATION_TYPES[value])
                else:
                    print(f"Warning: Invalid operation_type '{value}' ignored.")
            elif key == 'sum':
                if isinstance(value, (int, float)) and value > 0:
                    update_clauses.append("sum = ?")
                    update_values.append(value)
                else:
                    print(f"Warning: Invalid sum value '{value}' ignored.")
            elif key == 'location_id':
                # Check if new location exists and user has access
                loc = self.get_location(acting_user_id, value)
                if loc and self._check_ownership_and_permissions(acting_user_id, self._get_location_raw(value), 'edit'):
                     update_clauses.append("location_id = ?")
                     update_values.append(value)
                else:
                     print(f"Warning: Invalid or inaccessible location_id '{value}' ignored.")
            elif key == 'sphere_id':
                 # Check if new sphere exists and user has access (allow None?)
                 # Non-transfer records require sphere_id, so setting to None isn't valid here.
                 if value is None:
                     print("Warning: Cannot set sphere_id to None for non-transfer record. Ignored.")
                     continue
                 sph = self.get_sphere(acting_user_id, value)
                 if sph and self._check_ownership_and_permissions(acting_user_id, self._get_sphere_raw(value), 'edit'):
                      update_clauses.append("sphere_id = ?")
                      update_values.append(value)
                 else:
                      print(f"Warning: Invalid or inaccessible sphere_id '{value}' ignored.")
            elif key == 'user_read_ids':
                 if isinstance(value, list):
                     if not self._validate_friend_list(owner_id, value):
                         print(f"Warning: Not all user_read_ids are friends of owner {owner_id}. Ignored.")
                     else:
                         update_clauses.append("user_read_ids = ?")
                         update_values.append(_list_to_str(value))
                 else:
                     print("Warning: 'user_read_ids' update ignored, value must be a list.")
            elif key == 'user_edit_ids':
                 if isinstance(value, list):
                     if not self._validate_friend_list(owner_id, value):
                         print(f"Warning: Not all user_edit_ids are friends of owner {owner_id}. Ignored.")
                     else:
                         update_clauses.append("user_edit_ids = ?")
                         update_values.append(_list_to_str(value))
                 else:
                     print("Warning: 'user_edit_ids' update ignored, value must be a list.")
            elif key == 'description':
                 update_clauses.append("description = ?")
                 update_values.append(value)
            elif key == 'date':
                 # Add validation if needed
                 update_clauses.append("date = ?")
                 update_values.append(value)

        if not update_clauses:
            print("No valid fields provided for accounting record update.")
            return False

        sql = f"UPDATE Accounting SET {', '.join(update_clauses)} WHERE id = ?"
        update_values.append(internal_id)

        try:
            self._cursor.execute(sql, tuple(update_values))
            self._conn.commit()
            if self._cursor.rowcount > 0:
                print(f"Accounting record {internal_id} updated successfully.")
                return True
            else:
                print(f"Error: Accounting record {internal_id} update failed.")
                return False
        except sqlite3.Error as e:
            print(f"Error updating accounting record {internal_id}: {e}")
            self._conn.rollback()
            return False

    def delete_accounting_record(self, acting_user_id: int, internal_id: Optional[int] = None, accounting_id: Optional[int] = None) -> bool:
        """
        Deletes accounting record(s) if the user has edit/delete permission.
        Provide EITHER internal_id (for single record) OR accounting_id (for transfer pair).
        """
        if not ((internal_id is not None) ^ (accounting_id is not None)):
             print("Error: Provide exactly one of internal_id or accounting_id for deletion.")
             return False

        target_records = []
        if internal_id is not None:
             record_row = self._get_accounting_record_raw(internal_id)
             if record_row:
                 target_records.append(record_row)
             else:
                  print(f"Accounting record with internal id {internal_id} not found.")
                  return False # Or True if idempotent deletion is desired
        else: # accounting_id is not None
             target_records = self._get_accounting_records_by_acc_id(accounting_id)
             if not target_records:
                 print(f"Accounting records with accounting_id {accounting_id} not found.")
                 return False # Or True

        # Check permissions for *all* records being deleted
        for record_row in target_records:
            if not self._check_ownership_and_permissions(acting_user_id, record_row, 'delete'):
                # Get the specific ID for the message
                rec_id = record_row['id']
                acc_id = record_row['accounting_id']
                print(f"Permission Denied: User {acting_user_id} cannot delete accounting record (id={rec_id}, accounting_id={acc_id}).")
                return False

        # Perform deletion
        try:
            if internal_id is not None:
                self._cursor.execute("DELETE FROM Accounting WHERE id = ?", (internal_id,))
            else: # accounting_id is not None
                self._cursor.execute("DELETE FROM Accounting WHERE accounting_id = ?", (accounting_id,))

            self._conn.commit()
            if self._cursor.rowcount > 0:
                 affected = self._cursor.rowcount
                 id_type = "internal id" if internal_id else "accounting_id"
                 id_val = internal_id if internal_id else accounting_id
                 print(f"Successfully deleted {affected} accounting record(s) with {id_type} {id_val}.")
                 return True
            else:
                 # Should not happen if initial check passed, but good practice
                 print("Error: No records found for deletion (maybe already deleted?).")
                 return False
        except sqlite3.Error as e:
            id_val = internal_id if internal_id else accounting_id
            print(f"Error deleting accounting record(s) for ID {id_val}: {e}")
            self._conn.rollback()
            return False



def create_test_sample(api: DatabaseAPI):
    """
    Заполняет базу данных тестовыми данными: админ, пользователь 'ivan',
    сферы, локации и операции для 'ivan'.
    Функция идемпотентна (по возможности) - не создает дубликаты пользователей,
    но может создать дубликаты сфер/локаций/записей, если запускать многократно
    без очистки БД и без доп. проверок.
    """
    print("--- Создание тестовых данных ---")

    # 1. Создание пользователей (если их нет)
    admin_id = None
    ivan_id = None

    if not api.get_user_by_login("admin"):
        admin_id = api.add_user(None, "admin", "adminpass", admin=True, description="Default Admin")
        if admin_id:
            print(f"Создан администратор 'admin' с ID: {admin_id}")
        else:
            print("Ошибка создания администратора 'admin'")
            return # Прекращаем, если админ не создался
    else:
        admin_user = api.get_user_by_login("admin")
        admin_id = admin_user['user_id']
        print("Администратор 'admin' уже существует.")

    if not api.get_user_by_login("ivan"):
        ivan_id = api.add_user(admin_id, "ivan", "ivanpass", admin=False, description="Тестовый пользователь Иван")
        if ivan_id:
            print(f"Создан пользователь 'ivan' с ID: {ivan_id}")
        else:
            print("Ошибка создания пользователя 'ivan'")
            return # Прекращаем, если иван не создался
    else:
        ivan_user = api.get_user_by_login("ivan")
        ivan_id = ivan_user['user_id']
        print("Пользователь 'ivan' уже существует.")

    if not ivan_id:
        print("Не удалось получить ID пользователя 'ivan'. Прекращение создания тестовых данных.")
        return

    # 2. Создание сфер для Ивана
    # Проверим, есть ли уже такие сферы у Ивана, чтобы не дублировать при перезапуске
    ivan_spheres = {s['name']: s['sphere_id'] for s in api.get_spheres_for_user(ivan_id)}

    s_food_id = ivan_spheres.get("Еда")
    if not s_food_id:
        s_food_id = api.add_sphere(ivan_id, "Еда", [], [], description="Расходы на продукты питания")
        print(f"Создана сфера 'Еда' для Ивана, ID: {s_food_id}")

    s_salary_id = ivan_spheres.get("Зарплата")
    if not s_salary_id:
        s_salary_id = api.add_sphere(ivan_id, "Зарплата", [], [], description="Поступления от работодателя")
        print(f"Создана сфера 'Зарплата' для Ивана, ID: {s_salary_id}")

    s_transport_id = ivan_spheres.get("Транспорт")
    if not s_transport_id:
        s_transport_id = api.add_sphere(ivan_id, "Транспорт", [], [], description="Расходы на проезд, бензин")
        print(f"Создана сфера 'Транспорт' для Ивана, ID: {s_transport_id}")

    s_gifts_id = ivan_spheres.get("Подарки")
    if not s_gifts_id:
        s_gifts_id = api.add_sphere(ivan_id, "Подарки", [], [])
        print(f"Создана сфера 'Подарки' для Ивана, ID: {s_gifts_id}")


    # 3. Создание локаций для Ивана
    ivan_locations = {l['name']: l['location_id'] for l in api.get_locations_for_user(ivan_id)}

    l_alfa_id = ivan_locations.get("Банк Альфа")
    if not l_alfa_id:
        l_alfa_id = api.add_location(ivan_id, "Банк Альфа", [], [], description="Основной счет")
        print(f"Создана локация 'Банк Альфа' для Ивана, ID: {l_alfa_id}")

    l_sber_id = ivan_locations.get("Банк Сбер")
    if not l_sber_id:
        l_sber_id = api.add_location(ivan_id, "Банк Сбер", [], [], description="Зарплатный счет")
        print(f"Создана локация 'Банк Сбер' для Ивана, ID: {l_sber_id}")

    l_wallet_id = ivan_locations.get("Кошелек")
    if not l_wallet_id:
        l_wallet_id = api.add_location(ivan_id, "Кошелек", [], [], description="Наличные")
        print(f"Создана локация 'Кошелек' для Ивана, ID: {l_wallet_id}")


    # Проверяем, что все ID получены
    if not all([s_food_id, s_salary_id, s_transport_id, s_gifts_id, l_alfa_id, l_sber_id, l_wallet_id]):
        print("Не удалось создать все необходимые сферы/локации. Прекращение создания записей.")
        return

    # 4. Создание записей в истории операций для Ивана
    print("Добавление записей в историю...")

    # Зарплата на Сбер
    api.add_accounting_record(
        acting_user_id=ivan_id, operation_type_str="Income", sum_val=50000.00,
        location_id=l_sber_id, sphere_id=s_salary_id, description="Аванс"
    )
    api.add_accounting_record(
        acting_user_id=ivan_id, operation_type_str="Income", sum_val=70000.00,
        location_id=l_sber_id, sphere_id=s_salary_id, description="Основная часть"
    )

    # Перевод со Сбера на Альфа
    api.add_accounting_record(
        acting_user_id=ivan_id, operation_type_str="Spend", sum_val=100000.00,
        location_id=l_sber_id, sphere_id=s_salary_id, # Сфера здесь формально нужна для API
        is_transfer=True, transfer_peer_location_id=l_alfa_id,
        description="Перевод на основной счет"
    )

    # Расходы с Альфа
    api.add_accounting_record(
        acting_user_id=ivan_id, operation_type_str="Spend", sum_val=15000.50,
        location_id=l_alfa_id, sphere_id=s_food_id, description="Продукты на неделю"
    )
    api.add_accounting_record(
        acting_user_id=ivan_id, operation_type_str="Spend", sum_val=3000.00,
        location_id=l_alfa_id, sphere_id=s_transport_id, description="Бензин"
    )
    api.add_accounting_record(
        acting_user_id=ivan_id, operation_type_str="Spend", sum_val=5000.00,
        location_id=l_alfa_id, sphere_id=s_gifts_id, description="Подарок другу"
    )


    # Перевод с Альфа в Кошелек (наличные)
    api.add_accounting_record(
        acting_user_id=ivan_id, operation_type_str="Spend", sum_val=10000.00,
        location_id=l_alfa_id, sphere_id=s_gifts_id, # Сфера не важна при переводе локаций
        is_transfer=True, transfer_peer_location_id=l_wallet_id,
        description="Снятие наличных"
    )

    # Расходы из Кошелька
    api.add_accounting_record(
        acting_user_id=ivan_id, operation_type_str="Spend", sum_val=500.00,
        location_id=l_wallet_id, sphere_id=s_food_id, description="Обед"
    )
    api.add_accounting_record(
        acting_user_id=ivan_id, operation_type_str="Spend", sum_val=150.00,
        location_id=l_wallet_id, sphere_id=s_transport_id, description="Метро"
    )

    # Перевод между сферами (например, часть денег из "Зарплаты" перенесли в "Подарки")
    # Происходит в рамках одного счета (например, Альфа)
    api.add_accounting_record(
        acting_user_id=ivan_id, operation_type_str="Spend", sum_val=2000.00,
        location_id=l_alfa_id, # На каком счете происходит
        sphere_id=s_salary_id, # Из какой сферы
        is_transfer=True, transfer_peer_sphere_id=s_gifts_id, # В какую сферу
        description="Отложил на подарок"
    )


    print("--- Создание тестовых данных завершено ---")


# --- Example Usage (Optional - for testing) ---
if __name__ == "__main__":
    DB_FILE = "test_app_db.sqlite"
    # Clean up previous test db if exists
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)

    # Use context manager for automatic connection closing
    with DatabaseAPI(DB_FILE) as api:
        print("\n--- Initializing DB and Adding Users ---")
        # System adds admin
        admin_id = api.add_user(None, "admin", "adminpass", admin=True)
        # Admin adds regular users
        user1_id = api.add_user(admin_id, "user1", "pass1", description="First user")
        user2_id = api.add_user(admin_id, "user2", "pass2")
        user3_id = api.add_user(admin_id, "user3", "pass3", description="Third user")

        # Non-admin cannot add user
        api.add_user(user1_id, "user4", "pass4")

        if not all([admin_id, user1_id, user2_id, user3_id]):
            print("Failed to create initial users. Exiting.")
            exit()

        print("\n--- Managing Friends ---")
        api.add_friend(user1_id, user2_id) # user1 adds user2
        api.add_friend(user1_id, user3_id) # user1 adds user3
        api.add_friend(user2_id, user1_id) # user2 adds user1 (mutual friendship)
        api.add_friend(user1_id, user1_id) # Cannot add self
        api.add_friend(user1_id, 9999) # Cannot add non-existent user

        user1_info = api.get_user_by_id(admin_id, user1_id)
        print(f"User 1 info: {user1_info}")

        api.remove_friend(user1_id, user3_id)
        user1_info_after_remove = api.get_user_by_id(admin_id, user1_id)
        print(f"User 1 info after removing user3: {user1_info_after_remove}")

        print("\n--- Managing Spheres ---")
        # user1 creates a sphere, shared read with user2 (friend)
        sphere1_id = api.add_sphere(user1_id, "Personal Finance", [user2_id], [], "My personal budget")
        # user1 creates another sphere, shared edit with user2 (friend)
        sphere2_id = api.add_sphere(user1_id, "Work Projects", [], [user2_id])
        # user1 tries to add user3 (not a friend anymore) -> Fails
        api.add_sphere(user1_id, "Invalid Share", [user3_id], [])
        # user2 creates a sphere
        sphere3_id = api.add_sphere(user2_id, "User 2 Sphere", [], [])

        if not all([sphere1_id, sphere2_id, sphere3_id]):
             print("Failed to create initial spheres. Exiting.")
             # exit() # Continue anyway to show other tests

        print("\n--- Sphere Permissions ---")
        print(f"User 1 gets sphere 1: {api.get_sphere(user1_id, sphere1_id)}")
        print(f"User 2 gets sphere 1 (read access): {api.get_sphere(user2_id, sphere1_id)}")
        print(f"User 3 gets sphere 1 (no access): {api.get_sphere(user3_id, sphere1_id)}")
        print(f"User 2 gets sphere 2 (edit access): {api.get_sphere(user2_id, sphere2_id)}")
        print(f"Admin gets sphere 1: {api.get_sphere(admin_id, sphere1_id)}")

        print("\n--- Updating Sphere ---")
        api.update_sphere(user1_id, sphere1_id, {"description": "Updated personal budget"})
        api.update_sphere(user2_id, sphere2_id, {"name": "Work Projects Q3"}) # User 2 has edit access
        api.update_sphere(user3_id, sphere1_id, {"name": "Attempted Hack"}) # User 3 has no access -> Fails
        api.update_sphere(user1_id, sphere1_id, {"user_read_ids": [user3_id]}) # Try adding non-friend -> Fails
        api.update_sphere(user1_id, sphere1_id, {"user_read_ids": []}) # Remove user2 read access

        print(f"User 1 Spheres: {api.get_spheres_for_user(user1_id)}")
        print(f"User 2 Spheres: {api.get_spheres_for_user(user2_id)}")
        print(f"Admin Spheres: {api.get_spheres_for_user(admin_id)}") # Should see all


        print("\n--- Managing Locations ---")
        loc1_id = api.add_location(user1_id, "Bank Account A", [user2_id], [user2_id]) # Shared R/W with user2
        loc2_id = api.add_location(user1_id, "Wallet", [], [])
        loc3_id = api.add_location(user2_id, "Bank Account B", [], [])

        if not all([loc1_id, loc2_id, loc3_id]):
             print("Failed to create initial locations. Exiting.")
             # exit()

        print(f"User 1 gets location 1: {api.get_location(user1_id, loc1_id)}")
        print(f"User 2 gets location 1 (R/W): {api.get_location(user2_id, loc1_id)}")
        api.update_location(user2_id, loc1_id, {"description": "User 2 updated description"})
        print(f"User 1 gets location 1 after update: {api.get_location(user1_id, loc1_id)}")

        print("\n--- Managing Accounting ---")
        # Simple Income/Spend
        rec1_acc_id = api.add_accounting_record(user1_id, "Income", 1000.0, loc1_id, sphere1_id, description="Salary")
        rec2_acc_id = api.add_accounting_record(user1_id, "Spend", 50.50, loc2_id, sphere1_id, description="Lunch")
        # User 2 adds record to shared location/sphere
        rec3_acc_id = api.add_accounting_record(user2_id, "Spend", 25.0, loc1_id, sphere2_id, description="Coffee") # User 2 owns sphere2, has access to loc1

        # Invalid adds
        api.add_accounting_record(user1_id, "InvalidType", 100, loc1_id, sphere1_id) # Bad type
        api.add_accounting_record(user1_id, "Income", 100, loc1_id, None) # Missing sphere
        api.add_accounting_record(user3_id, "Spend", 10, loc1_id, sphere1_id) # User 3 no access

        # Transfers
        # Location Transfer (within sphere1)
        transfer1_acc_id = api.add_accounting_record(user1_id, "Spend", 200.0, loc1_id, sphere_id=sphere1_id,
                                                     is_transfer=True, transfer_peer_location_id=loc2_id,
                                                     description="Transfer Bank->Wallet")
        # Sphere Transfer (within loc3 owned by user2)
        # User 2 must own sphere3, have edit on sphere2 (destination), and edit on loc3
        transfer2_acc_id = api.add_accounting_record(user2_id, "Income", 75.0, loc3_id, sphere_id=sphere3_id,
                                                     is_transfer=True, transfer_peer_sphere_id=sphere2_id,
                                                     description="Transfer Project Budget")

        # Invalid transfers
        api.add_accounting_record(user1_id, "Spend", 10, loc1_id, sphere_id=sphere1_id, is_transfer=True) # Missing peer
        api.add_accounting_record(user1_id, "Spend", 10, loc1_id, sphere_id=None, is_transfer=True, transfer_peer_location_id=loc2_id) # Missing sphere for loc transfer
        api.add_accounting_record(user1_id, "Spend", 10, loc1_id, sphere_id=sphere1_id, is_transfer=True, transfer_peer_location_id=loc1_id) # Same location

        print("\n--- Retrieving Accounting Records ---")
        print("User 1 Records:")
        for rec in api.get_accounting_records_for_user(user1_id):
            print(f"  {rec}")

        print("\nUser 2 Records:")
        for rec in api.get_accounting_records_for_user(user2_id):
             print(f"  {rec}")

        print("\nAdmin Records:")
        for rec in api.get_accounting_records_for_user(admin_id, limit=5):
             print(f"  {rec}")

        # Get specific record by internal ID (find one first)
        user1_recs = api.get_accounting_records_for_user(user1_id)
        if user1_recs:
             internal_id_to_get = user1_recs[0]['id'] # Get the ID of the first record
             print(f"\nGetting record by internal ID {internal_id_to_get}:")
             print(api.get_accounting_record(user1_id, internal_id_to_get))
             print(f"User 3 attempts to get record {internal_id_to_get}:")
             print(api.get_accounting_record(user3_id, internal_id_to_get)) # Should fail permission

        print("\n--- Updating Accounting Record ---")
        if rec2_acc_id: # Update the "Lunch" record (assuming it's not a transfer)
            lunch_record = next((r for r in user1_recs if r['accounting_id'] == rec2_acc_id), None)
            if lunch_record and not lunch_record['is_transfer']:
                 api.update_accounting_record(user1_id, lunch_record['id'], {"sum": 60.0, "description": "Expensive Lunch"})
                 print("Updated Lunch record:", api.get_accounting_record(user1_id, lunch_record['id']))
            else:
                 print("Could not find non-transfer lunch record to update.")

        # Attempt to update transfer record -> Fails
        transfer_records = api._get_accounting_records_by_acc_id(transfer1_acc_id)
        if transfer_records:
            api.update_accounting_record(user1_id, transfer_records[0]['id'], {"sum": 250.0})


        print("\n--- Deleting Records ---")
        # Delete non-transfer record by internal ID
        if rec3_acc_id:
            coffee_record = next((r for r in api.get_accounting_records_for_user(user2_id) if r['accounting_id'] == rec3_acc_id), None)
            if coffee_record:
                api.delete_accounting_record(user2_id, internal_id=coffee_record['id']) # User 2 deletes their own record

        # Delete transfer records by accounting_id
        if transfer1_acc_id:
            api.delete_accounting_record(user1_id, accounting_id=transfer1_acc_id) # User 1 deletes their transfer

        # Attempt invalid deletion
        if transfer2_acc_id:
             api.delete_accounting_record(user1_id, accounting_id=transfer2_acc_id) # User 1 tries to delete User 2's transfer -> Fails

        print("\nUser 1 Records After Deletes:")
        for rec in api.get_accounting_records_for_user(user1_id):
            print(f"  {rec}")

        # Delete sphere (should set sphere_id to NULL in Accounting)
        if sphere1_id:
             print(f"\nDeleting Sphere {sphere1_id}")
             api.delete_sphere(user1_id, sphere1_id)
             print("Remaining User 1 Records (Sphere ID check):")
             for rec in api.get_accounting_records_for_user(user1_id):
                  print(f"  {rec}") # Check if sphere_id is None where it was sphere1_id

        # Delete User
        print(f"\nDeleting User {user2_id}")
        api.delete_user(admin_id, user2_id)
        print(f"Attempting to get deleted user {user2_id}: {api.get_user_by_id(admin_id, user2_id)}")
        print("Admin Records After User 2 Deletion (ownership check):")
        for rec in api.get_accounting_records_for_user(admin_id):
             print(f"  {rec}") # Records owned by user 2 should be gone due to CASCADE

    print("\n--- Test Finished ---")
    # Connection is automatically closed by 'with' statement