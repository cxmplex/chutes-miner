"""
Concrete validator migration implementations.

Add new migration classes here; register them in validator_migrations/__init__.py.
"""

# The pre-seedless SyncServerKeysMigration was retired after its production
# completion gate. Its audit record remains in the database; no seedless code
# path imports the legacy implementation or requests its broad authority.
