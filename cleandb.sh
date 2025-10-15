#!/bin/sh

# Exit immediately if a command exits with a non-zero status.
set -euo pipefail

DB_USER=${DB_USER:-mac}
DB_NAME=${DB_NAME:-mytestdb}

echo "\n++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
echo "STARTING CLEANUP PROCESS FOR '$DB_NAME' DATABASE!!!..."
echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n"

# # Optional confirmation prompt
# read -p "⚠️ Are you sure you want to reset database '$DB_NAME'? (y/N): " confirm
# if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
#     echo "\n========================================================"
#     echo "❌ Cleanup process cancelled by user."
#     echo "========================================================\n"
#     exit 0
# fi

# Terminating all connections to the database.
echo "\n========================================================"
echo "Terminating all connections to the database: $DB_NAME..."
echo "========================================================\n"
psql -U "$DB_USER" -d postgres -c "
SELECT pg_terminate_backend(pg_stat_activity.pid)
FROM pg_stat_activity
WHERE pg_stat_activity.datname = '$DB_NAME'
  AND pid <> pg_backend_pid();"

# Dropping the database if it exists.
echo "\n========================================================"
echo "Dropping database: $DB_NAME (if it exists)..."
echo "========================================================\n"
psql -U "$DB_USER" -d postgres -c "DROP DATABASE IF EXISTS $DB_NAME;"

# Creating a new database with the specified owner.
echo "\n========================================================"
echo "Creating database: $DB_NAME for user: $DB_USER..."
echo "========================================================\n"
psql -U "$DB_USER" -d postgres -c "CREATE DATABASE $DB_NAME OWNER $DB_USER;"

# Removing old Alembic migration files (except __init__.py)
echo "\n========================================================"
echo "Removing old Alembic migration files..."
echo "========================================================\n"
find alembic/versions -type f -name "*.py" ! -name "__init__.py" -delete || true

# Cleaning the cache from alembic
echo "\n========================================================"
echo "Cleaning the cache from alembic..."
echo "========================================================\n"
find alembic -type d -name "__pycache__" -exec rm -rf {} +

# Cleaning the cache of the entire project
echo "\n========================================================"
echo "Cleaning the cache of the entire project..."
echo "========================================================\n"
find . -type d -name "__pycache__" -exec rm -rf {} +

# Stamping the database with the base revision
echo "\n========================================================"
echo "Stamping database with base revision..."
echo "========================================================\n"
alembic stamp base

# Autogenerating a new cleaned-up migration
echo "\n========================================================"
echo "Autogenerating cleaned-up migration..."
echo "========================================================\n"
alembic revision --autogenerate -m "DB Cleaned Up"

# Upgrading the database to the latest version
echo "\n========================================================"
echo "Upgrading database to the latest version..."
echo "========================================================\n"
alembic upgrade head

# Done
echo "\n++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
echo "✅✅ DATABASE '$DB_NAME' SUCCESSFULLY RESET AND MIGRATED!✅✅"
echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n"
