import os
import sys

# Add the parent directory to sys.path so we can import app modules
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'backend'))

from app.db.session import engine
from sqlalchemy import text


def migrate():
    print("Starting migration...")
    with engine.begin() as conn:
        # Installations
        print("Checking installations table...")
        try:
            conn.execute(text("ALTER TABLE installations ADD COLUMN notify_on_findings BOOLEAN DEFAULT TRUE NOT NULL;"))
            print("Added notify_on_findings to installations.")
        except Exception as e:
            print(f"Skipping notify_on_findings: {e}")
            
        try:
            conn.execute(text("ALTER TABLE installations ADD COLUMN notify_email VARCHAR;"))
            print("Added notify_email to installations.")
        except Exception as e:
            print(f"Skipping notify_email: {e}")

        # Repositories
        print("Checking repositories table...")
        try:
            conn.execute(text("ALTER TABLE repositories ADD COLUMN scan_enabled BOOLEAN DEFAULT TRUE NOT NULL;"))
            print("Added scan_enabled to repositories.")
        except Exception as e:
            print(f"Skipping scan_enabled: {e}")
            
        try:
            conn.execute(text("ALTER TABLE repositories ADD COLUMN auto_patch_enabled BOOLEAN DEFAULT FALSE NOT NULL;"))
            print("Added auto_patch_enabled to repositories.")
        except Exception as e:
            print(f"Skipping auto_patch_enabled: {e}")
            
        try:
            # We must use VARCHAR for SQLAlchemy Enums if it's created dynamically without the enum type natively in postgres
            # The enum values are mapped to strings by SAEnum.
            conn.execute(text("ALTER TABLE repositories ADD COLUMN min_severity_to_report VARCHAR DEFAULT 'medium' NOT NULL;"))
            print("Added min_severity_to_report to repositories.")
        except Exception as e:
            print(f"Skipping min_severity_to_report: {e}")

    print("Migration complete.")

if __name__ == "__main__":
    migrate()
