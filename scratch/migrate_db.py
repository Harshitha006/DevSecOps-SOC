import psycopg2
import os
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")

def migrate():
    try:
        conn = psycopg2.connect(DATABASE_URL)
        cur = conn.cursor()
        
        # Check if the column exists
        cur.execute("SELECT column_name FROM information_schema.columns WHERE table_name='events' AND column_name='files';")
        if not cur.fetchone():
            print("Adding 'files' column to 'events' table...")
            cur.execute("ALTER TABLE events ADD COLUMN files JSON;")
            conn.commit()
            print("Successfully added 'files' column.")
        else:
            print("'files' column already exists.")
            
        cur.close()
        conn.close()
    except Exception as e:
        print(f"Migration failed: {e}")

if __name__ == "__main__":
    migrate()
