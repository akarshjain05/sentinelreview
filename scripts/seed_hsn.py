import asyncio
import pandas as pd
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy import text
from app.core.config import settings

async def seed_hsn():
    print("Connecting to database...")
    engine = create_async_engine('postgresql+asyncpg://eboe:eboe_dev_pass@postgres:5432/eboe_dev')
    async_session = sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )
    
    print("Reading Excel file...")
    try:
        df = pd.read_excel('scripts/data/HSN_SAC.xlsx')
    except Exception as e:
        print(f"Failed to read excel file: {e}")
        return

    print(f"Loaded {len(df)} rows. Seeding database...")
    
    # Fill NaN with empty strings and ensure strings
    df['HSN_CD'] = df['HSN_CD'].fillna('').astype(str)
    df['HSN_Description'] = df['HSN_Description'].fillna('').astype(str)

    async with async_session() as session:
        print("Creating table if not exists...")
        await session.execute(text("""
            CREATE TABLE IF NOT EXISTS hsn_sac_codes (
                hsn_cd VARCHAR PRIMARY KEY,
                description VARCHAR NOT NULL
            );
        """))
        
        # Clear existing
        await session.execute(text("TRUNCATE TABLE hsn_sac_codes"))
        
        batch = []
        batch_size = 500
        count = 0
        
        for index, row in df.iterrows():
            code = row['HSN_CD'].strip()
            if not code:
                continue
            
            # Remove decimals if pandas converted it
            if code.endswith('.0'):
                code = code[:-2]

            desc = row['HSN_Description'].strip()
            
            # Simple sanitization
            desc = desc.replace("'", "''")
            
            batch.append(f"('{code}', '{desc}')")
            
            if len(batch) >= batch_size:
                values_str = ",\n".join(batch)
                query = f"""
                INSERT INTO hsn_sac_codes (hsn_cd, description) 
                VALUES {values_str}
                ON CONFLICT (hsn_cd) DO UPDATE SET description = EXCLUDED.description;
                """
                await session.execute(text(query))
                await session.commit()
                count += len(batch)
                print(f"Inserted {count} rows...")
                batch = []
                
        # Insert remaining
        if batch:
            values_str = ",\n".join(batch)
            query = f"""
            INSERT INTO hsn_sac_codes (hsn_cd, description) 
            VALUES {values_str}
            ON CONFLICT (hsn_cd) DO UPDATE SET description = EXCLUDED.description;
            """
            await session.execute(text(query))
            await session.commit()
            count += len(batch)
            print(f"Inserted {count} rows. Done!")
            
if __name__ == "__main__":
    asyncio.run(seed_hsn())
