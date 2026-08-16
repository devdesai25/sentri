from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import text
from sqlalchemy.exc import ProgrammingError, SQLAlchemyError
from app.db.session import engine, AsyncSessionLocal

from app.db.base import Base
from app.db.session import engine
from app.models.event import SSHEvent  # Import all models to ensure they're registered

async def table_exists(table_name: str) -> bool:
    """Check if a table exists in the database."""
    async with AsyncSessionLocal() as session:
        try:
            # Query the information schema to check if the table exists
            query = text(
                """
                SELECT EXISTS (
                    SELECT FROM information_schema.tables 
                    WHERE table_schema = 'public'
                    AND table_name = :table_name
                );
                """
            )
            result = await session.execute(query, {"table_name": table_name})
            return result.scalar()
        except SQLAlchemyError:
            return False

async def create_tables() -> None:
    """Create database tables if they don't exist yet."""
    # Get list of all table names from our models
    table_names = [table.name for table in Base.metadata.sorted_tables]
    
    # Check if we need to create tables
    needs_creation = False
    
    # Sample some key tables to check if they exist
    for table_name in ['ssh_events', 'command_executions', 'privilege_escalations', 'brute_force_attempts']:
        if table_name in table_names:
            exists = await table_exists(table_name)
            if not exists:
                needs_creation = True
                break
    
    # Only create tables if at least one of our core tables doesn't exist
    if needs_creation:
        try:
            async with engine.begin() as conn:
                # Create tables without using metadata.create_all to avoid index creation issues
                # First, get all create table statements
                for table in Base.metadata.sorted_tables:
                    # Check if this specific table exists
                    if not await table_exists(table.name):
                        # Create the table
                        await conn.run_sync(lambda conn: table.create(conn, checkfirst=True))
            
            # Log successful initialization
            print("Database tables initialized.")
        except Exception as e:
            print(f"Error creating tables: {e}")
            # Don't raise the exception - allow the app to continue even with DB errors
            # This makes the app more resilient to temporary DB issues
    else:
        print("Database tables already exist, skipping creation")
    
async def check_db_connected() -> bool:
    """Check if the database is connected."""
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False

async def check_db_connected() -> bool:
    """Check if the database is connected."""
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        return True
    except Exception as e:
        print(f"Database connection failed: {e}")
        return False


async def initialize_db() -> None:
    """Initialize the database with required tables and initial data."""
    # First, check if database is connected
    db_connected = await check_db_connected()
    if not db_connected:
        print("Cannot initialize database - connection failed")
        return

    # Create tables if they don't exist
    await create_tables()
    
    # Here you can add seeding logic if needed
    # async with AsyncSessionLocal() as session:
    #    await seed_initial_data(session)