#!/usr/bin/env python3
"""
Script to create an admin user with secure password generation.
"""
import asyncio
import getpass
import sys
import os
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.auth.enhanced_password import enhanced_password_manager
from core.database.connections import get_postgres_pool
from core.config.settings import get_settings
from core.utils.logging import get_logger
import asyncpg
import uuid

logger = get_logger(__name__)


async def create_admin_user():
    """Create an admin user with secure password."""
    settings = get_settings()
    
    print("MCP Security Guardian - Admin User Creation")
    print("==========================================\n")
    
    # Get user details
    email = input("Enter admin email address: ").strip()
    if not email or '@' not in email:
        print("Error: Invalid email address")
        return False
    
    full_name = input("Enter full name: ").strip()
    if not full_name:
        print("Error: Full name is required")
        return False
    
    organization_id = input("Enter organization ID (default: 'default'): ").strip() or "default"
    
    # Get password
    print("\nPassword Requirements:")
    print("- At least 12 characters")
    print("- Include uppercase and lowercase letters")
    print("- Include numbers and special characters")
    print("- Avoid common patterns\n")
    
    # Option to generate password
    generate = input("Generate secure password? (Y/n): ").strip().lower()
    
    if generate != 'n':
        password = enhanced_password_manager.generate_secure_password(16)
        print(f"\nGenerated password: {password}")
        print("IMPORTANT: Save this password securely. You won't see it again!")
        input("\nPress Enter when you've saved the password...")
    else:
        while True:
            password = getpass.getpass("Enter password: ")
            password_confirm = getpass.getpass("Confirm password: ")
            
            if password != password_confirm:
                print("Error: Passwords don't match. Try again.\n")
                continue
            
            # Validate password
            is_valid, errors = enhanced_password_manager.validate_password(password)
            if not is_valid:
                print("\nPassword validation failed:")
                for error in errors:
                    print(f"  - {error}")
                print()
                continue
            
            # Check password strength
            strength, suggestions = enhanced_password_manager.check_password_strength(password)
            print(f"\nPassword strength: {strength}")
            if suggestions:
                print("Suggestions:")
                for suggestion in suggestions:
                    print(f"  - {suggestion}")
            
            if strength in ['weak', 'fair']:
                proceed = input("\nPassword is not very strong. Continue anyway? (y/N): ").strip().lower()
                if proceed != 'y':
                    continue
            
            break
    
    # Hash password
    password_hash = enhanced_password_manager.hash_password(password)
    
    # Create user in database
    try:
        pool = await get_postgres_pool()
        
        # Check if user already exists
        existing = await pool.fetchval(
            "SELECT id FROM security.users WHERE email = $1",
            email
        )
        
        if existing:
            print(f"\nError: User with email {email} already exists")
            return False
        
        # Create user
        user_id = str(uuid.uuid4())
        await pool.execute("""
            INSERT INTO security.users (
                id, email, password_hash, full_name, 
                organization_id, role, is_active, created_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
        """, user_id, email, password_hash, full_name, 
            organization_id, 'admin', True)
        
        # Update password history
        enhanced_password_manager.update_password_history(user_id, password_hash)
        
        print(f"\n✅ Admin user created successfully!")
        print(f"   Email: {email}")
        print(f"   Role: admin")
        print(f"   Organization: {organization_id}")
        
        # Create API key
        create_api_key = input("\nCreate API key for this user? (Y/n): ").strip().lower()
        if create_api_key != 'n':
            api_key = await create_user_api_key(pool, user_id, email, organization_id)
            if api_key:
                print(f"\n✅ API Key created: {api_key}")
                print("IMPORTANT: Save this API key securely. You won't see it again!")
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to create admin user: {str(e)}")
        print(f"\nError creating user: {str(e)}")
        return False


async def create_user_api_key(pool: asyncpg.Pool, user_id: str, email: str, organization_id: str) -> str:
    """Create an API key for the user."""
    import secrets
    import hashlib
    
    # Generate API key
    api_key = f"mcp_{secrets.token_urlsafe(32)}"
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()
    
    # Store in database
    await pool.execute("""
        INSERT INTO security.api_keys (
            id, key_hash, name, user_id, organization_id,
            scopes, created_at, is_active
        ) VALUES ($1, $2, $3, $4, $5, $6, NOW(), true)
    """, str(uuid.uuid4()), key_hash, f"API Key for {email}",
        user_id, organization_id, ['read', 'write'])
    
    return api_key


async def main():
    """Main function."""
    try:
        success = await create_admin_user()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\nOperation cancelled")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        print(f"\nUnexpected error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())