import logging
import os
from typing import Optional, Dict, Any
from datetime import datetime
import secrets
import hashlib
from dotenv import load_dotenv
import boto3
from botocore.exceptions import ClientError
from dataclasses import dataclass
from abc import ABC, abstractmethod

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

@dataclass
class UserCredentials:
    """Data class for user credentials"""
    username: str
    email: str
    password_hash: str
    salt: str

class SecurityManager:
    """Handles security operations like hashing"""
    
    @staticmethod
    def generate_salt() -> str:
        """Generate a cryptographically secure salt"""
        return secrets.token_hex(16)

    @staticmethod
    def hash_password(password: str, salt: str) -> str:
        """
        Hash a password with salt using SHA-256
        
        Args:
            password: Plain text password
            salt: Cryptographic salt
            
        Returns:
            Hashed password
        """
        try:
            password_bytes = password.encode('utf-8')
            salt_bytes = salt.encode('utf-8')
            return hashlib.sha256(password_bytes + salt_bytes).hexdigest()
        except Exception as e:
            logger.error(f"Error hashing password: {str(e)}")
            raise

class DataStorage(ABC):
    """Abstract base class for data storage"""
    
    @abstractmethod
    def save_user(self, user: UserCredentials) -> bool:
        pass

    @abstractmethod
    def get_user(self, username: str) -> Optional[UserCredentials]:
        pass

class DynamoDBStorage(DataStorage):
    """DynamoDB implementation of data storage"""
    
    def __init__(self):
        self.table_name = os.getenv('DYNAMODB_TABLE')
        self.dynamodb = boto3.resource('dynamodb')
        self.table = self.dynamodb.Table(self.table_name)

    def save_user(self, user: UserCredentials) -> bool:
        """
        Save user to DynamoDB
        
        Args:
            user: UserCredentials object
            
        Returns:
            bool: Success status
        """
        try:
            self.table.put_item(
                Item={
                    'username': user.username,
                    'email': user.email,
                    'password_hash': user.password_hash,
                    'salt': user.salt,
                    'created_at': datetime.utcnow().isoformat()
                }
            )
            return True
        except ClientError as e:
            logger.error(f"Error saving user to DynamoDB: {str(e)}")
            return False

    def get_user(self, username: str) -> Optional[UserCredentials]:
        """
        Retrieve user from DynamoDB
        
        Args:
            username: Username to lookup
            
        Returns:
            Optional[UserCredentials]: User if found, None otherwise
        """
        try:
            response = self.table.get_item(
                Key={'username': username}
            )
            if 'Item' in response:
                item = response['Item']
                return UserCredentials(
                    username=item['username'],
                    email=item['email'],
                    password_hash=item['password_hash'],
                    salt=item['salt']
                )
            return None
        except ClientError as e:
            logger.error(f"Error retrieving user from DynamoDB: {str(e)}")
            return None

class UserManager:
    """Handles user operations"""
    
    def __init__(self, storage: DataStorage):
        self.storage = storage
        self.security = SecurityManager()

    def register_user(self, username: str, email: str, password: str) -> bool:
        """
        Register a new user
        
        Args:
            username: Username
            email: Email address
            password: Plain text password
            
        Returns:
            bool: Success status
        """
        try:
            # Input validation
            if not all([username, email, password]):
                raise ValueError("All fields are required")
            
            if len(password) < 8:
                raise ValueError("Password must be at least 8 characters")
            
            # Check if user exists
            if self.storage.get_user(username):
                raise ValueError("Username already exists")
            
            # Create new user
            salt = self.security.generate_salt()
            password_hash = self.security.hash_password(password, salt)
            
            user = UserCredentials(
                username=username,
                email=email,
                password_hash=password_hash,
                salt=salt
            )
            
            return self.storage.save_user(user)
            
        except Exception as e:
            logger.error(f"Error registering user: {str(e)}")
            return False

    def authenticate_user(self, username: str, password: str) -> bool:
        """
        Authenticate a user
        
        Args:
            username: Username
            password: Plain text password
            
        Returns:
            bool: Authentication success
        """
        try:
            user = self.storage.get_user(username)
            if not user:
                return False
                
            password_hash = self.security.hash_password(password, user.salt)
            return secrets.compare_digest(password_hash, user.password_hash)
            
        except Exception as e:
            logger.error(f"Error authenticating user: {str(e)}")
            return False

def main():
    """Main function"""
    try:
        # Initialize components
        storage = DynamoDBStorage()
        user_manager = UserManager(storage)
        
        # Example usage
        success = user_manager.register_user(
            username="testuser",
            email="test@example.com",
            password=[REDACTED:PASSWORD]"
        )
        
        if success:
            logger.info("User registered successfully")
            
            # Test authentication
            is_authenticated = user_manager.authenticate_user(
                "testuser",
                "SecurePass123!"
            )
            logger.info(f"Authentication successful: {is_authenticated}")
            
    except Exception as e:
        logger.error(f"Application error: {str(e)}")

if __name__ == "__main__":
    main()
