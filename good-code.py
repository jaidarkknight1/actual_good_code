import logging
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Union
from dataclasses import dataclass
from abc import ABC, abstractmethod
import hashlib
import jwt
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

@dataclass
class Product:
    """Product data class with validation"""
    id: str
    name: str
    price: float
    stock: int
    category: str
    
    def __post_init__(self):
        if self.price < 0:
            raise ValueError("Price cannot be negative")
        if self.stock < 0:
            raise ValueError("Stock cannot be negative")

class InventoryException(Exception):
    """Custom exception for inventory-related errors"""
    pass

class PaymentException(Exception):
    """Custom exception for payment-related errors"""
    pass

class SecurityException(Exception):
    """Custom exception for security-related issues"""
    pass

class PaymentProcessor(ABC):
    """Abstract base class for payment processing"""
    
    @abstractmethod
    def process_payment(self, amount: float, currency: str) -> bool:
        pass
    
    @abstractmethod
    def refund_payment(self, transaction_id: str) -> bool:
        pass

class StripePaymentProcessor(PaymentProcessor):
    """Stripe payment processing implementation"""
    
    def __init__(self):
        self.api_key = os.getenv('STRIPE_API_KEY')
        if not self.api_key:
            raise SecurityException("Stripe API key not configured")
    
    def process_payment(self, amount: float, currency: str = 'USD') -> bool:
        try:
            logger.info(f"Processing payment of {amount} {currency}")
            # Simulate payment processing
            return True
        except Exception as e:
            logger.error(f"Payment processing failed: {str(e)}")
            raise PaymentException("Payment processing failed")
    
    def refund_payment(self, transaction_id: str) -> bool:
        try:
            logger.info(f"Processing refund for transaction {transaction_id}")
            # Simulate refund processing
            return True
        except Exception as e:
            logger.error(f"Refund processing failed: {str(e)}")
            raise PaymentException("Refund processing failed")

class InventoryManager:
    """Manages product inventory"""
    
    def __init__(self):
        self.products: Dict[str, Product] = {}
        self._load_initial_inventory()
    
    def _load_initial_inventory(self):
        """Load initial inventory data"""
        try:
            # Simulate loading from database
            sample_products = [
                Product("P1", "Laptop", 999.99, 10, "Electronics"),
                Product("P2", "Headphones", 99.99, 20, "Electronics"),
                Product("P3", "Mouse", 29.99, 30, "Electronics")
            ]
            for product in sample_products:
                self.products[product.id] = product
        except Exception as e:
            logger.error(f"Failed to load inventory: {str(e)}")
            raise InventoryException("Failed to load inventory")
    
    def add_product(self, product: Product):
        """Add a new product to inventory"""
        if product.id in self.products:
            raise InventoryException("Product ID already exists")
        self.products[product.id] = product
        logger.info(f"Added product: {product.name}")
    
    def remove_product(self, product_id: str):
        """Remove a product from inventory"""
        if product_id not in self.products:
            raise InventoryException("Product not found")
        del self.products[product_id]
        logger.info(f"Removed product: {product_id}")
    
    def update_stock(self, product_id: str, quantity: int):
        """Update product stock"""
        if product_id not in self.products:
            raise InventoryException("Product not found")
        if self.products[product_id].stock + quantity < 0:
            raise InventoryException("Insufficient stock")
        self.products[product_id].stock += quantity
        logger.info(f"Updated stock for {product_id}: {self.products[product_id].stock}")

class OrderManager:
    """Manages customer orders"""
    
    def __init__(self, inventory_manager: InventoryManager, payment_processor: PaymentProcessor):
        self.inventory_manager = inventory_manager
        self.payment_processor = payment_processor
        self.orders: Dict[str, Dict] = {}
    
    def create_order(self, user_id: str, items: List[Dict[str, Union[str, int]]]) -> str:
        """Create a new order"""
        try:
            # Validate order
            total_amount = 0
            for item in items:
                product_id = item['product_id']
                quantity = item['quantity']
                
                if product_id not in self.inventory_manager.products:
                    raise InventoryException(f"Product not found: {product_id}")
                
                product = self.inventory_manager.products[product_id]
                if product.stock < quantity:
                    raise InventoryException(f"Insufficient stock for {product.name}")
                
                total_amount += product.price * quantity
            
            # Process payment
            if not self.payment_processor.process_payment(total_amount):
                raise PaymentException("Payment failed")
            
            # Update inventory
            for item in items:
                self.inventory_manager.update_stock(
                    item['product_id'],
                    -item['quantity']
                )
            
            # Create order record
            order_id = hashlib.md5(f"{user_id}{datetime.now()}".encode()).hexdigest()
            self.orders[order_id] = {
                'user_id': user_id,
                'items': items,
                'total_amount': total_amount,
                'status': 'completed',
                'timestamp': datetime.now().isoformat()
            }
            
            logger.info(f"Created order: {order_id}")
            return order_id
            
        except Exception as e:
            logger.error(f"Order creation failed: {str(e)}")
            raise

class UserManager:
    """Manages user authentication and authorization"""
    
    def __init__(self):
        self.secret_key = os.getenv('JWT_SECRET_KEY')
        if not self.secret_key:
            raise SecurityException("JWT secret key not configured")
    
    def generate_token(self, user_id: str, expiry_hours: int = 24) -> str:
        """Generate JWT token for user"""
        try:
            payload = {
                'user_id': user_id,
                'exp': datetime.utcnow() + timedelta(hours=expiry_hours)
            }
            return jwt.encode(payload, self.secret_key, algorithm='HS256')
        except Exception as e:
            logger.error(f"Token generation failed: {str(e)}")
            raise SecurityException("Failed to generate token")
    
    def validate_token(self, token: str) -> Optional[str]:
        """Validate JWT token and return user_id"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=['HS256'])
            return payload['user_id']
        except jwt.ExpiredSignatureError:
            raise SecurityException("Token has expired")
        except jwt.InvalidTokenError:
            raise SecurityException("Invalid token")

def main():
    """Main function to demonstrate usage"""
    try:
        # Initialize components
        inventory_manager = InventoryManager()
        payment_processor = StripePaymentProcessor()
        order_manager = OrderManager(inventory_manager, payment_processor)
        user_manager = UserManager()
        
        # Simulate user authentication
        user_token = user_manager.generate_token("user123")
        user_id = user_manager.validate_token(user_token)
        
        # Create sample order
        order_items = [
            {"product_id": "P1", "quantity": 1},
            {"product_id": "P2", "quantity": 2}
        ]
        
        order_id = order_manager.create_order(user_id, order_items)
        logger.info(f"Order completed successfully: {order_id}")
        
    except Exception as e:
        logger.error(f"Application error: {str(e)}")
        raise

if __name__ == "__main__":
    main()
