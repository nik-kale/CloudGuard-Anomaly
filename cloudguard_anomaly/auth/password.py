"""
Password validation and complexity checking.

Enforces strong password policies for CloudGuard-Anomaly.
"""

import re
from typing import List, Optional


# Common weak passwords to reject
COMMON_PASSWORDS = {
    'password', 'password123', '123456', '12345678', 'qwerty', 'abc123',
    'monkey', '1234567', 'letmein', 'trustno1', 'dragon', 'baseball',
    'iloveyou', 'master', 'sunshine', 'ashley', 'bailey', 'passw0rd',
    'shadow', '123123', '654321', 'superman', 'qazwsx', 'michael',
    'football', 'admin', 'admin123', 'root', 'toor', 'changeme',
    'changeme123', 'welcome', 'welcome123', 'test', 'test123'
}


class PasswordValidationError(ValueError):
    """Raised when password validation fails."""
    pass


def validate_password_strength(password: str, username: Optional[str] = None) -> None:
    """
    Validate password meets complexity requirements.

    Requirements:
    - Minimum 12 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character
    - Not in common passwords list
    - Not containing username

    Args:
        password: Password to validate
        username: Optional username to check against

    Raises:
        PasswordValidationError: If password doesn't meet requirements
    """
    errors: List[str] = []

    # Check minimum length
    if len(password) < 12:
        errors.append("Password must be at least 12 characters long")

    # Check for uppercase letter
    if not re.search(r'[A-Z]', password):
        errors.append("Password must contain at least one uppercase letter")

    # Check for lowercase letter
    if not re.search(r'[a-z]', password):
        errors.append("Password must contain at least one lowercase letter")

    # Check for digit
    if not re.search(r'\d', password):
        errors.append("Password must contain at least one digit")

    # Check for special character
    if not re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', password):
        errors.append("Password must contain at least one special character")

    # Check against common passwords
    if password.lower() in COMMON_PASSWORDS:
        errors.append("Password is too common - please choose a stronger password")

    # Check if password contains username
    if username and username.lower() in password.lower():
        errors.append("Password cannot contain your username")

    # Maximum length check (prevent DoS)
    if len(password) > 128:
        errors.append("Password is too long (maximum 128 characters)")

    if errors:
        raise PasswordValidationError("; ".join(errors))


def validate_password_basic(password: str) -> None:
    """
    Basic password validation for backwards compatibility.

    Less strict than validate_password_strength():
    - Minimum 8 characters
    - At least one letter
    - At least one digit

    Args:
        password: Password to validate

    Raises:
        PasswordValidationError: If password doesn't meet basic requirements
    """
    errors: List[str] = []

    if len(password) < 8:
        errors.append("Password must be at least 8 characters long")

    if not re.search(r'[a-zA-Z]', password):
        errors.append("Password must contain at least one letter")

    if not re.search(r'\d', password):
        errors.append("Password must contain at least one digit")

    if len(password) > 128:
        errors.append("Password is too long (maximum 128 characters)")

    if errors:
        raise PasswordValidationError("; ".join(errors))


def check_password_strength_score(password: str) -> int:
    """
    Calculate password strength score (0-100).

    Args:
        password: Password to check

    Returns:
        Strength score from 0 (weak) to 100 (very strong)
    """
    score = 0

    # Length bonus
    if len(password) >= 8:
        score += 10
    if len(password) >= 12:
        score += 10
    if len(password) >= 16:
        score += 10
    if len(password) >= 20:
        score += 10

    # Character diversity
    if re.search(r'[a-z]', password):
        score += 10
    if re.search(r'[A-Z]', password):
        score += 10
    if re.search(r'\d', password):
        score += 10
    if re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', password):
        score += 15

    # Multiple character types
    char_types = 0
    if re.search(r'[a-z]', password):
        char_types += 1
    if re.search(r'[A-Z]', password):
        char_types += 1
    if re.search(r'\d', password):
        char_types += 1
    if re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', password):
        char_types += 1

    if char_types >= 3:
        score += 10
    if char_types == 4:
        score += 5

    # Penalize common passwords
    if password.lower() in COMMON_PASSWORDS:
        score = max(0, score - 50)

    # Penalize simple patterns
    if re.match(r'^(.)\1+$', password):  # All same character
        score = max(0, score - 30)
    if re.match(r'^(012|123|234|345|456|567|678|789)', password):  # Sequential
        score = max(0, score - 20)

    return min(100, score)
