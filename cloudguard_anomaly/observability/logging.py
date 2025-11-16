"""
Structured logging for CloudGuard-Anomaly.

Provides JSON-formatted logs with context and correlation IDs.
"""

import logging
import sys
import os
from typing import Dict, Any, Optional
from datetime import datetime
import json
from pythonjsonlogger import jsonlogger


class CloudGuardJsonFormatter(jsonlogger.JsonFormatter):
    """
    Custom JSON formatter with CloudGuard-specific fields.
    """

    def add_fields(self, log_record: Dict[str, Any], record: logging.LogRecord, message_dict: Dict[str, Any]):
        """Add custom fields to log record."""
        super(CloudGuardJsonFormatter, self).add_fields(log_record, record, message_dict)

        # Add timestamp
        if not log_record.get('timestamp'):
            log_record['timestamp'] = datetime.utcnow().isoformat() + 'Z'

        # Add log level
        if log_record.get('level'):
            log_record['level'] = log_record['level'].upper()
        else:
            log_record['level'] = record.levelname

        # Add logger name
        log_record['logger'] = record.name

        # Add service information
        log_record['service'] = 'cloudguard-anomaly'
        log_record['version'] = os.getenv('APP_VERSION', '3.0')

        # Add environment
        log_record['environment'] = os.getenv('ENVIRONMENT', 'development')

        # Add pod/host information (Kubernetes)
        if os.getenv('POD_NAME'):
            log_record['pod_name'] = os.getenv('POD_NAME')
        if os.getenv('POD_NAMESPACE'):
            log_record['pod_namespace'] = os.getenv('POD_NAMESPACE')
        if os.getenv('POD_IP'):
            log_record['pod_ip'] = os.getenv('POD_IP')

        # Add request context if available
        try:
            from flask import has_request_context, request
            if has_request_context():
                log_record['request_id'] = getattr(request, 'request_id', None)
                log_record['user_id'] = getattr(request, 'user_id', None)
                log_record['ip_address'] = request.remote_addr
                log_record['method'] = request.method
                log_record['path'] = request.path
        except (ImportError, RuntimeError):
            pass


def setup_logging(
    log_level: str = None,
    log_format: str = None,
    log_file: Optional[str] = None
):
    """
    Set up structured logging for CloudGuard-Anomaly.

    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_format: Log format ('json' or 'text')
        log_file: Optional file path for file logging
    """
    # Get configuration from environment or defaults
    log_level = log_level or os.getenv('LOG_LEVEL', 'INFO')
    log_format = log_format or os.getenv('LOG_FORMAT', 'json')

    # Convert log level string to logging constant
    level = getattr(logging, log_level.upper(), logging.INFO)

    # Create root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Remove existing handlers
    root_logger.handlers = []

    # Configure formatter
    if log_format == 'json':
        formatter = CloudGuardJsonFormatter(
            '%(timestamp)s %(level)s %(name)s %(message)s'
        )
    else:
        # Text format for development
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    # File handler (optional)
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)

    # Suppress noisy loggers
    logging.getLogger('werkzeug').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('boto3').setLevel(logging.WARNING)
    logging.getLogger('botocore').setLevel(logging.WARNING)

    root_logger.info(
        "Logging configured",
        extra={
            'log_level': log_level,
            'log_format': log_format,
            'log_file': log_file
        }
    )


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance with the specified name.

    Args:
        name: Logger name (typically __name__)

    Returns:
        Configured logger instance
    """
    return logging.getLogger(name)


class ContextLogger:
    """
    Logger wrapper that adds context to all log messages.

    Example:
        logger = ContextLogger(__name__, user_id='123', scan_id='abc')
        logger.info('Scan started')  # Includes user_id and scan_id in log
    """

    def __init__(self, name: str, **context):
        """
        Initialize context logger.

        Args:
            name: Logger name
            **context: Context fields to add to all log messages
        """
        self.logger = logging.getLogger(name)
        self.context = context

    def _log(self, level: int, msg: str, *args, **kwargs):
        """Internal logging method that adds context."""
        extra = kwargs.get('extra', {})
        extra.update(self.context)
        kwargs['extra'] = extra
        self.logger.log(level, msg, *args, **kwargs)

    def debug(self, msg: str, *args, **kwargs):
        """Log debug message with context."""
        self._log(logging.DEBUG, msg, *args, **kwargs)

    def info(self, msg: str, *args, **kwargs):
        """Log info message with context."""
        self._log(logging.INFO, msg, *args, **kwargs)

    def warning(self, msg: str, *args, **kwargs):
        """Log warning message with context."""
        self._log(logging.WARNING, msg, *args, **kwargs)

    def error(self, msg: str, *args, **kwargs):
        """Log error message with context."""
        self._log(logging.ERROR, msg, *args, **kwargs)

    def critical(self, msg: str, *args, **kwargs):
        """Log critical message with context."""
        self._log(logging.CRITICAL, msg, *args, **kwargs)

    def exception(self, msg: str, *args, **kwargs):
        """Log exception with context."""
        kwargs['exc_info'] = True
        self._log(logging.ERROR, msg, *args, **kwargs)
