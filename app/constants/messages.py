from enum import Enum

class Message(str, Enum):
    INVALID_AUTHENTICATION = "Invalid authentication credentials"
    PROJECT_NOT_FOUND = "Project not found"
    USER_NOT_FOUND = "User not found"
    USER_ALREADY_EXISTS = "User already exists"
    PROJECT_ALREADY_EXISTS = "Project already exists"
    PROJECT_DELETED = "Project deleted"
    PROJECT_FILES_DELETED = "Project files deleted"
    FILE_UPLOAD_FAILED = "File upload failed"
    FILE_DELETION_FAILED = "File deletion failed"
    FILE_UPLOAD_SUCCESS = "File uploaded successfully"
    FILE_NOT_FOUND = "File not found"
    FILE_DOWNLOAD_FAILED = "File download failed"
    FILE_TOO_LARGE = "File is too large"
    INVALID_OPEN_PORTS_OPTS = "Invalid open ports options"
    INVALID_SERVICE_OPTS = "Invalid service options"
    EMPTY_FILE = "File is empty"