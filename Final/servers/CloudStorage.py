# servers/CloudStorage.py
# ============================================================
# Simple in-memory cloud storage for ciphertext objects CT0
# ============================================================

class CloudStorage:
    def __init__(self):
        # Simulated cloud DB: file_id -> CT0
        self.storage = {}

    def upload(self, file_id: str, CT0: dict):
        self.storage[file_id] = CT0

    def download(self, file_id: str):
        if file_id not in self.storage:
            raise KeyError("File ID not found in cloud storage")
        return self.storage[file_id]

    def list_files(self):
        return list(self.storage.keys())
