# ============================================================
# servers/CloudStorage.py
# Simple in-memory cloud storage for ciphertext objects CT0
# ============================================================

class CloudStorage:
    def __init__(self):
        # Simulated cloud DB: file_id -> CT0
        self.storage = {}

    def upload(self, file_id: str, CT0: dict):
        """
        Save ciphertext CT0 in cloud using file_id reference.
        Equivalent to cloud.putObject(file_id, CT0)
        """
        self.storage[file_id] = CT0

    def download(self, file_id: str):
        """
        Retrieve ciphertext CT0 from cloud.
        Equivalent to cloud.getObject(file_id)
        """
        if file_id not in self.storage:
            raise KeyError("File ID not found in cloud storage")
        return self.storage[file_id]

    def list_files(self):
        """
        Return list of stored ciphertext file IDs.
        """
        return list(self.storage.keys())
