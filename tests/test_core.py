import unittest
from dotenv_webauthn_crypt.core import get_vault_key

class TestCore(unittest.TestCase):
    def test_vault_key_derivation(self):
        master_key = b"secret_master_key_32bytes!!!!!"
        env_path = ".env"
        key1 = get_vault_key(env_path, master_key)
        key2 = get_vault_key(env_path, master_key)
        
        self.assertEqual(key1, key2)
        self.assertEqual(len(key1), 32)

if __name__ == "__main__":
    unittest.main()
