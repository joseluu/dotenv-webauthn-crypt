import os
import sys
from dotenv_webauthn_crypt import load_dotenv, init_credential, encrypt_file

def verify():
    print("--- 🔐 dotenv-webauthn-crypt Module Verification ---")
    
    # 1. Ensure a credential exists
    # Note: If this is the first time, it will prompt for Windows Hello.
    # If a credential already exists on your machine, you can comment this out.
    data_dir = os.path.join(os.environ.get("LOCALAPPDATA", ""), "dotenv-webauthn")
    credential_path = os.path.join(data_dir, "credential.bin")
    
    if not os.path.exists(credential_path):
        print("\n[Step 1] Initializing root credential...")
        try:
            init_credential(user_name="test_user")
        except Exception as e:
            print(f"❌ Initialization failed: {e}")
            print("Tip: Run this script in an interactive terminal to answer the Windows Hello prompt.")
            return

    # 2. Create a test .env file
    print("\n[Step 2] Creating test .env file...")
    test_env = ".env.verify"
    with open(test_env, "w") as f:
        f.write("DATABASE_URL=postgres://user:password@localhost:5432/db\n")
        f.write("API_KEY=12345-super-secret-key\n")
        f.write("DEBUG=True\n")

    # 3. Encrypt the file
    print(f"\n[Step 3] Encrypting {test_env}...")
    try:
        encrypt_file(test_env)
        print("✅ File encrypted successfully.")
    except Exception as e:
        print(f"❌ Encryption failed: {e}")
        return

    # 4. Clear environment variables to test loading
    if "DATABASE_URL" in os.environ: del os.environ["DATABASE_URL"]
    if "API_KEY" in os.environ: del os.environ["API_KEY"]

    # 5. Load and Decrypt
    print(f"\n[Step 4] Loading {test_env} via load_dotenv()...")
    print("(Windows Hello prompt will appear for decryption)")
    try:
        load_dotenv(test_env)
        
        # 6. Verify results
        db_url = os.environ.get("DATABASE_URL")
        api_key = os.environ.get("API_KEY")
        
        print("\n--- 🏁 Verification Results ---")
        print(f"DATABASE_URL: {db_url}")
        print(f"API_KEY:      {api_key}")
        
        if db_url == "postgres://user:password@localhost:5432/db" and api_key == "12345-super-secret-key":
            print("\n🎉 SUCCESS: All secrets decrypted correctly!")
        else:
            print("\n❌ FAILURE: Decrypted values do not match original plaintext.")
            
    except Exception as e:
        print(f"❌ Decryption/Loading failed: {e}")

if __name__ == "__main__":
    verify()
