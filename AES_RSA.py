from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
import base64
import os
import mimetypes
import struct

class UniversalFileEncryption:
    def __init__(self):
        """Initialize encryption components"""
        self.aes_key = None
        self.rsa_key = None
    
    def generate_rsa_keys(self, key_size=2048):
        """Generate RSA key pair"""
        self.rsa_key = RSA.generate(key_size)
        
        # Save keys to files
        with open("private_key.pem", "wb") as f:
            f.write(self.rsa_key.export_key())
        with open("public_key.pem", "wb") as f:
            f.write(self.rsa_key.publickey().export_key())
    
    def load_rsa_keys(self, private_key_path="private_key.pem"):
        """Load existing RSA keys"""
        with open(private_key_path, "rb") as f:
            self.rsa_key = RSA.import_key(f.read())

    def get_file_info(self, file_path):
        """Get file metadata including MIME type and original filename"""
        mime_type, _ = mimetypes.guess_type(file_path)
        if mime_type is None:
            mime_type = 'application/octet-stream'
        return {
            'mime_type': mime_type,
            'filename': os.path.basename(file_path)
        }

    def encrypt_file(self, input_file_path, output_file_path=None):
        """
        Encrypt any file type using AES-256 and RSA
        Returns the path to the encrypted file
        """
        try:
            # Generate output path if not provided
            if output_file_path is None:
                output_file_path = input_file_path + '.encrypted'

            # Get file metadata
            file_info = self.get_file_info(input_file_path)
            
            # Generate a random AES key
            self.aes_key = get_random_bytes(32)  # 256-bit key
            
            # Create AES cipher
            cipher_aes = AES.new(self.aes_key, AES.MODE_CBC)
            
            # Read the file
            with open(input_file_path, 'rb') as file:
                file_data = file.read()
            
            # Encrypt the file data
            padded_data = pad(file_data, AES.block_size)
            encrypted_data = cipher_aes.encrypt(padded_data)
            
            # Encrypt the AES key with RSA
            cipher_rsa = PKCS1_OAEP.new(self.rsa_key.publickey())
            encrypted_aes_key = cipher_rsa.encrypt(self.aes_key)
            
            # Prepare metadata
            metadata = f"{file_info['mime_type']}|{file_info['filename']}".encode()
            metadata_length = len(metadata)
            
            # Write everything to the output file
            with open(output_file_path, 'wb') as file:
                # Write format version
                file.write(b'ENCV1')
                
                # Write metadata length and metadata
                file.write(struct.pack('<Q', metadata_length))
                file.write(metadata)
                
                # Write the IV
                file.write(cipher_aes.iv)
                
                # Write the encrypted AES key length and key
                file.write(struct.pack('<Q', len(encrypted_aes_key)))
                file.write(encrypted_aes_key)
                
                # Write the encrypted data length and data
                file.write(struct.pack('<Q', len(encrypted_data)))
                file.write(encrypted_data)
            
            return output_file_path
            
        except Exception as e:
            raise Exception(f"Encryption error: {str(e)}")

    def decrypt_file(self, input_file_path, output_file_path=None):
        """
        Decrypt any encrypted file and restore its original format
        Returns the path to the decrypted file
        """
        try:
            with open(input_file_path, 'rb') as file:
                # Verify format
                if file.read(5) != b'ENCV1':
                    raise ValueError("Invalid file format")
                
                # Read metadata
                metadata_length = struct.unpack('<Q', file.read(8))[0]
                metadata = file.read(metadata_length).decode()
                mime_type, original_filename = metadata.split('|')
                
                # Generate output path if not provided
                if output_file_path is None:
                    output_dir = os.path.dirname(input_file_path)
                    output_file_path = os.path.join(output_dir, f"decrypted_{original_filename}")
                
                # Read the IV
                iv = file.read(16)
                
                # Read the encrypted AES key
                aes_key_length = struct.unpack('<Q', file.read(8))[0]
                encrypted_aes_key = file.read(aes_key_length)
                
                # Read the encrypted data
                data_length = struct.unpack('<Q', file.read(8))[0]
                encrypted_data = file.read(data_length)
                
                # Decrypt the AES key using RSA
                cipher_rsa = PKCS1_OAEP.new(self.rsa_key)
                aes_key = cipher_rsa.decrypt(encrypted_aes_key)
                
                # Create AES cipher
                cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
                
                # Decrypt and unpad the data
                decrypted_data = unpad(cipher_aes.decrypt(encrypted_data), AES.block_size)
                
                # Write the decrypted data
                with open(output_file_path, 'wb') as output_file:
                    output_file.write(decrypted_data)
                
                return output_file_path
                
        except Exception as e:
            raise Exception(f"Decryption error: {str(e)}")

def main():
    # Example usage for various file types
    encryptor = UniversalFileEncryption()
    
    # Generate new RSA keys (do this once)
    encryptor.generate_rsa_keys()
    
    # Example files to encrypt
    files_to_encrypt = [
        r'C:\Users\sanji\OneDrive\Documents\encrypt&decrypt\Asce Holidays_Varkala_.pdf'
    ]
    
    # Encrypt each file
    encrypted_files = []
    for file_path in files_to_encrypt:
        if os.path.exists(file_path):
            encrypted_file = encryptor.encrypt_file(file_path)
            encrypted_files.append(encrypted_file)
    
    # Decrypt each file
    for encrypted_file in encrypted_files:
        decrypted_file = encryptor.decrypt_file(encrypted_file)
        print(f"Decrypted: {decrypted_file}")

if __name__ == "__main__":
    main()
