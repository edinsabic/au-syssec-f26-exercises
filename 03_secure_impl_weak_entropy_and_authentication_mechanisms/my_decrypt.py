#!/usr/bin/env python3

<<<<<<< HEAD
import random
import sys
import time
from Crypto.Cipher import AES

def decrypt(input_file, output_file, time_range=86400):
    """
    Brute-force decrypt by trying time values within time_range seconds
    of the current time (or when ciphertext was created).
    time_range: search window in seconds (default: 24 hours)
    """
=======
from datetime import datetime
import random
import sys
import time
from tqdm import tqdm # install the tqdm package for a fancy progress bar
from Crypto.Cipher import AES


def decrypt(date, input_file, output_file):

    date = datetime.strptime(date, '%Y-%m-%d')
    t_start = int(date.timestamp())

>>>>>>> upstream/main
    with open(input_file, 'rb') as f_in:
        nonce = f_in.read(16)
        tag = f_in.read(16)
        ciphertext = f_in.read()

<<<<<<< HEAD
    current_time = int(time.time())
    
    # Try times from (now - time_range) to (now + time_range)
    for time_offset in range(-time_range, time_range + 1):
        seed_time = current_time + time_offset
        random.seed(seed_time)
        key = random.randbytes(16)
        
        try:
            aes = AES.new(key, AES.MODE_GCM, nonce=nonce)
            data = aes.decrypt_and_verify(ciphertext, tag)
            # If we get here, decryption succeeded!
            print(f"[+] Found correct key! Time seed: {seed_time}")
            with open(output_file, 'wb') as f_out:
                f_out.write(data)
            print(f"[+] Decrypted plaintext written to {output_file}")
            return True
        except ValueError:
            # Tag verification failed, try next time
            pass
    
    print("[-] Could not find correct key within time range")
    return False


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print(f'usage: {sys.argv[0]} <ciphertext-file> <output-file> [time-range-seconds]', file=sys.stderr)
        exit(1)
    
    time_range = int(sys.argv[3]) if len(sys.argv) > 3 else 86400
    decrypt(sys.argv[1], sys.argv[2], time_range)
=======
    #  for t in range(t_start, t_start + (60 * 60 * 24)):  # <- use this instead of the following line if you don't have tqdm
    for t in tqdm(range(t_start, t_start + (60 * 60 * 24))):
        random.seed(t)
        key = random.randbytes(16)
        try:
            aes = AES.new(key, AES.MODE_GCM, nonce=nonce)
            plaintext = aes.decrypt_and_verify(ciphertext, tag)
            break
        except:
            continue
    else:
        print('decryption failed')

    with open(output_file, 'wb') as f_out:
        f_out.write(plaintext)


if __name__ == '__main__':
    if len(sys.argv) != 4:
        print(f'usage: {sys.argv[0]} <date> <src-file> <dst-file>', file=sys.stderr)
        exit(1)
    decrypt(sys.argv[1], sys.argv[2], sys.argv[3])
>>>>>>> upstream/main
