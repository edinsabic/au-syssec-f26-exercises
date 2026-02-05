import string
import secrets
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES


class PPMImage:
    """Wrapper around a image in the PPM format.

    Format specification: http://netpbm.sourceforge.net/doc/ppm.html
    """

    def __init__(self, width, height, data, comments=None):
        """Construct an image from given dimension and raw data, and optionally comments."""
        self.width = width
        self.height = height
        if len(data) < width * height * 3:
            raise ValueError('expected at least {width * height * 3} bytes, got {len(data)} bytes')
        self.data = bytearray(data)
        if comments is None:
            self.comments = []
        else:
            self.comments = comments[:]

    def copy(self):
        """Make a copy of this object."""
        return PPMImage(self.width, self.height, self.data[:], self.comments[:])

    def __eq__(self, other):
        """Check if two objects are equal.

        NB: This is invoked whenever the `==` operator is used.
        """
        eq = True
        eq &= self.width == other.width
        eq &= self.height == other.height
        eq &= self.data == other.data
        eq &= self.comments == other.comments
        return eq

    def __repr__(self):
        """Make a human-readable description of the image."""
        return f'<PPMImage: width={self.width}, height={self.height}, comments={self.comments}, data_size={len(self.data)}>'

    def encrypt(self, key, mode):
        """Use AES to encrypt the image data in-place.

        The self.data is replaced with the ciphertext.  Additional data is
        stored in comment fields:
        - 'X-mode: <mode of operation used>
        - 'X-iv: <iv if CBC mode is used>
        - 'X-nonce: <nonce if CTR or GCM mode is used>
        - 'X-tag: <authentication tag if GCM mode is used>

        Parameters
        ----------
        key : bytes-like object of size 16
              key to be used for encryption
        mode : string, one of 'ecb', 'cbc', 'ctr', 'gcm'
              mode of operation
        """
        if mode.lower() == 'ecb':
            # 1. create an AES object in ECB mode
            aes = AES.new(key, AES.MODE_ECB)
            # 2. pad the plaintext to a multiple of 16 bytes
            padded_plaintext = pad(self.data, 16)
            # 3. encrypt the padded plaintext
            ciphertext = aes.encrypt(padded_plaintext)
            # replace the image data with the ciphertext
            self.data = bytearray(ciphertext)
            # add a comment that we use ECB mode
            self.comments.append(b'X-mode: ecb')
        elif mode.lower() == 'cbc':
            # --------- solution --------
            # 1. generate a random IV of 16 bytes
            iv = secrets.token_bytes(16)
            # 2. create an AES object in CBC mode with the IV
            aes = AES.new(key, AES.MODE_CBC, iv)
            # 3. pad the plaintext to a multiple of 16 bytes
            padded_plaintext = pad(self.data, 16)
            # 4. encrypt the padded plaintext
            ciphertext = aes.encrypt(padded_plaintext)
            # --------- solution end --------

            # replace the image data with the ciphertext
            self.data = bytearray(ciphertext)
            # add a comment that we use CBC mode
            self.comments.append(b'X-mode: cbc')
            # store the IV in a comment
            self.comments.append(f'X-iv: {iv.hex()}'.encode())
        elif mode.lower() == 'ctr':
            # -------- solution --------
            # 1. generate a random nonce of 8 bytes
            nonce = secrets.token_bytes(8)
            # 2. create an AES object in CTR mode with the nonce
            aes = AES.new(key, AES.MODE_CTR, nonce=nonce)
            # 3. encrypt the plaintext
            ciphertext = aes.encrypt(self.data)
            # --------- solution end --------
            
            # replace the image data with the ciphertext
            self.data = bytearray(ciphertext)
            # add a comment that we use CTR mode
            self.comments.append(b'X-mode: ctr')
            # store the nonce in a comment
            self.comments.append(f'X-nonce: {nonce.hex()}'.encode())
        elif mode.lower() == 'gcm':
            # ------------ solution --------------
            # 1. create a random nonce
            nonce = secrets.token_bytes(16)
            # 2. create an AES object in GCM mode and pass the nonce
            aes = AES.new(key, AES.MODE_GCM, nonce=nonce)
            # 3. encrypt and authenticate the plaintext
            ciphertext, tag = aes.encrypt_and_digest(self.data)
            # --------- end solution --------------

            # replace the image data with the ciphertext
            self.data = bytearray(ciphertext)
            # add a comment that we use GCM mode
            self.comments.append(b'X-mode: gcm')
            # store the authentication tag in a comment
            self.comments.append(f'X-tag: {tag.hex()}'.encode())
            # store the nonce in a comment
            self.comments.append(f'X-nonce: {nonce.hex()}'.encode())
        else:
            raise NotImplementedError(f'unknown mode of operation {mode}')

    def decrypt(self, key):
        """Use AES to decrypt the encrypted image data in-place.

        Required additional data is read from the comments:
        - 'X-mode: <mode of operation used>
        - 'X-iv: <iv if CBC mode is used>
        - 'X-nonce: <nonce if CTR or GCM mode is used>
        - 'X-tag: <authentication tag if GCM mode is used>

        Then self.data is replaced with the plaintext.

        Parameters
        ----------
        key : bytes-like object of size 16
              key to be used for encryption
        """

        # Some helper functions you can ignore

        def find_property_in_comments(name):
            """Find the comment starting with 'X-name:'."""
            comment = next((c for c in self.comments if c.startswith(f'X-{name}:'.encode())), None)
            if comment is None:
                raise ValueError(f"not comment starting with 'X-{name}:' found")
            return comment.decode().removeprefix(f'X-{name}:').strip()

        def cleanup_comments():
            """Remove all the special comments we used to store additional data in."""
            prefixes = [b'X-mode', b'X-iv', b'X-nonce', b'X-tag']
            self.comments = list(filter(lambda c: not any(c.startswith(prefix) for prefix in prefixes), self.comments))

        # Read the mode of operation from the comments
        mode = find_property_in_comments('mode')

        if mode.lower() == 'ecb':
            # 1. create an AES object in ECB mode
            aes = AES.new(key, AES.MODE_ECB)
            # 2. decrypt the ciphertext
            padded_plaintext = aes.decrypt(self.data)
            # 3. remove the padding to obtain the original plaintext
            plaintext = unpad(padded_plaintext, 16)
            # replace the image data with the plaintext
            self.data = bytearray(plaintext)
            # remove the comments where we stored the additional data
            cleanup_comments()
        elif mode.lower() == 'cbc':
            # Read the used IV from the comments
            iv = bytes.fromhex(find_property_in_comments('iv'))
            
            # --------- solution --------
            # 1. create an AES object in CBC mode with the given IV
            aes = AES.new(key, AES.MODE_CBC, iv=iv)
            # 2. decrypt the ciphertext
            padded_plaintext = aes.decrypt(self.data)
            # 3. remove the padding to obtain the original plaintext
            plaintext = unpad(padded_plaintext, 16)
            # ----- end solution --------

            # replace the image data with the plaintext
            self.data = bytearray(plaintext)
            # remove the comments where we stored the additional data
            cleanup_comments()
        elif mode.lower() == 'ctr':
            # Read the used nonce from the comments
            nonce = bytes.fromhex(find_property_in_comments('nonce'))
            
            # --------- solution --------
            # 1. create an AES object in CTR mode with the given nonce
            aes = AES.new(key, AES.MODE_CTR, nonce=nonce)
            # 2. decrypt the ciphertext
            plaintext = aes.decrypt(self.data)
            # --------- solution end --------

            # replace the image data with the plaintext
            self.data = bytearray(plaintext)
            # remove the comments where we stored the additional data
            cleanup_comments()
        elif mode.lower() == 'gcm':
            # Read the used nonce from the comments
            nonce = bytes.fromhex(find_property_in_comments('nonce'))
            # Read the authentication tag from the comments
            tag = bytes.fromhex(find_property_in_comments('tag'))

            # ------------- solution --------------
            # 1. create an AES object in GCM mode and pass the nonce
            aes = AES.new(key, AES.MODE_GCM, nonce=nonce)
            # 2. decrypt the ciphertext and verify the authentication tag
            plaintext = aes.decrypt_and_verify(self.data, tag)
            # --------- end solution --------------
            
            # replace the image data with the plaintext
            self.data = bytearray(plaintext)
            # remove the comments where we stored the additional data
            cleanup_comments()
        else:
            raise NotImplementedError(f'unknown mode of operation {mode}')

    @property
    def size(self):
        """Size in pixels."""
        return self.width * self.height

    @staticmethod
    def load_from_file(file):
        """Load a PPM file from a file object.

        The implementation can be ignored for the exercise.

        Example
        -------
        with open('image.ppm', 'rb') as f:          # open the image in binary mode (with option 'b')
            image = PPMImage.load_from_file(f)
        """
        whitespace = string.whitespace.encode()
        digits = string.digits.encode()

        comments = []

        def consume_comment(f):
            if (c := f.read(1)) != b'#':
                raise ValueError(f"expected b'#', got {c} instead")
            comment = b''
            while (c := f.read(1)) != b'\n':
                if c == b'':
                    raise ValueError('unexpected end of file')
                comment += c
            comments.append(comment)

        def consume_whitespace(f):
            while (c := f.peek(1)[:1]) != b'':
                if c == b'#':
                    consume_comment(f)
                elif c in whitespace:
                    f.read(1)
                else:
                    return
            raise ValueError('unexpected end of file')

        def read_until_whitespace(f):
            token = b''
            while (c := f.peek(1)[:1]) != b'':
                if c == b'#':
                    consume_comment(f)
                elif c not in whitespace:
                    token += f.read(1)
                else:
                    return token
            raise ValueError('unexpected end of file')

        def is_number(token):
            return all(x in digits for x in token)

        def read_number(f):
            token = read_until_whitespace(f)
            if not is_number(token):
                raise ValueError(f'expected number, got {token} instead')
            return int(token)

        # read magic number
        magic_number = file.read(2)
        if len(magic_number) < 2:
            raise ValueError('unexpected end of file')
        if magic_number != b'P6':
            raise ValueError('unknown file type')

        # read width of image
        consume_whitespace(file)
        width = read_number(file)

        # read height of image
        consume_whitespace(file)
        height = read_number(file)

        # read maximum value of pixels
        consume_whitespace(file)
        max_value = read_number(file)
        if max_value >= 256:
            raise ValueError('only one-byte values are supported')

        while (c := file.peek(1)[:1]) == b'#':
            consume_comment()

        c = file.read(1)
        if not c in whitespace:
            raise ValueError(f'expected single whitespace, got {c} instead')

        size = width * height * 3
        data = file.read() # just read all available data
        if (l := len(data)) < size:
            raise ValueError(f'expected at least {size} bytes, got only {l} bytes')

        return PPMImage(width, height, data, comments=comments)


    def write_to_file(self, file):
        """Write this object to a PPM file.

        The implementation can be ignored for the exercise.

        Example
        -------
        with open('image.ppm', 'wb') as f:          # open the image writable in binary mode (with options 'w' and 'b')
            image.write_to_file(f)
        """
        file.write(b'P6\n')
        for comment in self.comments:
            file.write(b'#' + comment + b'\n')
        header = f'{self.width} {self.height}\n255\n'
        file.write(header.encode())
        file.write(self.data)


def final_encryption_and_decryption_test():
    """Simple test of correctness."""
    with open('dk.ppm', 'rb') as f:
        original_image = PPMImage.load_from_file(f)

    key = secrets.token_bytes(16)
    for mode in ['ecb', 'cbc', 'ctr', 'gcm']:
        image = original_image.copy()
        image.encrypt(key, mode)
        assert original_image != image, f'encrypting with {mode} mode should change the image'
        image.decrypt(key)
        assert original_image == image, f'encrypting and decrypting with {mode} mode should yield the original image'

def task1():
    """Simple test of correctness."""
    with open('dk.ppm', 'rb') as f:
        image = PPMImage.load_from_file(f)

    key = secrets.token_bytes(16)
    image.encrypt(key, 'ecb')

    with open('ecb_encrypted.ppm', 'wb') as f:   # open the image writable in binary mode (with options 'w' and 'b')
            image.write_to_file(f)

    image.data[42] = 0x42 # corrupt the ciphertext by changing one byte
    ''' To show that ECB mode is not secure, we can just change one byte of the ciphertext and then decrypt it again. 
        This should yield a corrupted image, but not an error. '''
    
    image.decrypt(key)
    image.write_to_file(open('ecb_corrupted.ppm', 'wb'))
    return

def task2():
    """ CBC """
    with open('dk.ppm', 'rb') as f:
        image = PPMImage.load_from_file(f)

    key = secrets.token_bytes(16)
    image.encrypt(key, 'cbc')

    with open('cbc_encrypted.ppm', 'wb') as f:   # open the image writable in binary mode (with options 'w' and 'b')
            image.write_to_file(f)

    image.data[42] = 0x42 # set the byte at position 42 to the value 0x42
    image.decrypt(key)
    image.write_to_file(open('cbc_corrupted.ppm', 'wb'))

    ''' CTR '''
    with open('dk.ppm', 'rb') as f:
        image = PPMImage.load_from_file(f)

    key = secrets.token_bytes(16)
    image.encrypt(key, 'ctr')

    with open('ctr_encrypted.ppm', 'wb') as f:   # open the image writable in binary mode (with options 'w' and 'b')
            image.write_to_file(f)

    image.data[42] = 0x42 # set the byte at position 42 to the value 0x42

    ''' Modifying the encrypted pictures, to observe how the picture has changed after decryption.
        Bascially, ctr does a pretty good job in hiding the patterns, even after modifying some bytes.
        The reason for this is that in ctr mode, each block is XORed with a unique keystream block
        generated from the nonce and counter. Therefore, changing a byte in the ciphertext only affects
        the corresponding byte in the plaintext after decryption, without propagating the change to other blocks.'''

    image.decrypt(key)
    image.write_to_file(open('ctr_corrupted.ppm', 'wb'))
    return

def task3():
    '''
    C = DK XOR K
    C XOR DK XOR SE = SE XOR K
    Thus, by modifying the ciphertext C at specific positions, we can achieve the desired changes in the decrypted image.
    
    So if we encrypt the original image DK to get ciphertext C, we can then modify C to C' such that:
    C' = C XOR DK XOR SE

    That's why we get the Sweden flag after decryption of the Danish flag modified ciphertext.    
    '''

    # Load the images with the Danish and the Swedish flags.
    with open('dk.ppm', 'rb') as f:
        image_dk = PPMImage.load_from_file(f)

    with open('se.ppm', 'rb') as f:
        image_se = PPMImage.load_from_file(f)

    # Make sure that both flags are of the same size.
    assert len(image_dk.data) == len(image_se.data)

    # Make a copy of the Danish flag image and encrypt.
    encrypted_image = image_dk.copy()
    key = secrets.token_bytes(16)
    encrypted_image.encrypt(key, 'ctr')

    # Now we modify the ciphertext while pretending that we don't know the key.
    # (Hence, this can also be done by an adversary on the network that does not know the key.)

    def xor(xs, ys):
        """Compute the bit-wise xor of two byte-like objects."""
        return bytes(x ^ y for x, y in zip(xs, ys))

    # The ciphertext c looks like c = dk ^ k, where k denotes the key stream
    # generated by CTR mode.

    # Compute the xor of the Danish and the Swedish flag:
    # d := dk ^ se
    diff = xor(image_dk.data, image_se.data)

    # Xor diff into the ciphertext:
    # c' := c ^ d = c ^ (dk ^ se) = (dk ^ k) ^ (dk ^ se) = se ^ k
    encrypted_image.data = bytearray(xor(encrypted_image.data, diff))

    # Now, when the recipient decrypts the tampered ciphertext, it will obtain
    # an image of the Swedish flag.
    encrypted_image.decrypt(key)
    with open('ex3_result.ppm', 'wb') as f:
        encrypted_image.write_to_file(f)

    # The same method can be used to e.g. replace the Danish flag with the
    # German flag or any other picture.  The fact that the Danish and the
    # Swedish flags only differ in color is *not* important.

    ''' How come this method can be used to replace the danish flag with the german flag?

        Because the method relies on the fact that we can compute the difference between the original image
        (Danish flag) and the desired image (German flag) and then apply this difference to the ciphertext. 
        
        The key point is that in CTR mode, the encryption of each block is independent and can be
        modified without affecting the other blocks. Therefore, as long as we can compute the difference 
        between the original and the desired image, we can apply this difference to the ciphertext to achieve
        the desired changes in the decrypted image, regardless of the specific content of the images.

        This shows a weakness of the CTR mode: It does not provide integrity protection, and thus
        an adversary can modify the ciphertext in a way that results in predictable changes in the decrypted plaintext. 
        This is why CTR mode should always be used in combination with a message authentication code (MAC)
        or an authenticated encryption mode like GCM to ensure both confidentiality and integrity of the data ... 
        

        Is this also the case for ECB and CBC mode? 

        No, this method cannot be used to replace the Danish flag with the German flag in ECB and CBC modes 
        because of how these modes handle encryption and decryption.

        In ECB mode, each block of plaintext is encrypted independently, which means that if we modify
        a block of ciphertext, it will only affect the corresponding block of plaintext after decryption. 
        However, since ECB mode does not use any chaining or feedback mechanism, modifying one block
        of ciphertext will not affect the other blocks. Therefore, while we can modify a specific block
        to change a part of the image, it would not allow us to replace the entire image with another one
        (like the German flag) without also modifying all the other blocks accordingly.

        In CBC mode, each block of plaintext is XORed with the previous ciphertext block before encryption. 
        This means that if we modify a block of ciphertext, it will affect the decryption of that block
        and the next block. However, since the decryption of each block depends on the previous ciphertext block,
        modifying one block of ciphertext will cause a chain reaction that affects all subsequent blocks. 
        This makes it more difficult to achieve a predictable change in the decrypted image, as modifying
        one block can lead to unpredictable changes in the following blocks. Therefore, while we can modify
        a specific block to change a part of the image, it would not allow us to replace the entire image with
        another one (like the German flag) without also modifying all the other blocks accordingly, and even then, 
        it would be much more complex and less predictable than in CTR mode.

        '''

    return 

def task4():
    """ GCM """
    with open('dk.ppm', 'rb') as f:
        image = PPMImage.load_from_file(f)

    key = secrets.token_bytes(16)
    image.encrypt(key, 'gcm')

    with open('gcm_encrypted.ppm', 'wb') as f:   # open the image writable in binary mode (with options 'w' and 'b')
            image.write_to_file(f)

    # image.data[42] = 0x42  # uncomment this to invalidate the MAC - and thus cause an error during decryption

    image.decrypt(key)
    image.write_to_file(open('gcm_corrupted.ppm', 'wb'))
    return

    return 

def task5():
    # Load the image with the security message.
    with open('security.ppm', 'rb') as f:
        image = PPMImage.load_from_file(f)

    # Encrypt it with GCM.
    key = secrets.token_bytes(16)
    image.encrypt(key, 'gcm')

    # Now we modify the image without using the key.
    # (We just change the `height` property of the object here, but we can do
    # the same if the image had been saved to a file.)
    image.height = 245

    # Now, when the recipient decrypts the image, the result will show a
    # different message.
    image.decrypt(key)
    with open('ex5_result.ppm', 'wb') as f:
        image.write_to_file(f)

    # In our implementation, the image metadata (width, height) is not
    # authenticated.  Hence, changes to them will not result in errors upon decryption.
    
    ''' This shows a weakness of our implementation: It does not provide integrity protection for the image metadata, 
        and thus an adversary can modify the metadata in a way that results in predictable changes in the decrypted image. 
        This is why the metadata should also be included in the authentication process, e.g. by including it in the 
        additional authenticated data (AAD) when using GCM mode, to ensure both confidentiality and integrity of the
        entire image, including its metadata. '''

    return 

if __name__ == '__main__':
    # The following is executed if you run `python3 ppmcrypt.py`.
    
    task1()
    task2()
    task3()
    task4()
    task5()

    final_encryption_and_decryption_test()
