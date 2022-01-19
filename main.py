import base64
import hashlib
import os
import random

import cv2
import numpy as np
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
from Crypto.Hash import SHA256
from tkinter import *
from tkinter import filedialog

from PIL import Image, ImageTk

KEY = 1001


class Window(Frame):
    def __init__(self, master=None):
        Frame.__init__(self, master)

        menu = Menu(self.master)
        master.config(menu=menu)

        rsa_menu = Menu(menu)
        rsa_menu.add_command(label="Generate RSA Key", command=self.generate_rsa_key)
        rsa_menu.add_command(label="Open RSA Key", command=self.open_rsa_key)
        # rsa_menu.add_command(label="Open Original Image", command=self.open_original_image)
        # rsa_menu.add_command(label="Open WaterMark Image", command=self.open_watermark_image)
        # rsa_menu.add_command(label="Encryption Image", command=self.encryption_image)
        # rsa_menu.add_command(label="Decryption Image", command=self.decryption_image)
        rsa_menu.add_command(label="Exit", command=self.quit)
        menu.add_cascade(label="RSA", menu=rsa_menu)

        image_menu = Menu(menu)
        image_menu.add_command(label="Open Original Image", command=self.open_original_image)
        image_menu.add_command(label="Open WaterMark Image", command=self.open_watermark_image)
        image_menu.add_command(label="Exit", command=self.quit)
        menu.add_cascade(label="Image", menu=image_menu)

        text_menu = Menu(menu)
        text_menu.add_command(label="Encryption Image", command=self.encryption_image)
        text_menu.add_command(label="Decryption Image", command=self.decryption_image)
        menu.add_cascade(label="Encryption", menu=text_menu)

        self.canvas = Canvas(self)
        self.canvas.pack(fill=BOTH, expand=True)
        random.seed(a=KEY)

        self.image = None  # none yet
        self.sha2 = hashlib.sha256()
        self.key = None
        self.original_image = None
        self.watermark_image = None
        self.original_size = None
        self.original_width = None
        self.original_height = None
        self.watermark_size = None
        self.watermark_width = None
        self.watermark_height = None
        self.signature = None
        self.original_image_bytes = None
        self.watermark_image_bytes = None
        self.output_image_bytes = None
        self.extract_image_bytes = None

    # Function for open bmp file
    def open_file_text(self):
        filename = filedialog.askopenfilename(initialdir=os.getcwd(), title="Select text File",
                                              filetypes=[("text Files", "*.txt")])
        if not filename:
            return  # user cancelled; stop this method
        contents = ""
        self.canvas.delete('all')
        # Read file
        with open(filename) as f:
            contents = f.read()
            # print(contents)

            # Create text widget and specify size.
            T = Text(root, height=5, width=52)
            label = Label(root, text="Original", compound='top')
            self.canvas.create_window(250, 30, window=label)
            self.canvas.create_window(250, 100, window=T)
            # Insert The Fact.
            T.insert(END, contents)
        return contents

    # Function for open bmp image
    def Display_BMP(self, filename):
        with open(filename, "rb") as f:
            contents = f.read()
            self.load2 = Image.open(filename)
            w, h = self.load2.size
            self.render2 = ImageTk.PhotoImage(self.load2)  # must keep a reference to this

            label2 = Label(root, text="Cipher", image=self.render2, compound='top')
            self.canvas.create_window(900, 300, window=label2)

    # Function for display text (.txt) file
    def Display_Text(self, filename):
        with open(filename) as f:
            contents = f.read()
            # print(contents)
            # Create text widget and specify size.
            T2 = Text(root, height=5, width=52)
            label4 = Label(root, text="Cipher", compound='top')
            self.canvas.create_window(900, 30, window=label4)
            self.canvas.create_window(900, 100, window=T2)
            # Insert The Fact.
            T2.insert(END, contents)

    def generate_rsa_key(self):
        # 2048 位元 RSA 金鑰
        self.key = RSA.generate(2048)

        # RSA 私鑰
        private_key = self.key.export_key()
        with open("private.pem", "wb") as f:
            f.write(private_key)
        # RSA 公鑰
        public_key = self.key.publickey().export_key()
        with open("public.pem", "wb") as f:
            f.write(public_key)

    def open_rsa_key(self):
        filename = filedialog.askopenfilename(initialdir=os.getcwd(), title="Select PEM File",
                                              filetypes=[("PEM Files", "*.pem")])
        if not filename:
            return  # user cancelled; stop this method
        with open(filename, "rb") as f:
            encoded_key = f.read()
            self.key = RSA.import_key(encoded_key)
            public_key = self.key.publickey().export_key()
            print(public_key)

    def open_watermark_image(self):
        filename = filedialog.askopenfilename(initialdir=os.getcwd(), title="Select JPG File",
                                              filetypes=[("JPG Files", "*.bmp")])
        if not filename:
            return  # user cancelled; stop this method
        with open(filename, "rb") as f:
            self.watermark_image_bytes = f.read()
            image_open = Image.open(filename)
            w, h = image_open.size
            self.watermark_width = w
            self.watermark_height = h
            self.watermark_size = w * h
            self.watermark_image = ImageTk.PhotoImage(image_open)  # must keep a reference to this
            if image_open is not None:  # if an image was already loaded
                self.canvas.delete(image_open)  # remove the previous image

            label = Label(root, text="Watermark", image=self.watermark_image, compound='top')
            self.canvas.create_window(800, 200, window=label)

    def open_original_image(self):
        filename = filedialog.askopenfilename(initialdir=os.getcwd(), title="Select JPG File",
                                              filetypes=[("JPG Files", "*.bmp")])
        if not filename:
            return  # user cancelled; stop this method
        self.canvas.delete('all')
        with open(filename, "rb") as f:
            self.original_image_bytes = f.read()
            image_open = Image.open(filename)
            w, h = image_open.size
            self.original_width = w
            self.original_height = h
            self.original_size = w * h
            self.original_image = ImageTk.PhotoImage(image_open)  # must keep a reference to this
            if image_open is not None:  # if an image was already loaded
                self.canvas.delete(image_open)  # remove the previous image
            label = Label(root, text="Original", image=self.original_image, compound='top')
            self.canvas.create_window(200, 200, window=label)
        self.sha2.update(self.original_image_bytes)
        # hash_data = self.sha2.new(self.original_image_bytes)
        hash_data = SHA256.new(self.original_image_bytes)
        # hash_data = self.sha2.hexdigest()
        print(hash_data)

    def encryption_image(self):
        # hash_data = self.sha2.new()
        hash_data = SHA256.new(self.original_image_bytes)
        print(hash_data)
        #key = RSA.importKey(open('public.pem').read())
        key = RSA.importKey(open('private.pem').read())
        signer = PKCS115_SigScheme(key)
        signature = signer.sign(hash_data)
        self.signature = signature

        # Watermark
        # random_points = random.sample(range(self.original_size), self.watermark_size)
        # print(random_points)
        img_buffer_numpy = np.frombuffer(self.original_image_bytes, dtype=np.uint8)
        img_numpy = cv2.imdecode(img_buffer_numpy, 1)

        _, img_encode = cv2.imencode('.bmp', img_numpy)
        img_bytes = img_encode.tobytes()

        img_bytes+=signature       # append signature
        print("image byte ")
        print(img_bytes)
        self.sha2.update(img_bytes)

        img_buffer_numpy = np.frombuffer(img_bytes, dtype=np.uint8)
        img_numpy = cv2.imdecode(img_buffer_numpy, 1)

        img_buffer_numpy2 = np.frombuffer(self.watermark_image_bytes, dtype=np.uint8)
        img_numpy2 = cv2.imdecode(img_buffer_numpy2, 1)

        for i in range(0, self.original_height):    # watermarking loop
            for j in range(0, self.original_width):
                # LSB WATERMARKING
                temp = 1 if img_numpy2[i%self.watermark_height][j%self.watermark_width][0]==255 else 0
                img_numpy[i][j][0]^=temp
                img_numpy[i][j][1]^=temp
                img_numpy[i][j][2]^=temp
                # LSB WATERMARKING
                

        _, img_encode = cv2.imencode('.bmp', img_numpy)
        img_bytes = img_encode.tobytes()
        self.output_image_bytes = img_bytes

        with open("output.bmp", "wb") as f:
            f.write(self.output_image_bytes)

    def decryption_image(self):
        filename = filedialog.askopenfilename(initialdir=os.getcwd(), title="Select JPG File",
                                              filetypes=[("JPG Files", "*.bmp")])
        if not filename:
            return  # user cancelled; stop this method
        with open(filename, "rb") as f:
            self.extract_image_bytes = f.read()
            image_open = Image.open(filename)
            w, h = image_open.size
            self.extract_width = w
            self.extract_height = h
            self.extract_size = w * h

        # Extract Watermark
            # Get watermarked image
            img_buffer_numpy = np.frombuffer(self.extract_image_bytes, dtype=np.uint8)
            img_numpy = cv2.imdecode(img_buffer_numpy, 1)

            # Get Watermark image
            img_buffer_numpy2 = np.frombuffer(self.watermark_image_bytes, dtype=np.uint8)
            img_numpy2 = cv2.imdecode(img_buffer_numpy2, 1)


            for i in range(0, self.original_height):    # watermarking loop
                for j in range(0, self.original_width):
                    # LSB WATERMARKING
                    temp = 1 if img_numpy2[i%self.watermark_height][j%self.watermark_width][0]==255 else 0
                    img_numpy[i][j][0]^=temp
                    img_numpy[i][j][1]^=temp
                    img_numpy[i][j][2]^=temp
                    # LSB WATERMARKING

            # img_numpy become no watermark
            _, img_encode = cv2.imencode('.bmp', img_numpy)
            #signature_data = message_data[-256:]
            #message_data = message_data[:len(self.extract_image_bytes) - 256]
            message_data = img_encode.tobytes()
            print("message_data ")
            print(message_data)
            # Extract Message and Signature
            signature_data = message_data[-256:]
            message_data = message_data[:len(self.extract_image_bytes) - 256]
            

            # image_open = Image.open(filename)
            # self.original_image = ImageTk.PhotoImage(image_open)  # must keep a reference to this
            # if image_open is not None:  # if an image was already loaded
            #     self.canvas.delete(image_open)  # remove the previous image
            #
            # label = Label(root, text="Original", image=self.original_image, compound='top')
            # self.canvas.create_window(200, 200, window=label)
            # hash1 = hashlib.sha256()
            # hash1.update(message_data)
            hash1_data = SHA256.new(message_data) #message hash

            key = RSA.importKey(open('public.pem').read())
            verifier = PKCS115_SigScheme(key)
            try:
                verifier.verify(hash1_data, signature_data)
                print("Signature is valid.")
            except:
                print("Signature is invalid.")

    # # Function for encrypt bmp file use ECB mode
    # def EncryptBMP_ECB(self):
    #     plain_data = self.open_file_image()
    #     self_aes = SelfAES()
    #     need_trim = len(plain_data) % 16  # 截斷
    #     clear_trimmed = plain_data[64:-need_trim]  # 截斷 16 倍數
    #     cipher_data = self_aes.ecb_encrypt(clear_trimmed)
    #     cipher_data = plain_data[0:64] + cipher_data + plain_data[-need_trim:]
    #     with open("tux_ecb.bmp", "wb") as f:
    #         f.write(cipher_data)
    #     self.Display_BMP("tux_ecb.bmp")
    #
    # # Function for encrypt bmp file use ECB mode
    # def EncryptBMP_CBC(self):
    #     plain_data = self.open_file_image()
    #     self_aes = SelfAES()
    #     need_trim = len(plain_data) % 16  # 截斷
    #     clear_trimmed = plain_data[64:-need_trim]  # 截斷 16 倍數
    #     cipher_data = self_aes.cbc_encrypt(clear_trimmed)
    #     cipher_data = plain_data[0:64] + cipher_data + plain_data[-need_trim:]
    #     with open("tux_cbc.bmp", "wb") as f:
    #         f.write(cipher_data)
    #     self.Display_BMP("tux_cbc.bmp")
    #
    # # Function for encrypt bmp file use ECB mode
    # def DecryptBMP_ECB(self):
    #     cipher_data = self.open_file_image()
    #     self_aes = SelfAES()
    #     need_trim = len(cipher_data) % 16  # 截斷
    #     clear_trimmed = cipher_data[64:-need_trim]  # 截斷 16 倍數
    #     plain_data = self_aes.ecb_decrypt(clear_trimmed)
    #     plain_data = cipher_data[0:64] + plain_data + cipher_data[-need_trim:]
    #     with open("tux_ecb_return.bmp", "wb") as f:
    #         f.write(plain_data)
    #     self.Display_BMP("tux_ecb_return.bmp")
    #
    # # Function for encrypt bmp file use ECB mode
    # def DecryptBMP_CBC(self):
    #     cipher_data = self.open_file_image()
    #     self_aes = SelfAES()
    #     need_trim = len(cipher_data) % 16  # 截斷
    #     clear_trimmed = cipher_data[64:-need_trim]  # 截斷 16 倍數
    #     plain_data = self_aes.cbc_decrypt(clear_trimmed)
    #     plain_data = cipher_data[0:64] + plain_data + cipher_data[-need_trim:]
    #     with open("tux_cbc_return.bmp", "wb") as f:
    #         f.write(plain_data)
    #     self.Display_BMP("tux_cbc_return.bmp")


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    root = Tk()
    root.geometry("%dx%d" % (1024, 768))
    root.title("Symmetryc Encryption GUI")
    app = Window(root)
    app.pack(fill=BOTH, expand=1)
    root.mainloop()

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
