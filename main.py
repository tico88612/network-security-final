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
        hash_data = SHA256.new(self.original_image_bytes)
        print(hash_data)

    def messageToBinary(self,message):
        if type(message) == str:
            return ''.join([ format(ord(i), "08b") for i in message ])
        elif type(message) == bytes or type(message) == np.ndarray:
            return [ format(i, "08b") for i in message ]
        elif type(message) == int or type(message) == np.uint8:
            return format(message, "08b")
        else:
            raise TypeError("Input type not supported")
        
    def encryption_image(self):
        image = cv2.imread("tux.bmp")       
        self.hash_data = SHA256.new(image.tobytes())
        key = RSA.importKey(open('private.pem').read())
        signer = PKCS115_SigScheme(key)
        signature = signer.sign(self.hash_data)
        self.signature = signature

        print(self.signature)
        print(self.signature[0],bin(self.signature[0])[1])

        listToStrSig = ''.join([format(elem, '08b') for elem in self.signature])
        x= "".join(f"{ord(i):08b}" for i in ("#####"))
        listToStrSig += x # you can use any string as the delimeter
        print(listToStrSig)
        data_index = 0
        data_len = len(listToStrSig)

        for values in image:   # watermarking loop
            for pixel in values:            
                # convert RGB values to binary format
                r, g, b = self.messageToBinary(pixel)
                # modify the least significant bit only if there is still data to store
                if data_index < data_len:
                    # hide the data into least significant bit of red pixel
                    temp = 1 if listToStrSig[data_index]=='1' else 0
                    pixel[0] ^= temp
                    data_index += 1
                if data_index < data_len:
                    # hide the data into least significant bit of green pixel
                    temp = 1 if listToStrSig[data_index]=='1' else 0
                    pixel[1] ^= temp
                    data_index += 1
                if data_index < data_len:
                    # hide the data into least significant bit of  blue pixel
                    temp = 1 if listToStrSig[data_index]=='1' else 0
                    pixel[2] ^= temp
                    data_index += 1
                # if data is encoded, just break out of the loop
                if data_index >= data_len:
                    break
        cv2.imwrite("output.bmp", image)


    def decryption_image(self):

        ouimage = cv2.imread("output.bmp")
        oriimage = cv2.imread("tux.bmp")
        extimage = ouimage
        h, w = ouimage.shape[:2]
        binary_data = ""
        decoded_data = ""
        decode_done=0
        x= "".join(f"{ord(i):08b}" for i in ("#####"))
        print(x)

        for i in range(0, h):    # watermarking loop
            if decode_done==1: break
            for j in range(0, w):
                if decode_done==1: break
                pixel = ouimage[i][j]
                oripixel = oriimage[i][j]
                r, g, b = self.messageToBinary(pixel)
                # modify the least significant bit only if there is still data to store
                for k in range(3):
                    binary_data += '1' if (pixel[k] ^ oripixel[k])==1 else '0'
                    extimage[i][j][k]=ouimage[i][j][k] ^ (pixel[k] ^ oripixel[k])
                    if (len(binary_data)%8==0):
                        if binary_data[-40:]==x: # decoded_data[-5:] == "#####": #check if we have reached the delimeter which is "#####"
                            decode_done=1
                            break
                if decode_done==1: break
        
        print(binary_data)
         # split by 8-bits
        all_bytes = [ binary_data[i: i+8] for i in range(0, len(binary_data), 8) ]
        all_bytes= all_bytes[:-5]
        signature_data =bytes()
        for i in range(len(all_bytes)):
            signature_data+=int(all_bytes[i], 2).to_bytes(1, byteorder='big')
       
        
        print(signature_data)
        print(decoded_data)

        extr_hash = SHA256.new(extimage.tobytes())
        
        key = RSA.importKey(open('public.pem').read())
        verifier = PKCS115_SigScheme(key)
        try:
            verifier.verify(extr_hash, signature_data)
            print("Signature is valid.")
        except:
            print("Signature is invalid.")

       

# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    root = Tk()
    root.geometry("%dx%d" % (1024, 768))
    root.title("Symmetryc Encryption GUI")
    app = Window(root)
    app.pack(fill=BOTH, expand=1)
    root.mainloop()

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
