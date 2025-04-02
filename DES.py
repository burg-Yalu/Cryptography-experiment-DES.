import os
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import sympy
import random
import tkinter as tk
from tkinter import filedialog, messagebox

# 生成大素数
def generate_large_prime(bits=300):
    prime = sympy.randprime(10**(bits-1), 10**bits)
    return prime

# DES 加密
def des_encrypt(key, data):
    cipher = DES.new(key, DES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(data.encode(), DES.block_size))
    return cipher.iv + ciphertext  # 前8字节是初始化向量

# DES 解密
def des_decrypt(key, encrypted_data):
    iv = encrypted_data[:8]  # 前8字节为初始化向量
    cipher = DES.new(key, DES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data[8:]), DES.block_size)
    return decrypted_data.decode()

# 文件加密
def encrypt_file(file_path, key):
    with open(file_path, 'rb') as file:
        data = file.read()
    encrypted_data = des_encrypt(key, data.decode(errors='ignore'))
    encrypted_file_path = file_path + '.enc'
    with open(encrypted_file_path, 'wb') as enc_file:
        enc_file.write(encrypted_data)
    return encrypted_file_path

# 文件解密
def decrypt_file(file_path, key):
    with open(file_path, 'rb') as file:
        encrypted_data = file.read()
    decrypted_data = des_decrypt(key, encrypted_data)
    decrypted_file_path = file_path.replace('.enc', '.dec')
    with open(decrypted_file_path, 'wb') as dec_file:
        dec_file.write(decrypted_data.encode())
    return decrypted_file_path

# GUI 界面
def select_file_and_encrypt():
    file_path = filedialog.askopenfilename(title="选择文件进行加密")
    if file_path:
        key = os.urandom(8)  # 生成一个8字节的随机DES密钥
        encrypted_file_path = encrypt_file(file_path, key)
        messagebox.showinfo("成功", f"文件加密成功，保存为：{encrypted_file_path}")

def select_file_and_decrypt():
    file_path = filedialog.askopenfilename(title="选择文件进行解密")
    if file_path:
        key = os.urandom(8)  # 生成一个8字节的随机DES密钥
        decrypted_file_path = decrypt_file(file_path, key)
        messagebox.showinfo("成功", f"文件解密成功，保存为：{decrypted_file_path}")

def generate_prime_number():
    prime_length = int(prime_length_entry.get())
    prime = generate_large_prime(prime_length)
    prime_display.delete(1.0, tk.END)
    prime_display.insert(tk.END, hex(prime))

def save_prime():
    prime = prime_display.get(1.0, tk.END).strip()
    if prime:
        with open("prime.txt", "w") as file:
            file.write(prime)
        messagebox.showinfo("保存成功", "素数已保存到 prime.txt")

def load_prime():
    try:
        with open("prime.txt", "r") as file:
            prime = file.read().strip()
            prime_display.delete(1.0, tk.END)
            prime_display.insert(tk.END, prime)
        messagebox.showinfo("加载成功", "素数已从文件加载")
    except FileNotFoundError:
        messagebox.showerror("文件未找到", "未找到 prime.txt 文件")

# 创建主界面
root = tk.Tk()
root.title("加解密与大素数生成软件")

frame = tk.Frame(root)
frame.pack(padx=20, pady=20)

encrypt_button = tk.Button(frame, text="选择文件加密", command=select_file_and_encrypt)
encrypt_button.grid(row=0, column=0, padx=10, pady=10)

decrypt_button = tk.Button(frame, text="选择文件解密", command=select_file_and_decrypt)
decrypt_button.grid(row=0, column=1, padx=10, pady=10)

prime_length_label = tk.Label(frame, text="生成素数位数 (最大300位)：")
prime_length_label.grid(row=1, column=0, padx=10, pady=10)

prime_length_entry = tk.Entry(frame)
prime_length_entry.grid(row=1, column=1, padx=10, pady=10)

generate_prime_button = tk.Button(frame, text="生成大素数", command=generate_prime_number)
generate_prime_button.grid(row=2, column=0, columnspan=2, pady=10)

prime_display = tk.Text(frame, height=4, width=50)
prime_display.grid(row=3, column=0, columnspan=2, pady=10)

save_prime_button = tk.Button(frame, text="保存素数", command=save_prime)
save_prime_button.grid(row=4, column=0, padx=10, pady=10)

load_prime_button = tk.Button(frame, text="加载素数", command=load_prime)
load_prime_button.grid(row=4, column=1, padx=10, pady=10)

root.mainloop()
