import os
import shutil
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import sympy
import random
import tkinter as tk
from tkinter import filedialog, messagebox


# 生成大素数
def generate_large_prime(bits=300):
    prime = sympy.randprime(10 ** (bits - 1), 10 ** bits)
    return prime


# DES 加密（使用 ECB 模式）
def des_encrypt(key, data):
    cipher = DES.new(key, DES.MODE_ECB)  # 使用 ECB 模式
    padded_data = pad(data.encode(), DES.block_size)  # 确保数据填充到8的倍数
    ciphertext = cipher.encrypt(padded_data)
    return ciphertext


# DES 解密（使用 ECB 模式）
def des_decrypt(key, encrypted_data):
    cipher = DES.new(key, DES.MODE_ECB)  # 使用 ECB 模式
    decrypted_data = unpad(cipher.decrypt(encrypted_data), DES.block_size)  # 去除填充
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

    # 解密后恢复原文件名 (去掉 `.enc` 后缀)
    decrypted_file_path = file_path.rsplit('.', 1)[0]  # 去掉文件扩展名 (.enc)

    with open(decrypted_file_path, 'wb') as dec_file:
        dec_file.write(decrypted_data.encode())

    return decrypted_file_path


# 压缩文件夹
def compress_folder(folder_path):
    zip_file_path = folder_path + '.zip'
    shutil.make_archive(zip_file_path.replace('.zip', ''), 'zip', folder_path)
    return zip_file_path


# 解压文件夹
def decompress_folder(zip_file_path, extract_to):
    shutil.unpack_archive(zip_file_path, extract_to)


# 文本加密
def encrypt_text():
    key = os.urandom(8)  # 生成一个8字节的随机DES密钥
    text = text_to_encrypt.get("1.0", tk.END).strip()  # 获取文本框1中的内容
    if text:
        encrypted_text = des_encrypt(key, text)
        text_after_encryption.delete("1.0", tk.END)  # 清空文本框2
        text_after_encryption.insert(tk.END, encrypted_text.hex())  # 显示加密后的文本 (十六进制)

        # 保存密钥到文件
        key_file_path = filedialog.asksaveasfilename(defaultextension=".key", filetypes=[("Key Files", "*.key")],
                                                     title="保存密钥")
        if key_file_path:
            with open(key_file_path, 'wb') as key_file:
                key_file.write(key)
            messagebox.showinfo("成功", f"密钥已保存：{key_file_path}")


# 文本解密
def decrypt_text():
    key_file_path = filedialog.askopenfilename(title="选择密钥文件", filetypes=[("Key Files", "*.key")])
    if key_file_path:
        with open(key_file_path, 'rb') as key_file:
            key = key_file.read()
        encrypted_text = text_to_decrypt.get("1.0", tk.END).strip()  # 获取文本框2中的加密文本
        if encrypted_text:
            encrypted_data = bytes.fromhex(encrypted_text)  # 将十六进制字符串转换为字节
            try:
                decrypted_text = des_decrypt(key, encrypted_data)
                text_after_encryption.delete("1.0", tk.END)  # 清空文本框2
                text_after_encryption.insert(tk.END, decrypted_text)  # 显示解密后的文本
            except Exception as e:
                messagebox.showerror("解密失败", f"解密失败：{e}")


# GUI 界面
def select_file_and_encrypt():
    file_path = filedialog.askopenfilename(title="选择文件进行加密")
    if file_path:
        key = os.urandom(8)  # 生成一个8字节的随机DES密钥
        encrypted_file_path = encrypt_file(file_path, key)
        # 保存密钥到文件
        with open(encrypted_file_path + '.key', 'wb') as key_file:
            key_file.write(key)
        messagebox.showinfo("成功",
                            f"文件加密成功，保存为：{encrypted_file_path} 和密钥文件：{encrypted_file_path + '.key'}")


def select_file_and_decrypt():
    file_path = filedialog.askopenfilename(title="选择文件进行解密")
    if file_path:
        key_file_path = filedialog.askopenfilename(title="选择密钥文件", filetypes=[("Key Files", "*.key")])
        if key_file_path:
            with open(key_file_path, 'rb') as key_file:
                key = key_file.read()
            decrypted_file_path = decrypt_file(file_path, key)
            messagebox.showinfo("成功", f"文件解密成功，保存为：{decrypted_file_path}")


# 创建主界面
root = tk.Tk()
root.title("加解密与大素数生成软件")

frame = tk.Frame(root)
frame.pack(padx=20, pady=20)

encrypt_button = tk.Button(frame, text="选择文件加密", command=select_file_and_encrypt)
encrypt_button.grid(row=0, column=0, padx=10, pady=10)

decrypt_button = tk.Button(frame, text="选择文件解密", command=select_file_and_decrypt)
decrypt_button.grid(row=0, column=1, padx=10, pady=10)

# 添加文本加解密部分
text_to_encrypt_label = tk.Label(frame, text="请输入待加密的文本：")
text_to_encrypt_label.grid(row=5, column=0, padx=10, pady=10)

text_to_encrypt = tk.Text(frame, height=4, width=50)
text_to_encrypt.grid(row=6, column=0, columnspan=2, pady=10)

encrypt_text_button = tk.Button(frame, text="加密文本", command=encrypt_text)
encrypt_text_button.grid(row=7, column=0, padx=10, pady=10)

text_to_decrypt_label = tk.Label(frame, text="请输入待解密的文本：")
text_to_decrypt_label.grid(row=8, column=0, padx=10, pady=10)

text_to_decrypt = tk.Text(frame, height=4, width=50)
text_to_decrypt.grid(row=9, column=0, columnspan=2, pady=10)

decrypt_text_button = tk.Button(frame, text="解密文本", command=decrypt_text)
decrypt_text_button.grid(row=10, column=0, padx=10, pady=10)

text_after_encryption = tk.Text(frame, height=4, width=50)
text_after_encryption.grid(row=11, column=0, columnspan=2, pady=10)

root.mainloop()
