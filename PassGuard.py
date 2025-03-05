import tkinter as tk
from tkinter import ttk, messagebox
import sqlite3
import webbrowser
from cryptography.fernet import Fernet
from tkinter import filedialog
import csv
import os

# 生成密钥并存储 (只需运行一次)
# key = Fernet.generate_key()
# with open("key.key", "wb") as key_file:
#     key_file.write(key)


# 检查密钥文件是否存在，不存在则生成
if not os.path.exists("key.key"):
    key = Fernet.generate_key()
    with open("key.key", "wb") as key_file:
        key_file.write(key)     #生成的密钥可以重复使用
    # print("密钥已生成并保存到 key.key")

# 读取密钥
with open("key.key", "rb") as key_file:
    key = key_file.read()

cipher = Fernet(key)

def setup_db():
    conn = sqlite3.connect("passwords.db")
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS passwords (
                      id INTEGER PRIMARY KEY,
                      name TEXT,
                      url TEXT,
                      username TEXT,
                      password TEXT)''')
    conn.commit()
    conn.close()

def add_entry():
    name, url, username, password = name_var.get(), url_var.get(), user_var.get(), pass_var.get()
    if not name or not url or not username or not password:
        messagebox.showwarning("警告", "所有字段都是必填的！")
        return
    encrypted_password = cipher.encrypt(password.encode()).decode()
    conn = sqlite3.connect("passwords.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO passwords (name, url, username, password) VALUES (?, ?, ?, ?)",
                   (name, url, username, encrypted_password))
    conn.commit()
    conn.close()
    load_entries()
    clear_fields()

def delete_entry():
    selected_item = tree.selection()
    if not selected_item:
        messagebox.showwarning("警告", "请先选择一条记录！")
        return
    item_id = tree.item(selected_item)['values'][0]
    conn = sqlite3.connect("passwords.db")
    cursor = conn.cursor()
    cursor.execute("DELETE FROM passwords WHERE id = ?", (item_id,))
    conn.commit()
    conn.close()
    load_entries()

def open_url():
    selected_item = tree.selection()
    if not selected_item:
        messagebox.showwarning("警告", "请先选择一条记录！")
        return
    url = tree.item(selected_item)['values'][2]
    webbrowser.open(url)

def load_entries():
    for row in tree.get_children():
        tree.delete(row)
    conn = sqlite3.connect("passwords.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM passwords")
    for row in cursor.fetchall():
        decrypted_password = cipher.decrypt(row[4].encode()).decode()
        tree.insert("", "end", values=(row[0], row[1], row[2], row[3], decrypted_password))
    conn.close()


def clear_fields():
    name_var.set("")
    url_var.set("")
    user_var.set("")
    pass_var.set("")

# 新增1：搜索功能
def search_entry():
    query = search_var.get()
    for row in tree.get_children():
        tree.delete(row)
    conn = sqlite3.connect("passwords.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM passwords WHERE name LIKE ? OR url LIKE ? OR username LIKE ?",
                   ('%' + query + '%', '%' + query + '%', '%' + query + '%'))
    for row in cursor.fetchall():
        tree.insert("", "end", values=row)
    conn.close()


# 新增2：导入导出
def export_data():
    file_path = filedialog.asksaveasfilename(defaultextension=".csv",
                                             filetypes=[("CSV 文件", "*.csv")])
    if not file_path:
        return
    conn = sqlite3.connect("passwords.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM passwords")
    with open(file_path, "w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["ID", "名称", "网址", "用户名", "密码"])
        for row in cursor.fetchall():
            decrypted_password = cipher.decrypt(row[4].encode()).decode()
            writer.writerow([row[0], row[1], row[2], row[3], decrypted_password])
    conn.close()
    messagebox.showinfo("成功", "数据已导出！")

def import_data():
    file_path = filedialog.askopenfilename(filetypes=[("CSV 文件", "*.csv")])
    if not file_path:
        return
    conn = sqlite3.connect("passwords.db")
    cursor = conn.cursor()
    with open(file_path, "r") as file:
        reader = csv.reader(file)
        next(reader)  # 跳过标题行
        for row in reader:
            encrypted_password = cipher.encrypt(row[4].encode()).decode()
            cursor.execute("INSERT INTO passwords (name, url, username, password) VALUES (?, ?, ?, ?)",
                           (row[1], row[2], row[3], encrypted_password))
    conn.commit()
    conn.close()
    load_entries()
    messagebox.showinfo("成功", "数据已导入！")

setup_db()

root = tk.Tk()
root.title("本地密码管理工具")
root.geometry("600x400")
root.resizable(False, False)

frame = tk.Frame(root, padx=10, pady=10)
frame.pack(pady=10)

name_var, url_var, user_var, pass_var = tk.StringVar(), tk.StringVar(), tk.StringVar(), tk.StringVar()

tk.Label(frame, text="名称:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
tk.Entry(frame, textvariable=name_var, width=30).grid(row=0, column=1, padx=5, pady=5)

tk.Label(frame, text="网址:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
tk.Entry(frame, textvariable=url_var, width=30).grid(row=1, column=1, padx=5, pady=5)

tk.Label(frame, text="用户名:").grid(row=2, column=0, sticky="w", padx=5, pady=5)
tk.Entry(frame, textvariable=user_var, width=30).grid(row=2, column=1, padx=5, pady=5)

tk.Label(frame, text="密码:").grid(row=3, column=0, sticky="w", padx=5, pady=5)
tk.Entry(frame, textvariable=pass_var, show="*", width=30).grid(row=3, column=1, padx=5, pady=5)

tk.Button(frame, text="增加", command=add_entry, width=10).grid(row=0, column=2, padx=5, pady=5)
tk.Button(frame, text="删除", command=delete_entry, width=10).grid(row=1, column=2, padx=5, pady=5)
tk.Button(frame, text="打开网址", command=open_url, width=10).grid(row=2, column=2, padx=5, pady=5)

# 新增1：搜索功能
search_var = tk.StringVar()
tk.Label(frame, text="搜索:").grid(row=4, column=0, sticky="w", padx=5, pady=5)
tk.Entry(frame, textvariable=search_var, width=30).grid(row=4, column=1, padx=5, pady=5)
tk.Button(frame, text="查找", command=search_entry, width=10).grid(row=4, column=2, padx=5, pady=5)
# 新增2：导出导入
tk.Button(frame, text="导入", command=import_data, width=10).grid(row=5, column=0, padx=5, pady=5)
tk.Button(frame, text="导出", command=export_data, width=10).grid(row=5, column=1, padx=5, pady=5)



columns = ("ID", "名称", "网址", "用户名", "密码")
tree_frame = tk.Frame(root)
tree_frame.pack(pady=10)

scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL)
tree = ttk.Treeview(tree_frame, columns=columns, show="headings", yscrollcommand=scrollbar.set)
scrollbar.config(command=tree.yview)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

for col in columns:
    tree.heading(col, text=col)
    tree.column(col, width=120, anchor="center")

tree.pack()
load_entries()
root.mainloop()
