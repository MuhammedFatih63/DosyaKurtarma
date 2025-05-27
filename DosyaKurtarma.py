import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from hashlib import sha256
from datetime import datetime
from binascii import hexlify
import pytsk3
import pyewf

SUPPORTED_EXTENSIONS = [
    '.pdf', '.txt', '.jpg', '.jpeg', '.png', '.zip', '.rar', '.doc', '.docx',
    '.xls', '.xlsx', '.ppt', '.pptx', '.mp3', '.mp4', '.avi', '.csv', '.log'
]

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Dosya Kurtarma Aracı")
        self.geometry("1000x600")
        self.selected_drive = tk.StringVar()
        self.file_ext_filter = tk.StringVar()
        self.start_date = tk.StringVar()
        self.end_date = tk.StringVar()
        self.e01_path = ""
        self.create_widgets()

    def create_widgets(self):
        frame = ttk.Frame(self)
        frame.pack(pady=10)

        ttk.Label(frame, text="Sürücü:").grid(row=0, column=0)
        drives = [f"{d}:\\" for d in "CDEFGHIJKLMNOPQRSTUVWXYZ" if os.path.exists(f"{d}:\\")]
        self.drive_combo = ttk.Combobox(frame, textvariable=self.selected_drive, values=drives, state="readonly", width=10)
        self.drive_combo.grid(row=0, column=1)
        if drives:
            self.drive_combo.current(0)

        ttk.Button(frame, text="E01 Seç", command=self.select_e01).grid(row=0, column=2, padx=5)

        ttk.Label(frame, text="Filtre (örn: .pdf)").grid(row=1, column=0)
        ttk.Entry(frame, textvariable=self.file_ext_filter, width=10).grid(row=1, column=1)

        ttk.Label(frame, text="Tarih Başlangıç (YYYY-MM-DD):").grid(row=2, column=0)
        ttk.Entry(frame, textvariable=self.start_date).grid(row=2, column=1)

        ttk.Label(frame, text="Tarih Bitiş (YYYY-MM-DD):").grid(row=3, column=0)
        ttk.Entry(frame, textvariable=self.end_date).grid(row=3, column=1)

        ttk.Button(self, text="Disk Tarama", command=self.scan_selected_disk).pack(pady=3)
        ttk.Button(self, text="E01 Tarama", command=self.scan_e01).pack(pady=3)
        ttk.Button(self, text="Geri Dönüşüm Kutusu", command=self.scan_recycle_bin).pack(pady=3)

        columns = ("Dosya Adı", "Uzantı", "Boyut (KB)", "SHA256", "Kaynak")
        self.tree = ttk.Treeview(self, columns=columns, show="headings", height=15)
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=150)
        self.tree.pack(pady=5)

        ttk.Button(self, text="Seçili Dosyayı Önizle", command=self.preview_selected_file).pack(pady=5)
        self.status = ttk.Label(self, text="Hazır", anchor="w")
        self.status.pack(fill="x")

        self.file_data_map = {}

    def select_e01(self):
        path = filedialog.askopenfilename(filetypes=[("E01 Image", "*.E01"), ("All files", "*.*")])
        if path:
            self.e01_path = path
            self.status.config(text=f"E01 seçildi: {os.path.basename(path)}")

    def scan_fs(self, fs, source):
        try:
            self.tree.delete(*self.tree.get_children())
            ext_filter = self.file_ext_filter.get().strip().lower()
            date_start = self.parse_date(self.start_date.get())
            date_end = self.parse_date(self.end_date.get(), end=True)

            file_count = 0
            for dir_entry in fs.open_dir(path="/"):
                try:
                    if not dir_entry.info.meta:
                        continue
                    if not (dir_entry.info.meta.flags & pytsk3.TSK_FS_META_FLAG_UNALLOC):
                        continue

                    name = dir_entry.info.name.name.decode("utf-8", "ignore")
                    ext = os.path.splitext(name)[1].lower()
                    
                    if ext_filter and not name.lower().endswith(ext_filter):
                        continue
                    if not ext_filter and ext not in SUPPORTED_EXTENSIONS:
                        continue

                    meta_time = dir_entry.info.meta.crtime
                    if meta_time:
                        dt = datetime.utcfromtimestamp(meta_time)
                        if (date_start and dt < date_start) or (date_end and dt > date_end):
                            continue

                    if dir_entry.info.meta.size > 1024 * 1024 * 100:
                        continue

                    f = dir_entry.as_file()
                    data = f.read_random(0, dir_entry.info.meta.size)
                    if data:
                        self.log_and_save(name, data, source)
                        file_count += 1
                        self.status.config(text=f"Taranan dosya sayısı: {file_count}")
                        self.update()

                except Exception as e:
                    continue

            self.status.config(text=f"{source} taraması tamamlandı. Toplam {file_count} dosya bulundu.")
            
        except Exception as e:
            self.status.config(text=f"Tarama hatası: {str(e)}")
            messagebox.showerror("Hata", f"Tarama sırasında bir hata oluştu: {str(e)}")

    def log_and_save(self, name, data, source):
        try:
            save_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Kurtarilanlar")
            os.makedirs(save_dir, exist_ok=True)
            
            base_name = os.path.splitext(name)[0]
            ext = os.path.splitext(name)[1]
            counter = 1
            dest_path = os.path.join(save_dir, name)
            while os.path.exists(dest_path):
                dest_path = os.path.join(save_dir, f"{base_name}_{counter}{ext}")
                counter += 1

            with open(dest_path, "wb") as f:
                f.write(data)

            hash_ = sha256(data).hexdigest()
            size_kb = len(data) // 1024
            ext = os.path.splitext(name)[1]
            
            self.tree.insert("", "end", values=(name, ext, size_kb, hash_, source))
            self.file_data_map[name] = data

            log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "log.txt")
            with open(log_path, "a", encoding="utf-8") as log:
                now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                log.write(f"[{now}] {source} | {dest_path} | SHA256: {hash_}\n")

        except Exception as e:
            messagebox.showerror("Hata", f"Dosya kaydedilirken hata oluştu: {str(e)}")

    def preview_selected_file(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Uyarı", "Lütfen bir dosya seçin.")
            return
        name = self.tree.item(selected[0])["values"][0]
        data = self.file_data_map.get(name)
        if data is None:
            return

        win = tk.Toplevel(self)
        win.title("Önizleme")
        tabs = ttk.Notebook(win)
        tabs.pack(expand=True, fill="both")

        hex_view = tk.Text(tabs)
        hex_view.insert("1.0", hexlify(data).decode())
        tabs.add(hex_view, text="HEX")

        text_view = tk.Text(tabs)
        text_view.insert("1.0", data.decode("utf-8", errors="replace"))
        tabs.add(text_view, text="TEXT")

        bin_view = tk.Text(tabs)
        bin_data = ' '.join(f"{byte:08b}" for byte in data[:2048])
        bin_view.insert("1.0", bin_data)
        tabs.add(bin_view, text="BINARY")

    def scan_selected_disk(self):
        try:
            img = pytsk3.Img_Info(self.selected_drive.get().replace("\\", ""))
            fs = pytsk3.FS_Info(img)
            self.scan_fs(fs, "Disk")
        except Exception as e:
            self.status.config(text=f"Disk tarama başarısız: {e}")

    def scan_recycle_bin(self):
        self.tree.delete(*self.tree.get_children())
        
        recycle_paths = [
            "C:\\$Recycle.Bin",
            "C:\\RECYCLER",
            "C:\\RECYCLED"
        ]
        
        file_count = 0
        for recycle_path in recycle_paths:
            if not os.path.exists(recycle_path):
                continue
                
            try:
                sid_dirs = []
                try:
                    sid_dirs = [os.path.join(recycle_path, d) for d in os.listdir(recycle_path)
                              if os.path.isdir(os.path.join(recycle_path, d))]
                except PermissionError:
                    self.status.config(text="Geri dönüşüm kutusuna erişim izni reddedildi.")
                    continue

                for sid in sid_dirs:
                    try:
                        for root, _, files in os.walk(sid):
                            for file in files:
                                if file.startswith('$I'):
                                    continue
                                    
                                ext = os.path.splitext(file)[1].lower()
                                if self.file_ext_filter.get():
                                    if not file.lower().endswith(self.file_ext_filter.get().strip().lower()):
                                        continue
                                elif ext not in SUPPORTED_EXTENSIONS:
                                    continue

                                fpath = os.path.join(root, file)
                                try:
                                    with open(fpath, "rb") as f:
                                        data = f.read()
                                    self.log_and_save(file, data, "RecycleBin")
                                    file_count += 1
                                    self.status.config(text=f"Bulunan dosya sayısı: {file_count}")
                                    self.update()
                                except (PermissionError, FileNotFoundError):
                                    continue
                    except PermissionError:
                        continue

            except Exception as e:
                self.status.config(text=f"Geri dönüşüm kutusu tarama hatası: {str(e)}")
                continue

        final_message = f"Geri dönüşüm kutusu taraması tamamlandı. {file_count} dosya bulundu."
        self.status.config(text=final_message)
        if file_count == 0:
            messagebox.showinfo("Bilgi", "Geri dönüşüm kutusunda kurtarılabilir dosya bulunamadı.")

    def scan_e01(self):
        if not self.e01_path:
            messagebox.showwarning("Uyarı", "Önce bir E01 dosyası seçmelisiniz.")
            return
        try:
            filenames = pyewf.glob(self.e01_path)
            ewf_handle = pyewf.handle()
            ewf_handle.open(filenames)
            img = EWFImgInfo(ewf_handle)
            fs = pytsk3.FS_Info(img)
            self.scan_fs(fs, "E01")
        except Exception as e:
            self.status.config(text=f"E01 tarama başarısız: {e}")

    def parse_date(self, s, end=False):
        try:
            dt = datetime.strptime(s, "%Y-%m-%d")
            if end:
                return dt.replace(hour=23, minute=59, second=59)
            return dt
        except:
            return None

class EWFImgInfo(pytsk3.Img_Info):
    def __init__(self, ewf_handle):
        self._ewf_handle = ewf_handle
        super().__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

    def read(self, offset, size):
        self._ewf_handle.seek(offset)
        return self._ewf_handle.read(size)

    def get_size(self):
        return self._ewf_handle.get_media_size()

if __name__ == "__main__":
    App().mainloop()
