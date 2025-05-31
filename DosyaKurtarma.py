import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from hashlib import sha256
from datetime import datetime
from binascii import hexlify
import pytsk3
import pyewf
import threading
import queue
import concurrent.futures
import atexit
import gc
import logging
from utils import MemoryOptimizer

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

SUPPORTED_EXTENSIONS = [
    '.pdf', '.txt', '.jpg', '.jpeg', '.png', '.zip', '.rar', '.doc', '.docx',
    '.xls', '.xlsx', '.ppt', '.pptx', '.mp3', '.mp4', '.avi', '.csv', '.log'
]

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Dosya Kurtarma Aracı")
        self.geometry("1200x800")
        
        self._scanning_lock = threading.RLock()
        self.scanning = False
        self.scan_thread = None
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=4)
        
        # UI değişkenleri
        self.selected_drive = tk.StringVar()
        self.file_ext_filter = tk.StringVar()
        self.start_date = tk.StringVar()
        self.end_date = tk.StringVar()
        self.progress_var = tk.DoubleVar()
        self.e01_path = ""
        self.scan_queue = queue.Queue()
        self.file_data_map = {}
        
        # UI oluştur
        self.create_widgets()
        
        # Cleanup kaydı
        self.protocol("WM_DELETE_WINDOW", self._on_closing)
        atexit.register(self._cleanup)

    def _cleanup(self):
        """Kaynakları temizler"""
        try:
            # Taramayı durdur
            if self.scanning:
                self.stop_scan()
            
            # Executor kapat
            if hasattr(self, 'executor'):
                self.executor.shutdown(wait=False)
            
            # Bellek temizle
            gc.collect()
        except Exception as e:
            logger.error(f"Cleanup error: {e}")

    def _on_closing(self):
        """Pencere kapatma"""
        try:
            self._cleanup()
        finally:
            self.destroy()

    def create_widgets(self):
        """UI bileşenlerini oluşturur"""
        main_frame = ttk.Frame(self)
        main_frame.pack(padx=20, pady=20, fill="both", expand=True)

        # Sol panel - Kontrol alanı
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(side="left", padx=(0, 20), fill="y")

        # Sürücü seçimi
        drive_frame = ttk.LabelFrame(control_frame, text="Sürücü Seçimi", padding=10)
        drive_frame.pack(fill="x", pady=(0, 10))

        drives = [f"{d}:\\" for d in "CDEFGHIJKLMNOPQRSTUVWXYZ" if os.path.exists(f"{d}:\\")]
        self.drive_combo = ttk.Combobox(drive_frame, textvariable=self.selected_drive, 
                                      values=drives, state="readonly", width=15)
        self.drive_combo.pack(side="left", padx=5)
        if drives:
            self.drive_combo.current(0)

        ttk.Button(drive_frame, text="E01 Seç", command=self.select_e01).pack(side="left", padx=5)

        # Filtre alanı
        filter_frame = ttk.LabelFrame(control_frame, text="Filtreleme", padding=10)
        filter_frame.pack(fill="x", pady=10)

        ttk.Label(filter_frame, text="Uzantı:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        ttk.Entry(filter_frame, textvariable=self.file_ext_filter, width=15).grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(filter_frame, text="Başlangıç (YYYY-MM-DD):").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        ttk.Entry(filter_frame, textvariable=self.start_date, width=15).grid(row=1, column=1, padx=5, pady=5)

        ttk.Label(filter_frame, text="Bitiş (YYYY-MM-DD):").grid(row=2, column=0, padx=5, pady=5, sticky="w")
        ttk.Entry(filter_frame, textvariable=self.end_date, width=15).grid(row=2, column=1, padx=5, pady=5)

        # Tarama butonları
        scan_frame = ttk.LabelFrame(control_frame, text="Tarama İşlemleri", padding=10)
        scan_frame.pack(fill="x", pady=10)

        self.btn_disk = ttk.Button(scan_frame, text="Disk Tarama", command=lambda: self.start_scan("disk"))
        self.btn_disk.pack(fill="x", pady=2)
        
        self.btn_e01 = ttk.Button(scan_frame, text="E01 Tarama", command=lambda: self.start_scan("e01"))
        self.btn_e01.pack(fill="x", pady=2)
        
        self.btn_recycle = ttk.Button(scan_frame, text="Geri Dönüşüm Kutusu", command=lambda: self.start_scan("recycle"))
        self.btn_recycle.pack(fill="x", pady=2)
        
        self.btn_stop = ttk.Button(scan_frame, text="Taramayı Durdur", command=self.stop_scan)
        self.btn_stop.pack(fill="x", pady=2)

        # Sağ panel - Sonuç alanı
        result_frame = ttk.Frame(main_frame)
        result_frame.pack(side="left", fill="both", expand=True)

        # Treeview
        columns = ("Dosya Adı", "Uzantı", "Boyut (KB)", "SHA256", "Kaynak")
        self.tree = ttk.Treeview(result_frame, columns=columns, show="headings", height=20)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(result_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        # Treeview kolonları
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=150)
        
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Alt panel
        bottom_frame = ttk.Frame(main_frame)
        bottom_frame.pack(side="bottom", fill="x", pady=10)

        ttk.Button(bottom_frame, text="Seçili Dosyayı Önizle", 
                  command=self.preview_selected_file).pack(side="left", padx=5)
        
        ttk.Button(bottom_frame, text="Sonuçları Temizle", 
                  command=self.clear_results).pack(side="left", padx=5)
        
        self.status = ttk.Label(bottom_frame, text="Hazır", anchor="w")
        self.status.pack(side="left", fill="x", expand=True, padx=5)

        # Progress bar
        self.progress = ttk.Progressbar(bottom_frame, mode='determinate', 
                                      variable=self.progress_var)
        self.progress.pack(side="bottom", fill="x", padx=5, pady=5)

    def select_e01(self):
        """E01 dosyası seçimi"""
        path = filedialog.askopenfilename(
            title="E01 Image Dosyası Seç",
            filetypes=[("E01 Image", "*.E01"), ("All files", "*.*")]
        )
        if path:
            self.e01_path = path
            self.status.config(text=f"E01 seçildi: {os.path.basename(path)}")

    def clear_results(self):
        """Sonuçları temizler"""
        self.tree.delete(*self.tree.get_children())
        self.file_data_map.clear()
        self.status.config(text="Sonuçlar temizlendi")

    def start_scan(self, scan_type):
        """Tarama işlemini başlatır"""
        with self._scanning_lock:
            if self.scanning:
                messagebox.showwarning("Uyarı", "Zaten bir tarama işlemi devam ediyor.")
                return
            
            try:
                self.scanning = True
                self._update_button_states(False)
                self.memory_optimizer = MemoryOptimizer()
                
                self.scan_thread = threading.Thread(
                    target=self._run_scan,
                    args=(scan_type,),
                    daemon=True
                )
                self.scan_thread.start()
                
            except Exception as e:
                self.scanning = False
                self._update_button_states(True)
                self.memory_optimizer = None
                logger.error(f"Scan start error: {e}")
                messagebox.showerror("Hata", f"Tarama başlatılamadı: {str(e)}")

    def stop_scan(self):
        """Tarama işlemini durdurur"""
        with self._scanning_lock:
            if not self.scanning:
                return
                
            self.scanning = False
            self.status.config(text="Tarama durduruluyor...")
            
            if self.scan_thread and self.scan_thread.is_alive():
                try:
                    self.scan_thread.join(timeout=2.0)
                except Exception as e:
                    logger.error(f"Thread join error: {e}")
                finally:
                    self.scan_thread = None
            
            self.progress_var.set(0)
            self.status.config(text="Tarama durduruldu")
            self._update_button_states(True)

    def _update_button_states(self, enabled):
        """Buton durumlarını günceller"""
        state = "normal" if enabled else "disabled"
        self.btn_disk.config(state=state)
        self.btn_e01.config(state=state)
        self.btn_recycle.config(state=state)

    def _run_scan(self, scan_type: str):
        """Tarama işlemini yönetir"""
        handlers = {
            "disk": self._scan_disk,
            "e01": self._scan_e01,
            "recycle": self._scan_recycle
        }
        
        try:
            handler = handlers.get(scan_type)
            if not handler:
                raise ValueError(f"Geçersiz tarama tipi: {scan_type}")
            
            handler()
            
        except Exception as e:
            error_msg = f"Tarama hatası: {str(e)}"
            self.after(0, lambda: self.status.config(text=error_msg))
            self.after(0, lambda: messagebox.showerror("Hata", error_msg))
            logger.error(f"Scan error: {e}")
            
        finally:
            with self._scanning_lock:
                self.scanning = False
                self.after(0, lambda: self.progress_var.set(0))
                self.after(0, lambda: self._update_button_states(True))

    def _scan_disk(self):
        """Disk tarama işlemini gerçekleştirir"""
        drive = self.selected_drive.get().replace("\\", "")
        if not drive or not os.path.exists(f"{drive}\\"):
            raise ValueError("Geçersiz sürücü seçimi")
        
        try:
            img = pytsk3.Img_Info(drive)
            fs = pytsk3.FS_Info(img)
            self.scan_fs(fs, "Disk")
        except Exception as e:
            logger.error(f"Disk scan error: {e}")
            raise

    def _scan_e01(self):
        """E01 tarama işlemini gerçekleştirir"""
        if not self.e01_path:
            raise ValueError("Önce bir E01 dosyası seçmelisiniz.")
        
        try:
            filenames = pyewf.glob(self.e01_path)
            ewf_handle = pyewf.handle()
            ewf_handle.open(filenames)
            img = EWFImgInfo(ewf_handle)
            fs = pytsk3.FS_Info(img)
            self.scan_fs(fs, "E01")
        except Exception as e:
            logger.error(f"E01 scan error: {e}")
            raise

    def _scan_recycle(self):
        """Geri dönüşüm kutusu tarama işlemini gerçekleştirir"""
        self.after(0, lambda: self.tree.delete(*self.tree.get_children()))
        
        recycle_paths = [
            "C:\\$Recycle.Bin",
            "C:\\RECYCLER", 
            "C:\\RECYCLED"
        ]
        
        file_count = 0
        
        for recycle_path in recycle_paths:
            if not os.path.exists(recycle_path) or not self.scanning:
                continue
                
            try:
                for root, dirs, files in os.walk(recycle_path):
                    if not self.scanning:
                        break
                        
                    for file in files:
                        if not self.scanning:
                            break
                        
                        # $I ile başlayan info dosyalarını atla
                        if file.startswith('$I'):
                            continue
                        
                        # Uzantı filtresi
                        ext = os.path.splitext(file)[1].lower()
                        ext_filter = self.file_ext_filter.get().strip().lower()
                        
                        if ext_filter:
                            if not file.lower().endswith(ext_filter):
                                continue
                        elif ext not in SUPPORTED_EXTENSIONS:
                            continue
                        
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, "rb") as f:
                                data = f.read()
                            
                            self.log_and_save(file, data, "RecycleBin")
                            file_count += 1
                            
                            # UI güncelleme
                            self.after(0, lambda c=file_count: self.status.config(
                                text=f"Bulunan dosya sayısı: {c}"
                            ))
                            
                        except (PermissionError, FileNotFoundError, OSError):
                            continue
                            
            except PermissionError:
                continue
        
        final_message = f"Geri dönüşüm kutusu taraması tamamlandı. {file_count} dosya bulundu."
        self.after(0, lambda: self.status.config(text=final_message))
        
        if file_count == 0:
            self.after(0, lambda: messagebox.showinfo(
                "Bilgi", "Geri dönüşüm kutusunda kurtarılabilir dosya bulunamadı."
            ))

    def scan_fs(self, fs, source):
        """Dosya sistemi taraması"""
        self.after(0, lambda: self.progress_var.set(0))
        self.after(0, lambda: self.tree.delete(*self.tree.get_children()))
        
        try:
            ext_filter = self.file_ext_filter.get().strip().lower()
            date_start = self.parse_date(self.start_date.get())
            date_end = self.parse_date(self.end_date.get(), end=True)

            file_count = 0
            processed_count = 0

            def process_file(dir_entry):
                if not self.scanning:
                    return None
                
                try:
                    if not dir_entry.info.meta:
                        return None
                    if not (dir_entry.info.meta.flags & pytsk3.TSK_FS_META_FLAG_UNALLOC):
                        return None

                    name = dir_entry.info.name.name.decode("utf-8", "ignore")
                    if not name or name in ['.', '..']:
                        return None
                        
                    ext = os.path.splitext(name)[1].lower()
                    
                    # Uzantı filtresi
                    if ext_filter and not name.lower().endswith(ext_filter):
                        return None
                    if not ext_filter and ext not in SUPPORTED_EXTENSIONS:
                        return None

                    # Tarih filtresi
                    if dir_entry.info.meta.crtime:
                        dt = datetime.utcfromtimestamp(dir_entry.info.meta.crtime)
                        if (date_start and dt < date_start) or (date_end and dt > date_end):
                            return None

                    # Boyut kontrolü (max 100MB)
                    if dir_entry.info.meta.size > 1024 * 1024 * 100:
                        return None

                    # Dosya içeriğini oku
                    try:
                        f = dir_entry.as_file()
                        data = f.read_random(0, dir_entry.info.meta.size)
                        if data:
                            return (name, data)
                    except Exception:
                        return None
                    
                except Exception:
                    return None
                
                return None

            # Paralel işleme
            futures = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
                try:
                    for dir_entry in fs.open_dir(path="/"):
                        if not self.scanning:
                            break
                        futures.append(executor.submit(process_file, dir_entry))
                    
                    total_futures = len(futures)
                    for future in concurrent.futures.as_completed(futures):
                        if not self.scanning:
                            break
                            
                        processed_count += 1
                        
                        # Progress güncelleme
                        if total_futures > 0:
                            progress = (processed_count / total_futures) * 100
                            self.after(0, lambda p=progress: self.progress_var.set(p))
                        
                        result = future.result()
                        if result:
                            name, data = result
                            self.log_and_save(name, data, source)
                            file_count += 1
                            
                            # Status güncelleme
                            self.after(0, lambda c=file_count: self.status.config(
                                text=f"Taranan dosya sayısı: {c}"
                            ))
                            
                except Exception as e:
                    logger.error(f"FS scan executor error: {e}")

            final_message = f"{source} taraması tamamlandı. Toplam {file_count} dosya bulundu."
            self.after(0, lambda: self.status.config(text=final_message))
            
        except Exception as e:
            error_msg = f"Tarama hatası: {str(e)}"
            self.after(0, lambda: self.status.config(text=error_msg))
            logger.error(f"FS scan error: {e}")
            raise

    def log_and_save(self, name, data, source):
        """Dosyayı kaydeder ve loglar"""
        try:
            # Kayıt dizini oluştur
            save_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Kurtarilanlar")
            os.makedirs(save_dir, exist_ok=True)
            
            # Dosya adı çakışması kontrolü
            base_name = os.path.splitext(name)[0]
            ext = os.path.splitext(name)[1]
            counter = 1
            dest_path = os.path.join(save_dir, name)
            
            while os.path.exists(dest_path):
                dest_path = os.path.join(save_dir, f"{base_name}_{counter}{ext}")
                counter += 1

            # Dosyayı kaydet
            with open(dest_path, "wb") as f:
                f.write(data)

            # Hash hesapla
            hash_value = sha256(data).hexdigest()
            size_kb = len(data) // 1024
            
            # TreeView'e ekle (UI thread'de çalıştır)
            self.after(0, lambda: self.tree.insert("", "end", values=(name, ext, size_kb, hash_value, source)))
            self.file_data_map[name] = data

            # Log kaydet
            log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "log.txt")
            with open(log_path, "a", encoding="utf-8") as log:
                now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                log.write(f"[{now}] {source} | {dest_path} | SHA256: {hash_value}\n")

        except Exception as e:
            error_msg = f"Dosya kaydedilirken hata: {str(e)}"
            self.after(0, lambda: messagebox.showerror("Hata", error_msg))
            logger.error(f"Save error: {e}")

    def preview_selected_file(self):
        """Seçili dosyanın önizlemesini gösterir"""
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Uyarı", "Lütfen bir dosya seçin.")
            return
            
        name = self.tree.item(selected[0])["values"][0]
        data = self.file_data_map.get(name)
        if data is None:
            messagebox.showwarning("Uyarı", "Dosya verisi bulunamadı.")
            return

        # Önizleme penceresi
        preview_window = tk.Toplevel(self)
        preview_window.title(f"Önizleme: {name}")
        preview_window.geometry("800x600")
        preview_window.configure(bg="#f0f0f0")

        # Notebook widget
        notebook = ttk.Notebook(preview_window)
        notebook.pack(expand=True, fill="both", padx=10, pady=10)

        # Farklı görünüm türleri
        views = [
            ("HEX", "Hexadecimal Görünüm", lambda d: hexlify(d[:4096]).decode()),
            ("TEXT", "Metin Görünüm", lambda d: d[:4096].decode("utf-8", errors="replace")),
            ("BINARY", "Binary Görünüm", lambda d: ' '.join(f"{byte:08b}" for byte in d[:1024]))
        ]

        for view_type, title, formatter in views:
            frame = ttk.Frame(notebook, padding=10)
            
            # Text widget ve scrollbar
            text_widget = tk.Text(frame, wrap="none", font=("Consolas", 10))
            scrollbar_y = ttk.Scrollbar(frame, orient="vertical", command=text_widget.yview)
            scrollbar_x = ttk.Scrollbar(frame, orient="horizontal", command=text_widget.xview)
            
            text_widget.configure(yscrollcommand=scrollbar_y.set, xscrollcommand=scrollbar_x.set)
            
            try:
                content = formatter(data)
                text_widget.insert("1.0", content)
            except Exception as e:
                text_widget.insert("1.0", f"Görüntüleme hatası: {str(e)}")
            
            text_widget.config(state="disabled")  # Read-only
            
            # Grid layout
            text_widget.grid(row=0, column=0, sticky="nsew")
            scrollbar_y.grid(row=0, column=1, sticky="ns")
            scrollbar_x.grid(row=1, column=0, sticky="ew")
            
            frame.grid_columnconfigure(0, weight=1)
            frame.grid_rowconfigure(0, weight=1)
            
            notebook.add(frame, text=title)

    def parse_date(self, date_str, end=False):
        """Tarih string'ini datetime objesine çevirir"""
        if not date_str.strip():
            return None
            
        try:
            dt = datetime.strptime(date_str, "%Y-%m-%d")
            if end:
                return dt.replace(hour=23, minute=59, second=59)
            return dt
        except ValueError:
            return None


class EWFImgInfo(pytsk3.Img_Info):
    """E01 image dosyaları için wrapper sınıfı"""
    def __init__(self, ewf_handle):
        self._ewf_handle = ewf_handle
        super().__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

    def read(self, offset, size):
        self._ewf_handle.seek(offset)
        return self._ewf_handle.read(size)

    def get_size(self):
        return self._ewf_handle.get_media_size()


if __name__ == "__main__":
    try:
        app = App()
        app.mainloop()
    except Exception as e:
        logger.error(f"Application error: {e}")
        messagebox.showerror("Kritik Hata", f"Uygulama başlatılamadı: {str(e)}")