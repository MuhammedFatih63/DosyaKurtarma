# Dosya Kurtarma Aracı

Bu uygulama, silinmiş dosyaları kurtarmak için geliştirilmiş bir adli bilişim aracıdır.

## Sistem Gereksinimleri

- Windows 7/8/10/11 (64-bit)
- Python 3.8 veya üzeri
- 4GB RAM (minimum)
- Yönetici hakları

## Bağımlılıklar

Aşağıdaki Python paketlerinin kurulu olması gerekmektedir:

```bash
pip install pytsk3==20230219
pip install pyewf-python==3.7.2
pip install tkinter
```

## Kurulum Adımları

1. [Python](https://www.python.org/downloads/) sitesinden Python 3.8 veya üzeri sürümü indirin ve kurun
   - Kurulum sırasında "Add Python to PATH" seçeneğini işaretleyin

2. Microsoft Visual C++ 14.0 veya üzeri gereklidir. İndirmek için:
   - [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/)
   - Kurulum sırasında "C++ Build Tools" seçeneğini seçin

3. Windows SDK gereklidir. İndirmek için:
   - [Windows SDK](https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/)

4. Bağımlılıkları yükleyin:
   ```bash
   pip install -r requirements.txt
   ```

## Çalıştırma

1. Komut istemcisini yönetici olarak açın
2. Uygulama klasörüne gidin:
   ```bash
   cd "c:\Users\Kullanici\Desktop\Dosya Kurtarma"
   ```
3. Uygulamayı çalıştırın:
   ```bash
   python DosyaKurtarma.py
   ```

## Özellikler

- Disk tarama
- E01 imaj dosyası tarama
- Geri dönüşüm kutusu tarama
- Dosya uzantısına göre filtreleme
- Tarih aralığına göre filtreleme
- HEX/TEXT/BINARY önizleme
- SHA256 hash değeri hesaplama
- Detaylı log kaydı

## Desteklenen Dosya Türleri

- Dökümanlar: .pdf, .doc, .docx, .xls, .xlsx, .ppt, .pptx
- Resimler: .jpg, .jpeg, .png
- Arşivler: .zip, .rar
- Medya: .mp3, .mp4, .avi
- Diğer: .txt, .csv, .log

## Hata Çözümleri

1. "pythonXX.dll bulunamadı" hatası:
   - Python'u kaldırıp yeniden kurun
   - PATH değişkenini kontrol edin

2. "Visual C++ 14.0 gerekli" hatası:
   - Visual Studio Build Tools'u yeniden kurun

3. "pytsk3 modülü yüklenemiyor" hatası:
   - Visual C++ Build Tools'u yeniden kurun
   - Windows SDK'yı yeniden kurun

## Güvenlik Notları

- Uygulamayı yönetici olarak çalıştırın
- Sistem diskinde kullanırken dikkatli olun
- Önemli veriler için önce yedek alın

## Lisans

Bu proje MIT lisansı altında dağıtılmaktadır.
