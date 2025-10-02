# Анализ зависания Krita из-за утечек памяти в libgif

```bash
krita poc_copies/poc_140.gif # именно этот файл вызвал странное поведение:

>>> krita.ui: path= «gimp_testing/poc_copies/poc_140.gif" 
>>> krita.plugins: mimeTypeForFile(). 
>>> QMimeDatabase returned "image/gif" for "gimp_testing/poc_copies/poc_140.gif" 
>>> krita.ui: "gimp_testing/poc_copies/poc_140.gif" type: "image/gif"
>>> qt.qpa.events.reader: [heap] 0
>>> qt.qpa.events.reader: [heap] 1
>>> qt.qpa.events.reader: [heap] 2 
>>> qt.qpa.events.reader: [heap] 3

```

### Анализ зависания через GDB
```bash
# Подключились к процессу Krita
gdb --pid $(pidof krita)
```

### Стек вызовов при зависании
```
(gdb) bt
#0  __GI___libc_read (nbytes=16384, buf=0x558c15f027e8, fd=43) at ../sysdeps/unix/sysv/linux/read.c:26
#1  __GI___libc_read (fd=43, buf=0x558c15f027e8, nbytes=16384) at ../sysdeps/unix/sysv/linux/read.c:24
#2  0x00007f473260dfad in ?? () from /lib/x86_64-linux-gnu/libQt5Core.so.5
#3  0x00007f47325d9a4b in QFileDevice::readData(char*, long long) () from /lib/x86_64-linux-gnu/libQt5Core.so.5
#4  0x00007f47325e2555 in QIODevicePrivate::read(char*, long long, bool) () from /lib/x86_64-linux-gnu/libQt5Core.so.5
#5  0x00007f46c0d6dbc0 in ?? () from /usr/lib/x86_64-linux-gnu/kritaplugins/kritagifimport.so
#6  0x00007f46c0979ffc in DGifGetRecordType () from /lib/x86_64-linux-gnu/libgif.so.7
#7  0x00007f46c0d6de9d in ?? () from /usr/lib/x86_64-linux-gnu/kritaplugins/kritagifimport.so
#8  0x00007f46c0d6d4f3 in ?? () from /usr/lib/x86_64-linux-gnu/kritaplugins/kritagifimport.so
#9  0x00007f47346e3b3d in KisImportExportManager::doImport(QString const&, QSharedPointer<KisImportExportFilter>) ()
   from /lib/x86_64-linux-gnu/libkritaui.so.18
#10 0x00007f47346e5d75 in KisImportExportManager::convert(KisImportExportManager::Direction, QString const&, QString const&, QString const&, bool, KisPinnedSharedPtr<KisPropertiesConfiguration>, bool, bool) () from /lib/x86_64-linux-gnu/libkritaui.so.18
#11 0x00007f47346e700a in KisImportExportManager::importDocument(QString const&, QString const&) () from /lib/x86_64-linux-gnu/libkritaui.so.18
#12 0x00007f47346cf68a in KisDocument::openFile() () from /lib/x86_64-linux-gnu/libkritaui.so.18
#13 0x00007f47346d01d9 in KisDocument::openPathInternal(QString const&) () from /lib/x86_64-linux-gnu/libkritaui.so.18
#14 0x00007f47346d5859 in KisDocument::openPath(QString const&, QFlags<KisDocument::OpenFlag>) () from /lib/x86_64-linux-gnu/libkritaui.so.18
#15 0x00007f47346f3d6d in KisMainWindow::openDocumentInternal(QString const&, QFlags<KisMainWindow::OpenFlag>) () from /lib/x86_64-linux-gnu/libkritaui.so.18
#16 0x00007f47346f43c6 in KisMainWindow::openDocument(QString const&, QFlags<KisMainWindow::OpenFlag>) () from /lib/x86_64-linux-gnu/libkritaui.so.18
#17 0x00007f47346bc510 in KisApplication::start(KisApplicationArguments const&) () from /lib/x86_64-linux-gnu/libkritaui.so.18
#18 0x0000558c026ffe31 in ?? ()
#19 0x00007f473224524a in __libc_start_call_main (main=main@entry=0x558c026fd4c0, argc=argc@entry=3, argv=argv@entry=0x7ffec55464b8)
    at ../sysdeps/nptl/libc_start_call_main.h:58
#20 0x00007f4732245305 in __libc_start_main_impl (main=0x558c026fd4c0, argc=3, argv=argv@entry=0x7ffec55464b8, init=<optimized out>, fini=<optimized out>, 
    rtld_fini=<optimized out>, stack_end=0x7ffec55464a8) at ../csu/libc-start.c:360
#21 0x0000558c02701271 in ?? ()
```

## Анализ зависания

### Ключевые моменты стека:

1. **#6: `DGifGetRecordType()`** - функция libgif застряла в бесконечном цикле чтения
2. **#5: `kritagifimport.so`** - Krita GIF импортер вызывает libgif
3. **#4-1: Qt I/O** - Qt пытается читать файл через `QFileDevice::readData()`

### Причина зависания: poc_140.gif

```c
00000000: 47 49 46 38 39 61 01 00 01 00 80 00 00 00 00 00  GIF89a..........
00000010: ff ff ff 21 74 00 02 00 ff 74 74 74              ...!t....ttt
```

Формально корректен в заголовке, но:

- содержит неизвестный Extension Label (0x74), 
- нет конца файла (Trailer), 
- поток обрывается, 

что ведет к зависанию при чтении (read() блокируется в ожидании байтов, которых нет)