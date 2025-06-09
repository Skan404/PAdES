## @file drive_utils.py
## @brief Moduł pomocniczy do wykrywania pendrive'ów i lokalizacji pliku klucza.

import os
import psutil
import sys

## @var KEY_FILENAME
## @brief Nazwa pliku klucza prywatnego, którego szukamy na pendrive.
KEY_FILENAME = "private_key.pem"

## @brief Zwraca listę ścieżek montowania dysków wymiennych (potencjalnych pendrive'ów).
## @return Lista ścieżek montowania (np. ['D:\\', 'E:\\'] na Windows lub ['/media/usb1', '/media/usb2'] na Linux).
def list_removable_drives():
    removable_drives = []
    partitions = psutil.disk_partitions(all=False) # all=False pomija wirtualne spacje
    for p in partitions:
        if 'removable' in p.opts.lower():
            if os.path.isdir(p.mountpoint):
                removable_drives.append(p.mountpoint)
                continue

        # Sprawdzamy typ systemu plików - FAT/exFAT
        # lub po prostu sprawdzamy czy litera dysku to nie C:
        if sys.platform == "win32":
            if p.device.upper().startswith(('A:', 'B:')) or (len(p.device) == 3 and p.device[1:3] == ':\\' and p.device[0].upper() != 'C'):
                if os.path.isdir(p.mountpoint):
                    removable_drives.append(p.mountpoint)
                    continue

    # usun duplikaty
    return sorted(list(set(removable_drives))

)

## @brief Szuka pliku KEY_FILENAME na wszystkich wymiennych dyskach.
## @return Pełna ścieżka do pierwszego znalezionego pliku lub None jeśli nie znaleziono.
def find_key_on_removable_drives():
    drives = list_removable_drives()
    for drive_path in drives:
        potential_key_path = os.path.join(drive_path, KEY_FILENAME)
        if os.path.isfile(potential_key_path):
            print(f"Znaleziono plik klucza: {potential_key_path}")
            return potential_key_path
    print("Nie znaleziono pliku klucza na żadnym wymiennym nośniku.")
    return None
