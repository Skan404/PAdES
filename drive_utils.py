import os
import psutil
import sys

# Nazwa pliku klucza na pendrive
KEY_FILENAME = "private_key.enc"

def list_removable_drives():
    """Zwraca listę ścieżek montowania dysków wymiennych (potencjalnych pendrive'ów)."""
    removable_drives = []
    partitions = psutil.disk_partitions(all=False) # all=False próbuje pominąć wirtualne/specjalne
    for p in partitions:
        # Sprawdzanie 'removable' w opcjach montowania (działa dobrze na Linux)
        if 'removable' in p.opts.lower():
             # Sprawdźmy czy ścieżka istnieje i jest katalogiem
            if os.path.isdir(p.mountpoint):
                removable_drives.append(p.mountpoint)
                continue # Przejdź do następnej partycji

        # Dodatkowe sprawdzanie dla Windows (często nie ma 'removable')
        # Sprawdźmy typ systemu plików - FAT/exFAT są częste dla pendrive'ów
        # lub po prostu sprawdzamy czy litera dysku to nie C:
        if sys.platform == "win32":
             # Proste sprawdzenie czy to nie C: i czy ścieżka istnieje
            if p.device.upper().startswith(('A:', 'B:')) or (len(p.device) == 3 and p.device[1:3] == ':\\' and p.device[0].upper() != 'C'):
                 if os.path.isdir(p.mountpoint):
                    removable_drives.append(p.mountpoint)
                    continue

        # Można dodać inne heurystyki specyficzne dla macOS lub bardziej złożone warunki
        # Np. sprawdzanie `p.fstype` pod kątem 'vfat', 'exfat', 'msdos'

    # Usuń duplikaty, jeśli jakieś się pojawiły
    return sorted(list(set(removable_drives)))


def find_key_on_removable_drives():
    """Szuka pliku KEY_FILENAME na wszystkich wymiennych dyskach.
       Zwraca pełną ścieżkę do pierwszego znalezionego pliku lub None."""
    drives = list_removable_drives()
    for drive_path in drives:
        potential_key_path = os.path.join(drive_path, KEY_FILENAME)
        if os.path.isfile(potential_key_path):
            print(f"Znaleziono plik klucza: {potential_key_path}")
            return potential_key_path
    print("Nie znaleziono pliku klucza na żadnym wymiennym nośniku.")
    return None

# Testowe wywołanie (uruchomi się tylko przy bezpośrednim wywołaniu skryptu)
if __name__ == "__main__":
    print("Wykryte dyski wymienne:")
    drives = list_removable_drives()
    if drives:
        for d in drives:
            print(f"- {d}")
    else:
        print("Nie znaleziono żadnych dysków wymiennych.")

    key_path = find_key_on_removable_drives()
    if key_path:
        print(f"\nZnaleziono plik klucza w: {key_path}")
    else:
        print("\nPlik klucza nie został znaleziony.")