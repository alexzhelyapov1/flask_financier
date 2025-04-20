import os

# 1. Список путей до файлов (относительные пути)
# Замените этот список своими путями к файлам
file_paths = [
    "app.py",
    "db_api.py",
    "templates/accounting_history.html",
    "templates/add_record.html",
    "templates/admin_select_user.html",
    "templates/base.html",
    "templates/dashboard.html",
    "templates/edit_location.html",
    "templates/edit_sphere.html",
    "templates/index.html",
    "templates/locations.html",
    "templates/login.html",
    "templates/register.html",
    "templates/spheres.html",
]

# Имя выходного файла
output_filename = "context_promt.txt"

# Кодировка для чтения и записи файлов (рекомендуется UTF-8)
encoding = 'utf-8'

# print(f"Начинаю объединение файлов в {output_filename}...")

# 2. Открываем выходной файл для записи ('w' - перезапишет файл, если он существует)
try:
    with open(output_filename, 'w', encoding=encoding) as outfile:
        # Проходим по каждому пути в списке
        for file_path in file_paths:
            # print(f"Обработка: {file_path}")
            # Записываем разделитель и путь к файлу
            outfile.write(f"--- File: {file_path} ---\n")

            # Проверяем, существует ли файл
            if os.path.exists(file_path):
                try:
                    # Открываем текущий файл для чтения
                    with open(file_path, 'r', encoding=encoding) as infile:
                        # Читаем все содержимое файла
                        content = infile.read()
                        # Записываем содержимое в выходной файл
                        outfile.write(content)
                        # Добавляем перевод строки в конце содержимого файла, если его нет
                        if not content.endswith('\n'):
                            outfile.write('\n')

                except FileNotFoundError:
                    # Эта ветка не должна сработать из-за os.path.exists,
                    # но оставим на всякий случай
                    warning_msg = "[!] ОШИБКА: Файл не найден (хотя os.path.exists его видел?).\n"
                    print(f"  {warning_msg.strip()}")
                    outfile.write(warning_msg)
                except UnicodeDecodeError:
                    warning_msg = f"[!] ОШИБКА: Не удалось прочитать файл {file_path} с кодировкой {encoding}. Попробуйте другую кодировку или проверьте файл.\n"
                    print(f"  {warning_msg.strip()}")
                    outfile.write(warning_msg)
                except Exception as e:
                    # Ловим другие возможные ошибки при чтении файла
                    error_msg = f"[!] ОШИБКА: Не удалось прочитать файл {file_path}. Причина: {e}\n"
                    print(f"  {error_msg.strip()}")
                    outfile.write(error_msg)
            else:
                # Если файл не найден
                not_found_msg = "[!] Файл не найден по указанному пути.\n"
                print(f"  Предупреждение: Файл {file_path} не найден, пропускаю.")
                outfile.write(not_found_msg)

            # Добавляем пару пустых строк для лучшего разделения между файлами
            outfile.write("\n\n")

    # print("-" * 30)
    # print(f"Готово! Все найденные файлы были объединены в файл: {output_filename}")

except IOError as e:
    print(f"Ошибка при открытии или записи в выходной файл {output_filename}: {e}")
except Exception as e:
    print(f"Произошла непредвиденная ошибка: {e}")