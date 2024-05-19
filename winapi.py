import ctypes
import json
from ctypes import wintypes, windll

# Constants
PROCESS_QUERY_INFORMATION = 0x0400
#начение 0x0400 указывает на конкретный флаг, который используется в функциях Windows API, таких как OpenProcess. Этот флаг разрешает доступ для запроса информации о процессе, такой как приоритет процесса, его базовый адрес и другие атрибуты.
PROCESS_VM_READ = 0x0010
#Эта константа определяет право доступа к процессу, которое позволяет читать память процесса. Значение 0x0010 указывает на конкретный флаг, используемый в функциях Windows API, таких как ReadProcessMemory. Этот флаг разрешает доступ для чтения памяти, выделенной процессу.
MAX_PATH = 260
#Эта константа определяет максимальную длину пути в Windows, включая нулевой терминатор. Значение 260 является стандартом в Windows для максимальной длины полного пути к файлу. Этот стандарт включает букву диска, все папки в пути и имя файла с расширением.

# Define GUID structure
class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", wintypes.BYTE * 8)
    ]

# Define necessary structures and functions
class WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),   # Размер структуры в байтах.
        ("pcwszFilePath", wintypes.LPCWSTR),     # Указатель на строку, содержащую путь к файлу.
        ("hFile", wintypes.HANDLE),  # Дескриптор файла. Обычно не используется и устанавливается в None.
        ("pgKnownSubject", ctypes.POINTER(GUID))    # Указатель на GUID известного субъекта. Обычно не используется и устанавливается в None.
    ]

class WINTRUST_DATA(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),   # Размер структуры в байтах.
        ("pPolicyCallbackData", wintypes.LPVOID),   # Указатель на данные обратного вызова политики. Обычно не используется.
        ("pSIPClientData", wintypes.LPVOID),    # Указатель на данные клиента SIP. Обычно не используется.
        ("dwUIChoice", wintypes.DWORD), # Уровень взаимодействия с пользователем (например, без интерфейса).
        ("fdwRevocationChecks", wintypes.DWORD),    # Типы проверок аннулирования сертификатов.
        ("dwUnionChoice", wintypes.DWORD),  # Тип данных для проверки (в данном случае, файл).
        ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),  # Указатель на структуру WINTRUST_FILE_INFO.
        ("dwStateAction", wintypes.DWORD),  # Действие состояния (например, проверка или закрытие).
        ("hWVTStateData", wintypes.HANDLE),  # Состояние данных проверки доверия.
        ("pwszURLReference", wintypes.LPCWSTR),  # Указатель на строку URL для проверки. Обычно не используется.
        ("dwProvFlags", wintypes.DWORD),    # Флаги настройки проверки.
        ("dwUIContext", wintypes.DWORD),    # Контекст пользовательского интерфейса. Обычно не используется.
        ("pSignatureSettings", wintypes.LPVOID) # Указатель на настройки подписи. Обычно не используется.
    ]

WINTRUST_ACTION_GENERIC_VERIFY_V2 = GUID(
    0x00AAC56B, 0xCD44, 0x11d0, (0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))   # Это фиксированный идентификатор, который Microsoft определила для стандартной проверки цифровой подписи.

WTD_UI_NONE = 2 # Эта константа указывает, что функция WinVerifyTrust не должна отображать никакой пользовательский интерфейс (UI).
WTD_REVOKE_NONE = 0 # Эта константа указывает, что не нужно выполнять проверку аннулирования сертификатов.
WTD_CHOICE_FILE = 1 # Эта константа указывает, что объектом проверки является файл.
WTD_STATEACTION_VERIFY = 0x00000001 # Эта константа указывает, что функция WinVerifyTrust должна выполнить проверку доверия.
WTD_STATEACTION_CLOSE = 0x00000002 # Эта константа указывает, что нужно закрыть состояние проверки.
WTD_REVOCATION_CHECK_NONE = 0x00000010 # Эта константа отключает проверку аннулирования сертификатов.

# Load necessary libraries
psapi = windll.psapi # Получения списка идентификаторов всех текущих процессов (EnumProcesses). Получения имени и пути исполняемого файла для конкретного процесса (GetModuleFileNameExW).
kernel32 = windll.kernel32 # Предоставляет широкий набор функций для управления памятью, процессами, потоками, файлами и т. д.
wintrust = windll.wintrust # Проверки цифровой подписи файла (WinVerifyTrust).

def verify_digital_signature(file_path): 
    file_info = WINTRUST_FILE_INFO( # Путь к файлу который нужно проверить
        cbStruct=ctypes.sizeof(WINTRUST_FILE_INFO), 
        pcwszFilePath=file_path 
    )

    trust_data = WINTRUST_DATA( # Содержит настройки для проверки, такие как отсутствие пользовательского интерфейса, отключение проверки аннулирования сертификатов и указание, что проверяется файл.
        cbStruct=ctypes.sizeof(WINTRUST_DATA), # Устанавливает размер структуры WINTRUST_DATA.
        dwUIChoice=WTD_UI_NONE, # Указывает, что не должно быть пользовательского интерфейса (без отображения диалоговых окон).
        fdwRevocationChecks=WTD_REVOKE_NONE, # Указывает, что проверки отзыва не требуются.
        dwUnionChoice=WTD_CHOICE_FILE, # Указывает, что будет проверяться файл.
        pFile=ctypes.pointer(file_info), # Указывает на структуру WINTRUST_FILE_INFO, которая содержит информацию о файле.
        dwStateAction=WTD_STATEACTION_VERIFY, # Указывает, что нужно выполнить проверку.
        dwProvFlags=WTD_REVOCATION_CHECK_NONE # Указывает, что проверки отзыва не требуются.
    )

    result = wintrust.WinVerifyTrust( 
        wintypes.HANDLE(0),
        ctypes.byref(WINTRUST_ACTION_GENERIC_VERIFY_V2), 
        ctypes.byref(trust_data)
    )

    trust_data.dwStateAction = WTD_STATEACTION_CLOSE # WTD_STATEACTION_CLOSE выполняется для завершения процесса проверки доверия, который был начат предыдущим вызовом.
    wintrust.WinVerifyTrust(
        wintypes.HANDLE(0),
        ctypes.byref(WINTRUST_ACTION_GENERIC_VERIFY_V2),
        ctypes.byref(trust_data)
    )
 # После того как проверка завершена, чтобы избежать утечки ресурсов и правильно завершить процесс проверки, необходимо выполнить второй вызов WinVerifyTrust с dwStateAction, установленным в WTD_STATEACTION_CLOSE. Это сообщает системе, что нужно закрыть состояние проверки, освободив любые выделенные ресурсы.
    return result == 0

def get_process_info():
    # Выделяем память под массив для идентификаторов процессов
    process_ids = (wintypes.DWORD * 1024)() # Выделяем массив из 1024 элементов типа DWORD (unsigned long)
    cb = ctypes.sizeof(process_ids)  # Размер массива в байтах
    bytes_returned = wintypes.DWORD()  # Переменная для хранения количества байт, возвращенных функцией EnumProcesses
    
    # Вызываем функцию EnumProcesses, чтобы получить идентификаторы всех процессов
    if not psapi.EnumProcesses(ctypes.byref(process_ids), cb, ctypes.byref(bytes_returned)):
        raise ctypes.WinError()
    
   
    num_processes = bytes_returned.value // ctypes.sizeof(wintypes.DWORD)
    #Когда мы делим bytes_returned.value на ctypes.sizeof(wintypes.DWORD), мы получаем количество элементов типа DWORD в массиве process_ids, что соответствует количеству процессов.
  
    processes = []
    # Создаем список для хранения информации о процессах

    # Перебираем все полученные идентификаторы процессов
    for i in range(num_processes):
         # Получаем идентификатор процесса из массива
        process_id = process_ids[i]

          # Пропускаем идентификаторы процессов, равные 0 (неподходящие)
        if process_id == 0:
            continue

             # Открываем дескриптор процесса для получения дополнительной информации
        h_process = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, process_id)

          # Если не удалось открыть дескриптор процесса, пропускаем процесс
        if not h_process:
            continue


        # Выделяем память для хранения пути к исполняемому файлу процесса
        exe_path = (wintypes.WCHAR * MAX_PATH)()

         # Получаем полный путь к исполняемому файлу процесса
        if psapi.GetModuleFileNameExW(h_process, None, exe_path, MAX_PATH):

             # Преобразуем путь к строковому типу
            exe_path_str = exe_path.value

            # Проверяем цифровую подпись исполняемого файла
            is_trusted = verify_digital_signature(exe_path_str)


             # Добавляем информацию о процессе в список
            processes.append({
                "ProcessID": process_id,
                "ExecutablePath": exe_path_str,
                "DigitalSignatureTrusted": is_trusted
            })

         # Закрываем дескриптор процесса
        kernel32.CloseHandle(h_process)
    
    # Возвращаем список информации о процессах
    return processes

def save_to_json(data, filename):
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=4)

if __name__ == "__main__":
    process_info = get_process_info()
    save_to_json(process_info, "processes_info.json")
    print("Process information saved to processes_info.json")
