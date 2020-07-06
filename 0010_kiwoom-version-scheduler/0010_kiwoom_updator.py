import subprocess
import win32gui
import win32con
import win32api
import time
import sys
import logging
import logging.handlers

path_work           = "D:/myPython/kiwoom/0010_kiwoom-version-scheduler/"
path_work_py_full   = sys._getframe().f_code.co_filename
path_work_py        = path_work_py_full.split("/")[len(path_work_py_full.split("/"))-1].split(".")[0]
path_work_logfile   = path_work + path_work_py + '_log.log'
path_login_py       = path_work + "0011_kiwoom_updator_login.py"
path_account        = path_work + "0012_kiwoom_updator_account.txt"

# logger 인스턴스를 생성 및 로그 레벨 설정
logger = logging.getLogger(path_work_py)
logger.setLevel(logging.DEBUG)

# formmater 생성
formatter = logging.Formatter(u'[%(levelname)s|%(filename)s:%(lineno)s] %(asctime)s > %(message)s')


# file max size를 10MB로 설정
file_max_bytes = 10 * 1024 * 1024

fileHandler = logging.handlers.RotatingFileHandler(filename=path_work_logfile, encoding = "utf-8", maxBytes=file_max_bytes, backupCount=10)

# fileHandler와 StreamHandler를 생성
# fileHandler = logging.FileHandler(path_work + path_work_py + '_log.log')
streamHandler = logging.StreamHandler()

# handler에 fommater 세팅
fileHandler.setFormatter(formatter)
streamHandler.setFormatter(formatter)

# Handler를 logging에 추가
logger.addHandler(fileHandler)
logger.addHandler(streamHandler)

def open_login_window(password, cert_password, secs=60):
    """
    OpenAPI+를 사용해서 로그인 윈도우를 실행한 후 로그인을 시도하는 함수
    :param password: 비밀번호
    :param cert_password: 공인인증 비밀번호
    :param secs: 로그인 완료까지 대기할 시간
    :return:
    """
    cmd = "d:/Anaconda3/python.exe " + path_login_py
    subprocess.Popen(cmd, shell=True)
    time.sleep(5)

    if(try_manual_login(password, cert_password)) :
        for i in range(secs):
            logger.info("로그인 완료 대기 중 : " + str(secs-i))
            time.sleep(1)
    else :
        logger.info('자동로그인 중')


def window_enumeration_handler(hwnd, top_windows):
    top_windows.append((hwnd, win32gui.GetWindowText(hwnd)))


def enum_windows():
    windows = []
    win32gui.EnumWindows(window_enumeration_handler, windows)
    return windows


def find_window(caption):
    hwnd = win32gui.FindWindow(None, caption)

    if hwnd == 0:
        windows = enum_windows()
        for handle, title in windows:
            if caption in title:
                hwnd = handle
                break

    return hwnd


def enter_keys(hwnd, password):
    win32gui.SetForegroundWindow(hwnd)
    win32api.Sleep(100)

    for c in password:
        win32api.SendMessage(hwnd, win32con.WM_CHAR, ord(c), 0)
        win32api.Sleep(100)


def click_button(btn_hwnd):
    win32api.PostMessage(btn_hwnd, win32con.WM_LBUTTONDOWN, 0, 0)
    win32api.Sleep(100)
    win32api.PostMessage(btn_hwnd, win32con.WM_LBUTTONUP, 0, 0)
    win32api.Sleep(100)


def set_auto_on(password):
    hwnd = find_window("계좌비밀번호")

    # 비밀번호등록
    edit = win32gui.GetDlgItem(hwnd, 0xCA)
    enter_keys(edit, password)
    win32api.Sleep(100)
    button_register_all = win32gui.GetDlgItem(hwnd, 0xCE)
    click_button(button_register_all)

    # 체크박스 체크
    checkbox = win32gui.GetDlgItem(hwnd, 0xCD)
    checked = win32gui.SendMessage(checkbox, win32con.BM_GETCHECK)
    if not checked:
        win32gui.SendMessage(checkbox, win32con.BM_SETCHECK, 0)

    # 닫기 버튼 클릭
    button= win32gui.GetDlgItem(hwnd, 0x01)
    click_button(button)


def get_window_list():
    def callback(hwnd, hwnd_list: list):
        title = win32gui.GetWindowText(hwnd)
        if win32gui.IsWindowEnabled(hwnd) and win32gui.IsWindowVisible(hwnd) and title:
            hwnd_list.append((title, hwnd))
        return True
    output = []
    win32gui.EnumWindows(callback, output)
    return output



def set_auto_off(cert_window_name):
    logger.info('called cert_window_name : ' + cert_window_name)
    try:
        hwnd = find_window(cert_window_name)
        # logger.info('win32gui.GetDlgCtrlID() : ' + win32gui.GetDlgCtrlID())
        # 체크박스 해제
        checkbox = win32gui.GetDlgItem(hwnd, 0xCD)
        checked = win32gui.SendMessage(checkbox, win32con.BM_GETCHECK)
        if checked:
            win32gui.SendMessage(checkbox, win32con.BM_SETCHECK, 0)

        # 닫기 버튼 클릭
        button= win32gui.GetDlgItem(hwnd, 0x01)
        click_button(button)
    except:
        logger.info("auto 해제 실패")
        sys.exit()

    logger.info("auto 해제 후 대기 중")
    time.sleep(5)

def try_manual_login(password, cert_password):
    # i = 1
    hwnd = find_window("Open API Login")
    # while hwnd == 0 and i != 21:
    #     logger.info("Wait more update(" + str(i) + "/20)")
    #     i = i + 1
    #     time.sleep(5)
    if hwnd == 0:
        # logger.info("please try next time update")
        return False
    logger.info("manual login window hwnd value : " + str(hwnd))
    edit_pass = win32gui.GetDlgItem(hwnd, 0x3E9)
    edit_cert = win32gui.GetDlgItem(hwnd, 0x3EA)
    button = win32gui.GetDlgItem(hwnd, 0x1)

    # 비밀번호 입력
    try:
        enter_keys(edit_pass, password)
    except:
        pass

    # 인증비밀번호입력
    try:
        enter_keys(edit_cert, cert_password)
    except:
        pass

    # 버튼 클릭
    try:
        click_button(button)
    except:
        pass

    return True


def close_window(title, secs=5):
    hwnd = find_window(title)
    if hwnd !=0:
        win32gui.PostMessage(hwnd, win32con.WM_CLOSE, 0, 0)
        time.sleep(secs)


def execute_version_process():
    try:
        close_window("opstarter", secs=120)         # 버전처리 메시지 창이 있는 경우 120초 대기
        close_window("업그레이드 확인")
    except:
        pass


def close_login_window():
    title = "Python 로그인"
    try:
        time.sleep(2)
        close_window("계좌비밀번호")
        close_window(title)
        time.sleep(2)
    except:
        logger.info("error: close login window")


if __name__ == "__main__":
    # 비밀번호
    f = open(path_account, 'r')
    lines = f.readlines()
    for idx in range(len(lines)):
        # 비밀번호류는 별도로 저장해두어 관리가 용이하도록한다.
        lines[idx] = lines[idx].split(':')[1].rstrip('\n')
        # logger.info(lines[idx])
    f.close()
    # logger.info(lines)
    password = lines[1]
    password2 = lines[2]
    cert_password = ""

    # 로그인 -> Auto 해제 -> 창닫기
    open_login_window(password, cert_password)
    logger.info("\n".join("{: 9d} {}".format(h, t) for t, h in get_window_list()))
    cert_window_name = ""
    for t, h in get_window_list():
        # 버전에 따라 창 이름이 달라지므로 특정 이름이 들어간 창을 선택할수 있게 한다.
        if '계좌비밀번호' in t:
            cert_window_name = t
    set_auto_off(cert_window_name)
    close_login_window()

    # 로그인
    open_login_window(password, cert_password)
    close_login_window()

    # 버전처리 수행
    execute_version_process()

    # 로그인 -> Auto 재등록 -> 창닫기
    open_login_window(password, cert_password)
    set_auto_on(password2)
    close_login_window()




