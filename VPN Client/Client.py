import os.path
import os
import sys
# import LoginCheck
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.Qt import *
from PyQt5 import uic
from PyQt5.QtGui import *
import subprocess
import time
import webbrowser
import socket

url = "https://schfido.com:44334/"
chrome_path = 'C:\Program Files\Google\Chrome\Application\chrome.exe'

# UI파일 연결
form_class = uic.loadUiType(r"D:\2021 FIDO\VPN Client\FIDO_VPN_Client.ui")[0]


# 화면을 띄우는데 사용되는 Class 선언
# 메인 UI
class WindowClass(QMainWindow, form_class):
    dialog = None

    def __init__(self):
        super().__init__()
        self.setupUi(self)
        self.setWindowTitle("VPN Service")
        self.setWindowIcon(QIcon(r'D:\2021 FIDO\VPN Client\Logo.png'))
        self.threadclass = Threadclass()
        self.FidoAuthentication.clicked.connect(self.FidoAuthenticationFunction)  # 버튼 객체 함수 선언
        self.ConnectVPN.clicked.connect(self.ConnectVPNFuction)
        self.threadclass.login_status.connect(self.update_button)
        # self.Check.clicked.connect(self.CheckAuthentication)
        self.ConnectVPN.setEnabled(False)

    # 파이도 인증 버튼 함수
    def FidoAuthenticationFunction(self):
        # 크롬 존재 여부 확인
        if os.path.isfile(chrome_path):
            webbrowser.open(url)  # 크롬 브라우저가 존재하면 웹 브라우저 열기
            self.threadclass.command = "Authentication"  # 스레드 내 조건문에 필요한 조건 선언
            self.threadclass.start()  # 스레드 내 인증 루틴 실행
        else:
            ChormeDownload(self)  # 크롬 브라우저가 존재하지 않으면 안내창으로 이동

    @pyqtSlot(bool)
    def update_button(self, status):
        if status is True:
            self.ConnectVPN.setEnabled(True)
        elif status is False:
            self.ConnectVPN.setEnabled(False)

    # VPN 연결 버튼
    def ConnectVPNFuction(self):
        VPNinfo(self)


# VPN 정보 입력 Dialog
class VPNinfo(QDialog):
    def __init__(self, parent):
        super(VPNinfo, self).__init__(parent)
        self.setWindowTitle("VPN Service")
        self.threadclass = Threadclass()  # 스레드 함수 선언
        option_ui = r'D:\2021 FIDO\VPN Client\VPNInfo.ui'
        uic.loadUi(option_ui, self)
        self.show()

        # 저장 버튼 클릭시 데이터 저장
        self.Save.clicked.connect(self.savedata)
        self.Connect.clicked.connect(self.Connectvpn)
        self.Disconnect.clicked.connect(self.DisconnectVPN)
        self.threadclass.status.connect(self.update_status)

    # 데이터 저장, 해당 버튼 클릭 시 값 변경 금지
    def savedata(self):
        Servername = (self.Input_ServerName.text())
        Serveraddress = (self.Input_ServerAddress.text())
        VPNtype = (self.Select_VPNType.currentText())
        L2tpPsk = (self.Input_L2tpPsk.text())
        Username = (self.Input_UserName.text())
        Password = (self.Input_Password.text())

        info = [Servername, Serveraddress, VPNtype, L2tpPsk, Username, Password]
        # 값 변경 금지 설정
        self.Input_ServerName.setEnabled(False)
        self.Input_ServerAddress.setEnabled(False)
        self.Select_VPNType.setEnabled(False)
        self.Input_L2tpPsk.setEnabled(False)
        self.Input_UserName.setEnabled(False)
        self.Input_Password.setEnabled(False)
        return info

    # VPN 연결
    def Connectvpn(self):
        self.threadclass.command = "Connect"  # 스레드 내 조건문에 필요한 조건 선언
        self.threadclass.info = self.savedata()  # savedata()에서 변수 받아오기
        self.threadclass.start()  # 스레드 시작

    # VPN 연결 해제
    def DisconnectVPN(self):
        self.threadclass.command = "Disconnect"  # 스레드 내 조건문에 필요한 조건 선언
        self.threadclass.info = self.savedata()  # savedata()에서 변수 받아오기
        self.threadclass.start()  # 스레드 시작

    @pyqtSlot(str)
    def update_status(self, status):
        self.Status.setText(status)


# 크롬 다운로드
class ChormeDownload(QDialog):
    def __init__(self, parent):
        super(ChormeDownload, self).__init__(parent)
        self.setWindowTitle("VPN Service")
        option_ui2 = r'D:\2021 FIDO\VPN Client\chromedownload.ui'
        uic.loadUi(option_ui2, self)
        self.show()


# 스레드 클래스 생성
class Threadclass(QThread):
    login_status = pyqtSignal(bool)
    status = pyqtSignal(str)

    def __init__(self, parent=None):
        super(Threadclass, self).__init__(parent)
        self.command = ""  # 조건 선언 변수
        self.info = []  # VPN 구성 및 연결에 필요한 정보
          # 인증 성공 유무에 따른 메시지 박스 출력

    def run(self):
        if self.command == "Authentication":  # 소켓 통신을 통한 인증 요청
            HOST = '27.117.251.37'  # IPv4
            PORT = 44335  # Port
            start = time.time()
            while True:
                try:
                    # 시간 체크
                    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    client_socket.connect((HOST, PORT))
                    client_socket.sendall('Authentication Request'.encode())  # Send message to server
                    data = client_socket.recv(1024)
                    if "Succeed" in repr(data.decode()):
                        client_socket.close()
                        self.login_status.emit(True)
                        break
                    elif "Failed" in repr(data.decode()):
                        client_socket.close()
                        self.login_status.emit(False)
                        break
                    if time.time() - start > 60:
                        client_socket.close()
                        break
                except:
                    pass
            print()
        elif self.command == "Connect":  # 연결 명령이면
            if self.info[2] == "L2TP":
                SaveCommand = """PowerShell.exe -Command "Add-VpnConnection -Name """ + self.info[0] + """ -ServerAddress """ + self.info[1] + """ -TunnelType """ + self.info[2] + """ -L2tpPsk """ + self.info[3]  # VPN 구성 명령
                subprocess.run(SaveCommand, input='y', text=True, shell=True)  # 명령 실행, key 인코딩 문제로  input 'y' 추가
                ConnectCommand = """PowerShell.exe -Command rasdial """ + self.info[0] + """ """ + self.info[4] + """ """ + self.info[5]  # VPN 연결 실행 명령
                self.status.emit(subprocess.getstatusoutput(ConnectCommand)[1])  # 연결 명령 실행 후 결과 클라이언트 창에 표시

            else:
                SaveCommand = """PowerShell.exe -Command "Add-VpnConnection -Name """ + self.info[0] + """ -ServerAddress """ + self.info[1] + """ -TunnelType """ + self.info[2]  # VPN 구성 명령
                subprocess.run(SaveCommand, shell=True)  # 명령 실행
                ConnectCommand = """PowerShell.exe -Command rasdial """ + self.info[0] + """ """ + self.info[4] + """ """ + self.info[5]  # VPN 연결 실행 명령
                self.status.emit(subprocess.getstatusoutput(ConnectCommand)[1])  # 연결 명령 실행 후 결과 클라이언트 창에 표시

        elif self.command == "Disconnect":  # 연결 해제 명령이면
            DisconnectCommand = """Powershell.exe -Command rasdial """ + self.info[0] + """ /DISCONNECT """  # 연결 해제 명령
            subprocess.run(DisconnectCommand, shell=True)  # 명령 실행


if __name__ == "__main__":
    # QApplication : 프로그램을 실행시켜주는 클래스
    app = QApplication(sys.argv)
    # MainWindow의 인스턴스 생성
    myWindow = WindowClass()
    # 프로그램 화면을 보여주는 코드
    myWindow.show()
    # 프로그램을 이벤트루프로 진입시키는(프로그램을 작동시키는) 코드
    app.exec_()