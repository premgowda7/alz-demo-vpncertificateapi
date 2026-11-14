import os
import glob


class Static:

    def __init__(self):

        self.__keysDir = "/etc/openvpn/easy-rsa/keys"
        self.__ccd = "/etc/openvpn/ccd"

        self.TUN_IP = os.environ['TUN_IP']
        print("TUN_IP:", self.TUN_IP)
        self.TUN_IP_PREFIX = self.TUN_IP.split('.')[0] + '.' + self.TUN_IP.split('.')[1] + '.'

    def readKey(self):
        logDirList = os.listdir(self.__keysDir)
        return logDirList

    def checkOldclient(self):
        file_list = glob.glob(os.path.join(os.getcwd(), "/etc/openvpn/ccd", "*"))

        old_ip_list = []

        for file_path in file_list:
            with open(file_path) as f_input:
                old_ip_list.append(f_input.read().split(' ')[1])

        return old_ip_list

    def createFiles(self, logDirList, oldIP):
        list_0 = [6, 11, 16, 21, 26, 31, 36, 41, 46, 51, 56, 61, 66, 71, 76, 81, 86, 91, 96,
                  101, 106, 111, 116, 121, 126, 131, 136, 141, 146, 151, 156, 161, 166, 171, 176, 181, 186, 191, 196,
                  201, 206, 211, 216, 221, 226, 231, 236, 241, 246, 251]
        list_1 = [1, 6, 11, 16, 21, 26, 31, 36, 41, 46, 51, 56, 61, 66, 71, 76, 81, 86, 91, 96,
                  101, 106, 111, 116, 121, 126, 131, 136, 141, 146, 151, 156, 161, 166, 171, 176, 181, 186, 191, 196,
                  201, 206, 211, 216, 221, 226, 231, 236, 241, 246, 251]

        name = ""
        count = 0
        for i in range(0, 255):
            if i == 0:
                for j in list_0:
                    if not self.TUN_IP_PREFIX + str(i) + "." + str(j) in oldIP:
                        for clientName in logDirList:
                            if ".key" in clientName:
                                actualName = clientName.split('.')[0]
                                if not os.path.exists(self.__ccd + "/" + actualName):
                                    with (open(self.__ccd + "/" + actualName, 'w') as static):
                                        count += 1
                                        # cmd = f"ifconfig-push {self.TUN_IP_PREFIX}" + str(i) + "." + str(j) + f" {self.TUN_IP_PREFIX}" + str(i) + "." + str(j + 1)
                                        static.write(f"ifconfig-push {self.TUN_IP_PREFIX}" + str(i) + "." + str(j) + f" {self.TUN_IP_PREFIX}" + str(i) + "." + str(j + 1))
                                        break

                        name = clientName
            else:
                for j in list_1:
                    if not self.TUN_IP_PREFIX + str(i) + "." + str(j) in oldIP:
                        for clientName in logDirList:
                            if ".key" in clientName:
                                actualName = clientName.split('.')[0]
                                if not os.path.exists(self.__ccd + "/" + actualName):
                                    with open(self.__ccd + "/" + actualName, 'w') as static:
                                        count += 1
                                        # cmd = f"ifconfig-push {self.TUN_IP_PREFIX}" + str(i) + "." + str(j) + f" {self.TUN_IP_PREFIX}" + str(i) + "." + str(j + 1)
                                        static.write(f"ifconfig-push {self.TUN_IP_PREFIX}" + str(i) + "." + str(j) + f" {self.TUN_IP_PREFIX}" + str(i) + "." + str(j + 1))
                                        break

                        name = clientName
            if name == logDirList[-1]:
                break

        tclient = 0
        for client in logDirList:
            if ".key" in client:
                tclient += 1


if __name__ == "__main__":
    obj = Static()
    logDirList = obj.readKey()
    oldIP = obj.checkOldclient()
    obj.createFiles(logDirList, oldIP)
