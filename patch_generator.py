from idaapi import *
from PySide import QtGui, QtCore
from idaapi import PluginForm
import idc

class findPatch(QtGui.QMainWindow):
    def __init__(self, parent=None):
        QtGui.QMainWindow.__init__(self, parent)    # We create the principal window
        self.resize(1000,600)                       # We resize the principal window
        self.setFont(QtGui.QFont("Verdana"))        # We change the font of principal window
        self.setWindowTitle("Patch Generator")      # We rename the principal window

        wind = QtGui.QDesktopWidget().screenGeometry()   # widget screenGeometry returns the geometry of the screen with index screen
        size = self.geometry()
        self.move((wind.width()-size.width())/2, (wind.height()-size.height())/2)

        self.tabWidget = QtGui.QTabWidget(self)
        self.tabWidget.setGeometry(0,20,1000,600-40)

        self.windows = QtGui.QWidget(self.tabWidget) # We've got a windows will contain our lits, button etc

        self.windows.setPalette(QtGui.QPalette(QtGui.QColor("white")))
        self.windows.setAutoFillBackground(True)

        toPatchBytes = self.searchPatch()

        self.read = QtGui.QPlainTextEdit(toPatchBytes, self)
        self.read.setStyleSheet("color: rgb(0, 0, 102); font-size : 15px;")
        self.read.resize(300,480)
        self.read.move(150, 60)
        #self.read = QtGui.QPlainTextEdit.setReadOnly(self.read,True)
        self.patchValue = QtGui.QPlainTextEdit("", self)
        self.patchValue.setStyleSheet("color: rgb(0, 0, 102); font-size : 15px;")
        self.patchValue.resize(300,480)
        self.patchValue.move(500, 60)

        self.buttonCatch = QtGui.QPushButton("Patch", self)
        self.buttonCatch.move(600,545)
        self.buttonCatch.clicked.connect(self.catch)

    def searchPatch(self):
        previous_file_offset = 0
        continous_byte = 0
        patchBytes = {}

        for seg_start in Segments():
            for ea in range(seg_start, SegEnd(seg_start) ):
                if isLoaded(ea):
                    byte = Byte(ea)
                    original_byte = GetOriginalByte(ea)
                    if byte != original_byte:
                        file_offset = get_fileregion_offset( ea )
                        if previous_file_offset+1 == file_offset:
                            continous_byte += 1
                            patchBytes['0x%08x'%(file_offset-continous_byte)] += '%02x'%byte
                        else:
                            continous_byte = 0
                            patchBytes['0x%08x'%(file_offset)] = '%02x'%byte
                        previous_file_offset = file_offset

        toPatchBytes = ''
        for patchByte in patchBytes:
            toPatchBytes += patchByte+':'+patchBytes[patchByte]+'\n'
        return toPatchBytes[:-1]

    def catch(self):
        #self.read.setReadOnly(False)
        newPatch = QtGui.QPlainTextEdit.toPlainText(self.patchValue)
        for patch in newPatch.split('\n'):
            if len(patch) != 0:
                (offset, hexbytes) = tuple(patch.split(':'))
                addr = get_fileregion_ea(int(offset, 16))
                _bytes = hexbytes.decode("hex")
                c = 0
                for byte in _bytes:
                    idc.PatchByte(addr+c, ord(byte))
                    c+=1
        QtGui.QPlainTextEdit.setPlainText(self.read, self.searchPatch())
        QtGui.QPlainTextEdit.setPlainText(self.patchValue, "")

    def closeEvent(self, event):
        event.accept()

'''
view = findPatch()
view.show()
'''

# This class allow us to create a plugin ida (put this inside c:/programme/ida/plugin)
class pluginFindPatch(plugin_t):

    flags = PLUGIN_KEEP
    comment = "This plugin transform your current idb into a list of patch for webPatcher"

    help = "Just press Alt-F8 and copy paste the result"
    wanted_name = "Patch generator"
    wanted_hotkey = "Alt-F8"

    def __init__(self):
        self.view = None

    def init(self):
        return PLUGIN_KEEP

    def run(self, arg):
        self.view = findPatch()
        self.view.show()

    def term(self):
        msg("Patch generator exit\n")


def PLUGIN_ENTRY():
    return pluginFindPatch()
