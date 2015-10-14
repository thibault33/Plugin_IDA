from idaapi import *
import idc
import idautils
import re
import string
from PySide import QtGui, QtCore
from idaapi import PluginForm
import sys


# This function allow to find byte if they're not original
def find_changed_bytes():

    changed_bytes = list()

    for seg_start in Segments():
        for ea in range(seg_start, SegEnd(seg_start) ):
            if isLoaded(ea):
                byte = Byte(ea)
                original_byte = GetOriginalByte(ea)
                if byte != original_byte:
                    changed_bytes.append( (ea, byte, original_byte) )
                    print ea

    return changed_bytes

# This funciton allow to patch the file
def patch_file(data, changed_bytes):

    for ea, byte, original_byte in changed_bytes:
        print '%08x: %02x original(%02x)' % (ea, byte, original_byte)

        file_offset = idaapi.get_fileregion_offset( ea )

        original_char = chr( original_byte )
        char = chr( byte )

        if data[ file_offset ] == original_char:
            data[ file_offset ] = char

    patched_file = idc.AskFile( 1, '*.*', 'Choose new file')
    if patched_file:
        with file(patched_file, 'wb') as f:
            f.write( ''.join( data ) )

class patch(QtGui.QMainWindow):
    def __init__(self, parent=None):
        QtGui.QMainWindow.__init__(self, parent)    # We create the principal window
        self.resize(1000,600)                       # We resize the principal window
        self.setFont(QtGui.QFont("Verdana"))        # We change the font of principal window
        self.setWindowTitle("Find and change binary")               # We rename the principal window
        self.patchedAddr = 0                        # We create a variable inside the principal windows so we use self
        self.containLeaveAndPrologue = {}           # We create a dict will contain address we want to retrieve
        self.containPrologue = []                   # We create a list will contain prologue with sub esp,
        self.containLeave = []                      # We create a list will contain epilogues with leave
        self.liste = []                             # We create a list will contain all function name of a binary

        wind = QtGui.QDesktopWidget().screenGeometry()   # widget screenGeometry returns the geometry of the screen with index screen
        size = self.geometry()
        self.move((wind.width()-size.width())/2, (wind.height()-size.height())/2)
        menubar = self.menuBar()                    # We create a menu bar
        file_ = menubar.addMenu("menu")             # We add a menu bar will be name menu

        self.menuLeave = QtGui.QAction("Leave", self, shortcut=QtGui.QKeySequence.Close,
                                    statusTip="Leave application", triggered=self.close) # Inside our menu we create shortcuts close
                                                                                         # Go to def close() to see action
        self.menuSave = QtGui.QAction( "&Save", self, shortcut=QtGui.QKeySequence.Save,
                                    statusTip="Save the document to disk", triggered=self.main) # Inside our menu we create shortcuts save
                                                                                                # Go to def main() to see action
        file_.addAction(self.menuLeave) # We triggers our funciton menuLeave
        file_.addAction(self.menuSave)  # We triggers our funciton saveAct

        self.tabWidget = QtGui.QTabWidget(self)
        self.tabWidget.setGeometry(0,20,1000,600-40)

        self.windows = QtGui.QWidget(self.tabWidget) # We've got a windows will contain our lits, button etc

        self.tabWidget.addTab(self.windows, "List") # We create this to have a name for our liste

        self.windows.setPalette(QtGui.QPalette(QtGui.QColor("white")))
        self.windows.setAutoFillBackground(True)

        self.centralWindows = QtGui.QTabWidget(self)
        self.centralWindows.resize(800,490)
        self.centralWindows.move(170, 50)
        self.centralLabel = QtGui.QLabel("Make Key_Down to begin :"+"\n"+"\n"+"\n"+"You can use key_Up and Key_Down to choose a function"+"\n"+"\n"+"You can use Key_Shift to add 10 to ESP"+"\n"+"\n"+"You can use Key_ctrl to sub 10 to ESP", self)
        self.centralLabel.setGeometry(380, 130, 420, 300)
        self.centralLabel.setStyleSheet('''color: rgb(0, 0, 102); font-size: 14px;''')
        self.leave = QtGui.QPushButton("Leave", self.windows) # We create a button to leave the app
        self.leave.move(918, 510)
        self.leave.clicked.connect(self.close)

        self.nameFunction() # We call the function

    def nameFunction(self) :
        ea = ScreenEA() # We get the segment's starting address
        for function_ea in Functions(SegStart(ea), SegEnd(ea)): # this loop is to find prologue with Sub esp,
            functionName = GetFunctionName(function_ea) # We get the names function into function_ea
            addr = function_ea
            f_end = FindFuncEnd(function_ea)
            while addr < f_end:
                operation = GetDisasm(addr) # Whith GetDisasm we see operations of address
                if re.compile('sub').search(operation) and re.compile('esp,').search(operation):
                    self.liste.append(functionName) # We add name function into our liste created previously
                    self.list = QtGui.QListWidget(self.windows) # We create a list with Qt
                    self.list.resize(150,538)
                    self.list.move(-1, -1)
                    self.list.addItems(self.liste) # We add elements of our liste inside the Qt list
                    self.list.itemClicked.connect(self.clickList) # We connect the Qt list to the def clickList
                    self.list.show()
                    Nfirst = NextHead(addr)     # We create 6 variable will contain add we want, 3 before and after our SUB
                    Nsecond = NextHead(Nfirst)  # -------------------------------------------------------------------------
                    Nthird = NextHead(Nsecond)  # -------------------------------------------------------------------------
                    Pfirst = PrevHead(addr)     # -------------------------------------------------------------------------
                    Psecond = PrevHead(Pfirst)  # -------------------------------------------------------------------------
                    Pthird = PrevHead(Psecond)  # -------------------------------------------------------------------------
                    self.containPrologue=[Pthird, Psecond, Pthird, addr,Nfirst,Nsecond,Nthird]
                    self.containLeaveAndPrologue[functionName] = {'addrPrologue': self.containPrologue, 'original': operation} # original will be use to see the original SUB value if you got a mistake
                    break
                addr = NextHead(addr) # NextHead go to head address to head address. For exemple we go to 0x01 to 0x07 instead of 0x01, 0x02, 0x03 ...

        for function_ea in Functions(SegStart(ea), SegEnd(ea)): # this loop is the same but we go to the other side to find epilogue with Leave
            functionName = GetFunctionName(function_ea)
            f_beg = function_ea
            addr = FindFuncEnd(function_ea)
            while addr > f_beg:
                operation = GetDisasm(addr)
                if re.compile('leave').search(operation):
                    Pfirst = PrevHead(addr)
                    Psecond = PrevHead(Pfirst)
                    Pthird = PrevHead(Psecond)
                    Nfirst = NextHead(addr)
                    Nsecond = NextHead(Nfirst)
                    Nthird = NextHead(Nsecond)
                    self.containLeave=[Nthird, Nsecond, Nfirst, addr,Pfirst,Psecond,Pthird]
                    self.containLeaveAndPrologue[functionName]['PrevLeave'] = self.containLeave
                    break
                addr = PrevHead(addr)

    def clickList(self, item):
        self.secondWindow = QtGui.QTabWidget(self) #It's the right window
        self.secondWindow.resize(800,490)
        self.secondWindow.move(170, 50)
        self.leaveItem = QtGui.QPushButton("X", self.secondWindow) #We create the leave Button inside the secondWindow
        self.leaveItem.move(770, 2)
        self.leaveItem.resize(25,25)
        self.leaveItem.clicked.connect(self.secondWindow.close)
        self.changeValue = QtGui.QPushButton("Sub esp + 0x10", self) # We create the button will add 0x10 to esp
        self.changeValue.clicked.connect(self.change) # We connect the button to def change
        self.changeValue.setGeometry(490, 450, 150, 30)
        self.changeValue.move(750, 505)
        self.valueFirst = QtGui.QPushButton("Sub esp - 0x10", self) # We create the button will sub 0x10 to esp
        self.valueFirst.clicked.connect(self.coreValue) # We connect the button to def coreValue
        self.valueFirst.setGeometry(490, 450, 150, 30)
        self.valueFirst.move(230, 505)
        self.ButtonNext = QtGui.QPushButton("Next Function", self) # We create the button will go to next function
        self.ButtonNext.move(600,505)
        self.ButtonNext.clicked.connect(self.nextItem) # We connect the button to def prevItem
        self.ButtonNext.show()
        self.ButtonPrev = QtGui.QPushButton("Prev Function", self) # We create the button will go to previous function
        self.ButtonPrev.move(430,505)
        self.ButtonPrev.clicked.connect(self.prevItem) # We connect the button to def prevItem
        self.ButtonPrev.show()
        subPatch = []
        leavePatch = []
        for function in self.containLeaveAndPrologue.keys(): # We travel our dictionary
            if function == item.text():  # if function name == name of item
                self.subLabel = QtGui.QLabel("Original Sub Value: "+self.containLeaveAndPrologue[function]['original'], self.secondWindow) # This to see the origal value
                self.subLabel.move(190,10)
                self.subLabel.setStyleSheet('''color: rgb(41, 146, 69); font-size: 24px;''')
                renderSub = ''
                renderSub+=GetDisasm(self.containLeaveAndPrologue[function]['addrPrologue'][0])+"\n"
                renderSub+=GetDisasm(self.containLeaveAndPrologue[function]['addrPrologue'][1])+"\n"
                renderSub+=GetDisasm(self.containLeaveAndPrologue[function]['addrPrologue'][2])+"\n"
                renderSub+=GetDisasm(self.containLeaveAndPrologue[function]['addrPrologue'][3])+"\n"
                renderSub+=GetDisasm(self.containLeaveAndPrologue[function]['addrPrologue'][4])+"\n"
                renderSub+=GetDisasm(self.containLeaveAndPrologue[function]['addrPrologue'][5])+"\n"
                renderSub+=GetDisasm(self.containLeaveAndPrologue[function]['addrPrologue'][6])+"\n"
                # self.Sub.addItem(renderSub)
                # self.Sub = QtGui.QListWidget(self.secondWindow)  So we create an other Qt list will contain our prologue instruction
                subPatch.append(renderSub)
                Subs = ''
                for sub in subPatch:
                    Subs += sub
                self.sub = QtGui.QLabel(Subs, self.secondWindow)
                self.sub.setStyleSheet('''color: rgb(0, 0, 255); font-size: 18px;padding-left: 200px''')
                self.sub.resize(600,190)
                self.sub.move(100,50)
                self.sub.show()
                if 'PrevLeave' in self.containLeaveAndPrologue[function]:   # if our function contain a Leave
                    #self.Leave = QtGui.QListWidget(self.secondWindow)
                    renderLeave = ''
                    renderLeave+=GetDisasm(self.containLeaveAndPrologue[function]['PrevLeave'][6])+"\n"
                    renderLeave+=GetDisasm(self.containLeaveAndPrologue[function]['PrevLeave'][5])+"\n"
                    renderLeave+=GetDisasm(self.containLeaveAndPrologue[function]['PrevLeave'][4])+"\n"
                    renderLeave+=GetDisasm(self.containLeaveAndPrologue[function]['PrevLeave'][3])+"\n"
                    renderLeave+=GetDisasm(self.containLeaveAndPrologue[function]['PrevLeave'][2])+"\n"
                    renderLeave+=GetDisasm(self.containLeaveAndPrologue[function]['PrevLeave'][1])+"\n"
                    renderLeave+=GetDisasm(self.containLeaveAndPrologue[function]['PrevLeave'][0])+"\n"
                    #self.Leave.addItem(renderLeave)
                    leavePatch.append(renderLeave)
                    Leave = ''
                    for leave in leavePatch:
                        Leave += leave
                    self.leave = QtGui.QLabel(Leave, self.secondWindow)
                    self.leave.setStyleSheet('''color: rgb(0, 0, 65); font-size: 18px;padding-left: 200px''')
                    self.leave.resize(600,190)
                    self.leave.move(100,255)
                    self.leave.show()
                self.patchedAddr = self.containLeaveAndPrologue[function]['addrPrologue'][3]+2
                break
        self.leaveItem.show()
        self.changeValue.show()
        self.valueFirst.show()
        self.subLabel.show()
        self.secondWindow.show()

    # This function will patch the value directly inside ida in real time (we add 0x10)
    def change(self):
        valByteChang = int(Byte(self.patchedAddr))
        idc.PatchByte(self.patchedAddr, valByteChang + 0x10)
        onClick = self.list.currentRow()
        self.list.setCurrentRow(onClick)
        self.clickList(self.list.item(onClick))
        labelOnClick = QtGui.QLabel("Value was change correctly", self)
        labelOnClick.setStyleSheet('''color: rgb(51, 204, 0); font-size: 14px;''')
        labelOnClick.setGeometry(680,260, 200, 30)
        labelOnClick.show()

    # This function will patch the value directly inside ida in real time (we sub 0x10)
    def coreValue(self):
        valByteChang = int(Byte(self.patchedAddr))
        idc.PatchByte(self.patchedAddr, valByteChang - 0x10)
        onClick = self.list.currentRow()
        self.list.setCurrentRow(onClick)
        self.clickList(self.list.item(onClick))
        labelOnClick = QtGui.QLabel("Value was change correctly", self)
        labelOnClick.setStyleSheet('''color: rgb(102, 0, 0); font-size: 14px;''')
        labelOnClick.setGeometry(680,260, 200, 30)
        labelOnClick.show()

    # This function will be use to close the app
    def closeEvent(self, event):
        reply = QtGui.QMessageBox.question(self, 'Message', "Are you sure to quit ?", QtGui.QMessageBox.Yes, QtGui.QMessageBox.No)
        if reply == QtGui.QMessageBox.Yes:
            event.accept()
        else:
            event.ignore()

    # This funciton go to the next item of Qt list
    def nextItem(self):
        next = self.list.currentRow() + 1
        if next == self.list.count():
            next = 0
        self.list.setCurrentRow(next)
        self.clickList(self.list.item(next))

    # This funciton go to the previous item of Qt list
    def prevItem(self):
        prev = self.list.currentRow() - 1
        if prev == self.list.count():
            prev = 0
        if prev == -1:
            prev = self.list.count() - 1
        self.list.setCurrentRow(prev)
        self.clickList(self.list.item(prev))

    # This function allow to use keys
    def keyPressEvent(self, event):
        if event.key() == QtCore.Qt.Key_Down:
            return self.nextItem()
        if event.key() == QtCore.Qt.Key_Up:
            return self.prevItem()
        if event.key() == QtCore.Qt.Key_Shift:
            return self.change()
        if event.key() == QtCore.Qt.Key_Control:
            return self.coreValue()


    # This function allow to save patch function
    def main(self):
        reply = QtGui.QMessageBox.question(self, 'Message', "Are you sure to quit ?", QtGui.QMessageBox.Yes, QtGui.QMessageBox.No)
        if reply == QtGui.QMessageBox.Yes:

            print 'Finding changed bytes...',
            changed_bytes = find_changed_bytes()
            print 'done. %d changed bytes found' % len(changed_bytes)

            if changed_bytes:
                original_file = GetInputFilePath()
                print original_file

                if not os.path.exists(original_file):
                    original_file = idc.AskFile( 0, '*.*', 'Select original file to patch')

                if os.path.exists(original_file):

                    with file(original_file, 'rb') as f:
                        data = list( f.read() )

                    patch_file(data, changed_bytes)

# This class allow us to create a plugin ida (put this inside c:/programme/ida/plugin)
class pluginPatch(idaapi.plugin_t):

    flags = idaapi.PLUGIN_KEEP
    comment = "This is a comment"

    help = "This is help"
    wanted_name = "Patch Sub Value"
    wanted_hotkey = "Alt-F10"

    def __init__(self):
        self.view = None

    def init(self):
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        self.view = patch()
        self.view.show()

    def term(self):
        idaapi.msg("")


def PLUGIN_ENTRY():
    return pluginPatch()
