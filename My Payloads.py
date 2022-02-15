from burp import IBurpExtender, ITab
from javax.swing import JPanel, JScrollPane, JTextPane, JButton, JTextArea, JOptionPane, JLabel, JComboBox,JTextField, BorderFactory, JTabbedPane, JRadioButton
from java.awt import GridBagLayout, Color, Dimension, FlowLayout, GridBagConstraints, Font, Insets
from javax.swing.border import EmptyBorder, CompoundBorder, TitledBorder

class fileUtil:
    def __init__(self, dataFpath):
        self.dataFpath = dataFpath
            
    def insertToFile(self, startString, insertedData, lineIndex = None):
        with open(self.dataFpath, "r") as f:
            contents = f.readlines()
        if not lineIndex:
            for x in range(len(contents)):
                if contents[x].startswith(startString):
                    contents.insert(x+1, insertedData + "\n")
                    break
        else:
            contents.insert(lineIndex-1, insertedData + "\n")         
        with open(self.dataFpath, "w") as f:
            contents = "".join(contents)
            f.write(contents)
            f.close()
    
    def appendToFile(self, insertedData):
        f = open(self.dataFpath, "a")
        f.write(insertedData + "\n")
        f.close()        
        
    def delFileLine(self, startString):
        with open(self.dataFpath, "r") as f:
            contents = f.readlines()
        for x in contents:
            if x.startswith(startString):
                contents.remove(x)
                break
        with open(self.dataFpath, "w") as f:
            contents = "".join(contents)
            f.write(contents) 
    
    def findAndReplaceString(self, dataInput, output):
        with open(self.dataFpath, 'r') as file :
            filedata = file.read()
        filedata = filedata.replace(dataInput, output)
        with open(self.dataFpath, 'w') as file:
            file.write(filedata)
        file.close()

class util:
    def addPreHtml(self, stringInput, sizeFont):
        return """<pre style="font-size: {}px">""".format(sizeFont) + stringInput + "</pre>"

    def htmlEscape(self, inputString):
        inputString = inputString.replace("&","&amp;")
        inputString = inputString.replace("<","&lt;")
        inputString = inputString.replace(">","&gt;")
        inputString = inputString.replace("'","&#x27;")
        inputString = inputString.replace('"',"&quot;")
        return inputString
        
    
class BurpExtender(IBurpExtender, ITab):
    def __init__(self):
        self.dataFpath = "D:\Pentest Document\PortSwigger\Burp Extension\My payloads\datafile.txt"
        self.myUtil = util()
        self.futil = fileUtil(self.dataFpath)
        self.payloadTypeList = list()
        f = open(self.dataFpath, 'a')
        self.loadConfigFromFile()
        self.displayTypeList = list()
        self.loadDisplayConfig()
        self.radioBtnList = list()
        self.dataDict = dict()
        self.loadDataFromFile()
    
    def displayPayloads(self):
        data = ""
        for typeName, payload in self.dataDict.items():
            if typeName in self.displayTypeList:
                typeName = self.myUtil.htmlEscape(typeName)
                payload = self.myUtil.htmlEscape(payload)
                data += """<dt><h1 style="font-size: 22px">{}</h1></dt><dd>{}</dd>""".format(typeName,self.myUtil.addPreHtml(payload, 15))        
        self.showTextPane.setText("<dl>" + data + "</dl>")
    
    def loadDisplayConfig(self):
        f = open(self.dataFpath, "r")
        displayConf = f.readline()
        if displayConf and displayConf.startswith("* Selected Options: "):
            self.displayTypeList = displayConf[len("* Selected Options: "):-1].split(",,,")
        
    def updateComboBox(self):
        temp = str(self.typeCb.getSelectedItem())
        self.typeCb.removeAllItems()
        for data in self.payloadTypeList:
            self.typeCb.addItem(data)
        self.typeCb.revalidate()
        self.selectTypePanel.revalidate()
        self.selectTypePanel.repaint()
        if temp in self.payloadTypeList:
            self.typeCb.setSelectedItem(temp)
    
    def updateGlobalVar(self,typeName, payload):
        if typeName not in self.payloadTypeList and not payload:
            self.futil.appendToFile("-Type: " + typeName + "\n" + "="*200)
            self.payloadTypeList.append(typeName)
            self.dataDict[typeName] = payload
            self.updateComboBox()
            
        elif typeName in self.payloadTypeList:
            self.removeDataFromFile(typeName, onlyRemovePayload = True)
            self.futil.insertToFile("-Type: " + typeName, payload, lineIndex = None)
            self.dataDict[typeName] = payload
        
    def removeGlobalEleVar(self,typeName):
        if typeName in self.payloadTypeList:
            self.removeDataFromFile(typeName)
            self.payloadTypeList.remove(typeName)
            del self.dataDict[typeName]
            if typeName in self.displayTypeList:
                self.displayTypeList.remove(typeName)
            self.updateComboBox()
                        
    def loadDataFromFile(self):
        payloadAndTypeList = self.getPayloadAndTypeList()
        for data in payloadAndTypeList:
            if data.startswith("-Type: "):
                payloadType = data.split("\n")[0][len("-Type: "):]
                payload = data[len("-Type: " + payloadType + "\n"):]
                self.dataDict[payloadType] = payload   
        
    def getPayloadWithTypeName(self, typeName):
        f = open(self.dataFpath, "r")
        fullData = f.read()
        if len(fullData.split("*"*200+"\n")) == 2:
            payloadData = fullData.split("*"*200+"\n")[1]
        else:
            payloadData = fullData  
        for data in payloadData.split("\n"+"="*200+"\n"):
            if data.startswith("-Type: " + typeName):
                return data[len("-Type: " + typeName + "\n"):]                    
    
    def getPayloadAndTypeList(self):
        f = open(self.dataFpath, "r")
        fullData = f.read()
        if len(fullData.split("*"*200+"\n")) == 2:
            payloadData = fullData.split("*"*200+"\n")[1]
        else:
            payloadData = fullData
        return payloadData.split("\n"+"="*200+"\n")     
        
    def removeDataFromFile(self, typeName, onlyRemovePayload = None):
        payloadAndTypeList = self.getPayloadAndTypeList()
        for data in payloadAndTypeList:
            if not onlyRemovePayload:
                if data.startswith("-Type: " + typeName):
                    self.futil.findAndReplaceString(data + "\n" + "="*200 + "\n","")
                    break
            elif onlyRemovePayload:
                if data.startswith("-Type: " + typeName):
                    self.futil.findAndReplaceString(data,"-Type: " + typeName)
                    break                      
    
    def loadConfigFromFile(self):
        self.payloadTypeList = []
        f = open(self.dataFpath, "r")
        lines = f.read()
        for line in lines.split("\n"):
            if line.startswith("-Type: "):
                self.payloadTypeList.append(line[len("-Type: "):])
    
    def getTabCaption(self):
        return "My Payloads"

    def changeButtonTextFont(self, data, style):
        if style == "BOLD":
            data.setFont(Font(data.getFont().getName(),Font.BOLD,data.getFont().getSize()))
        elif style == "ITALIC":
            data.setFont(Font(data.getFont().getName(),Font.ITALIC,data.getFont().getSize()))
        elif style == "PLAIN":
            data.setFont(Font(data.getFont().getName(),Font.PLAIN,data.getFont().getSize()))
        elif style == "BOLD + ITALIC":
            data.setFont(Font(data.getFont().getName(),Font.BOLD + Font.ITALIC,data.getFont().getSize()))    
           
        
    def loadPayloadType(self):
        self.radioBtnList = []
        gbc = GridBagConstraints()
        gbc.gridx = 0
        gbc.gridy = 0
        gbc.anchor = GridBagConstraints.WEST
        count = 100
        typeId=0
        if self.payloadTypeList:
            for x in self.payloadTypeList:
                gbc.insets = Insets(-1050 + count,0,0,250)
                self.radioBtnList.append(JRadioButton(x))
                self.dsplayPanel.add(self.radioBtnList[typeId], gbc)
                gbc.gridy += 1
                count+=100
                typeId+=1
        self.updateStatusDisplayOption()
    
    def updateStatusDisplayOption(self):
        for x in self.radioBtnList:
            if x.getText() in self.displayTypeList:
                x.setSelected(True)  
            
    #Perform event button
    def addPayloadType(self, event):
        try:
            payloadType = str(self.addTypeField.getText())
            payloadType.decode('ascii')
        except:
            print ("Not support unicode")
            JOptionPane.showMessageDialog(self.configPanel, "Not support unicode")
            return
        if payloadType in self.payloadTypeList:
            JOptionPane.showMessageDialog(self.configPanel, "Duplicate Name")
            return
        if payloadType:
            self.updateGlobalVar(payloadType, "")
        self.dsplayPanel.removeAll()
        self.dsplayPanel.revalidate()
        self.loadPayloadType()
        self.dsplayPanel.repaint()        
        self.addTypeField.setText("")
        
    def saveDisplayConfig(self, event):
        self.futil.delFileLine("* Selected Options:")
        self.futil.delFileLine("*"*200)
        self.displayTypeList=[]
        for x in self.radioBtnList:
            if x.isSelected():
                self.displayTypeList.append(str(x.getText()))
        if self.displayTypeList:                
            self.futil.insertToFile("", "* Selected Options: " + str(",,,".join([x for x in self.displayTypeList]) + "\n" + "*"*200), lineIndex = 1)
        self.displayPayloads()
     
    def clearOptions(self, event):
        self.displayTypeList=[]
        for x in self.radioBtnList:
            x.setSelected(False)    
        self.futil.delFileLine("* Selected Options:")
        self.futil.delFileLine("*"*200)
        self.displayPayloads()
    
    def deleteType(self, event):
        self.futil.delFileLine("* Selected Options:")
        self.futil.delFileLine("*"*200)
        for x in self.radioBtnList:
            if x.isSelected():
                self.removeGlobalEleVar(x.getText())
        self.dsplayPanel.removeAll()
        self.dsplayPanel.revalidate()
        self.loadPayloadType()
        self.dsplayPanel.repaint()
        if self.displayTypeList:                
            self.futil.insertToFile("", "* Selected Options: " + str(",,,".join([x for x in self.displayTypeList]) + "\n" + "*"*200), lineIndex = 1)
        self.displayPayloads()
    
    def saveCusPayload(self, event):
        try:
            self.editTextArea.getText().decode('ascii')
        except:
            print ("Not support unicode")
            JOptionPane.showMessageDialog(self.rightPanel, "Not support unicode")
            return
        self.updateGlobalVar(str(self.typeCb.getSelectedItem()),self.editTextArea.getText())
        self.displayPayloads()
        
    def renameType(self, event):
        oldName = str(self.typeCb.getSelectedItem())
        newName = JOptionPane.showInputDialog(self.rightPanel,"Enter a new name:", str(self.typeCb.getSelectedItem()))
        if not newName:
            return
        try:
            newName = str(newName)
            newName.decode('ascii')
        except:
            print ("Not support unicode")
            JOptionPane.showMessageDialog(self.configPanel, "Not support unicode")
            return        
        
        if oldName == newName:
            return
        if newName in self.payloadTypeList:
            JOptionPane.showMessageDialog(self.configPanel, "Duplicate Name")
            return        
        else:
            self.futil.findAndReplaceString("-Type: " + oldName, "-Type: " + newName)
            self.payloadTypeList = [newName if x==oldName else x for x in self.payloadTypeList]
            self.dataDict[newName] = self.dataDict[oldName]
            del self.dataDict[oldName]
            self.displayTypeList = [newName if x==oldName else x for x in self.displayTypeList]
            self.updateStatusDisplayOption()
            self.futil.delFileLine("* Selected Options:")
            self.futil.delFileLine("*"*200)
            if self.displayTypeList:                
                self.futil.insertToFile("", "* Selected Options: " + str(",,,".join([x for x in self.displayTypeList]) + "\n" + "*"*200), lineIndex = 1)
            self.updateComboBox()
            self.dsplayPanel.removeAll()
            self.dsplayPanel.revalidate()
            self.loadPayloadType()
            self.dsplayPanel.repaint()
            self.displayPayloads()
            self.typeCb.setSelectedItem(newName)

    #JComboBox Event
    def selectOptionToEdit(self, event):
        if self.typeCb.getSelectedItem():
            self.editTextArea.setText(self.dataDict[self.typeCb.getSelectedItem()])

    #======================
    
    def getUiComponent(self):
        gbc = GridBagConstraints()
        containerPanel = JTabbedPane()
        ##################################
        self.configPanel = JPanel(FlowLayout())
        self.configPanel.setName("Configuration")
        
        leftPanel = JPanel()
        leftPanel.setBorder(CompoundBorder(TitledBorder("Payload Type Configuration"), EmptyBorder(4, 4, 4, 4)))
        leftPanel.setPreferredSize(Dimension(500, 1300))
        
        addTypePanel =  JPanel(GridBagLayout())
        addTypePanel.setPreferredSize(Dimension(480, 150))
        gbc.insets = Insets(0,0,0,0)
        gbc.anchor = GridBagConstraints.EAST     
        self.addTypeField = JTextField(10)
        addTypeButton = JButton("Add")
        addTypeButton.addActionListener(self.addPayloadType)
        addTypePanel.add(JLabel("Payload Type Name     "), gbc)
        addTypePanel.add(self.addTypeField, gbc)
        gbc.insets = Insets(0,10,0,0)
        addTypePanel.add(addTypeButton, gbc)
        leftPanel.add(addTypePanel)
        
        buttonPanel = JPanel(GridBagLayout())
        gbc.gridx = 0
        gbc.gridy = 0
        gbc.insets = Insets(-30,0,0,290)
        blueBorder = BorderFactory.createLineBorder(Color.blue)
        buttonPanel.setPreferredSize(Dimension(480, 100))
        leftPanel.add(buttonPanel)
        saveDsplayBtn = JButton("Display")
        clearBtn = JButton("Clear")
        self.changeButtonTextFont(saveDsplayBtn,"BOLD")
        self.changeButtonTextFont(clearBtn,"BOLD")
        saveDsplayBtn.setPreferredSize(Dimension(100, 50))
        clearBtn.setPreferredSize(Dimension(100, 50))
        clearBtn.addActionListener(self.clearOptions)
        saveDsplayBtn.addActionListener(self.saveDisplayConfig)
        buttonPanel.add(saveDsplayBtn, gbc)
        gbc.insets = Insets(-30,0,0,-10)
        buttonPanel.add(clearBtn, gbc)
        deleteBtn = JButton("Delete")
        self.changeButtonTextFont(deleteBtn,"BOLD")
        deleteBtn.setPreferredSize(Dimension(100, 50))
        deleteBtn.addActionListener(self.deleteType)
        gbc.insets = Insets(-30,0,0,140)
        buttonPanel.add(deleteBtn, gbc)
        
        self.dsplayPanel = JPanel(GridBagLayout())
        self.dsplayPanel.setPreferredSize(Dimension(480, 1000))
        self.loadPayloadType()
        
        leftPanel.add(self.dsplayPanel)
           
        self.rightPanel = JPanel()
        self.rightPanel.setBorder(CompoundBorder(TitledBorder("Edit Payloads"), EmptyBorder(4, 4, 4, 4)))          
        self.rightPanel.setPreferredSize(Dimension(1200, 1300))

        self.selectTypePanel = JPanel(GridBagLayout())
        self.selectTypePanel.setPreferredSize(Dimension(1000, 50))
        self.typeCb = JComboBox(self.payloadTypeList)
        self.typeCb.setPrototypeDisplayValue("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")
        gbc.insets = Insets(-20,0,0,30)
        self.typeCb.addActionListener(self.selectOptionToEdit)
        self.selectTypePanel.add(self.typeCb, gbc)
        self.saveTextBtn = JButton("Save")
        self.saveTextBtn.setPreferredSize(Dimension(80, 20))
        self.changeButtonTextFont(self.saveTextBtn,"BOLD")
        self.saveTextBtn.addActionListener(self.saveCusPayload)
        gbc.insets = Insets(-20,0,0,350)
        gbc.gridx = 2
        self.selectTypePanel.add(self.saveTextBtn,gbc)
        self.renameBtn = JButton("Rename")
        self.renameBtn.setPreferredSize(Dimension(80, 20))
        self.changeButtonTextFont(self.renameBtn,"BOLD")
        self.renameBtn.addActionListener(self.renameType)
        gbc.insets = Insets(-20,0,0,50)
        gbc.gridx = 1
        self.selectTypePanel.add(self.renameBtn,gbc)
        self.rightPanel.add(self.selectTypePanel)
        
        editPayloadPanel = JPanel(GridBagLayout())
        editPayloadPanel.setPreferredSize(Dimension(1100, 850))
        self.editTextArea = JTextArea()
        self.editTextArea.setLineWrap(True)
        self.editTextArea.setWrapStyleWord(True)
        if self.dataDict:
            self.editTextArea.setText(self.dataDict[self.typeCb.getSelectedItem()])
        
        cusPayloadLb = JLabel("Custome Payload")
        gbc.gridx = 0
        gbc.gridy = 0
        gbc.insets = Insets(-30,0,0,900)
        editPayloadPanel.add(cusPayloadLb, gbc)
        jsp = JScrollPane(self.editTextArea)
        jsp.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS)
        jsp.setPreferredSize(Dimension(1000, 790))
        gbc.gridy = 1
        gbc.insets = Insets(0,0,0,0)
        editPayloadPanel.add(jsp,gbc)
        self.rightPanel.add(editPayloadPanel)
        
        self.configPanel.add(leftPanel)
        self.configPanel.add(self.rightPanel)
        
        payloadPanel = JPanel(GridBagLayout())
        showPanel = JPanel(GridBagLayout())
        showPanel.setPreferredSize(Dimension(1000, 1100))
        # blackBorder = BorderFactory.createLineBorder(Color.black)
        # showPanel.setBorder(blackBorder)
        self.showTextPane = JTextPane()
        self.showTextPane.setEditable(False)
        showJsp = JScrollPane(self.showTextPane) 
        showJsp.setPreferredSize(Dimension(900, 1000))
        self.showTextPane.setContentType("text/html")
        self.displayPayloads()
        showLabel = JLabel("Your Payloads")
        showLabel.setFont(Font(showLabel.getFont().getName(), Font.BOLD, 15))
        gbc.gridx = 0
        gbc.gridy = 0
        gbc.insets = Insets(-40,0,0,785)        
        showPanel.add(showLabel, gbc)
        gbc.gridy = 1
        gbc.insets = Insets(0,0,0,0) 
        showPanel.add(showJsp, gbc)              
        payloadPanel.add(showPanel)
        
        containerPanel.add(self.configPanel)
        containerPanel.add(payloadPanel)
        containerPanel.addTab("Payloads", payloadPanel)
        containerPanel.addTab("Configuration", self.configPanel)
        
        return containerPanel

    def registerExtenderCallbacks(self,callbacks):
        callbacks.setExtensionName("My Payloads")
        callbacks.printOutput("abcd")        
        callbacks.addSuiteTab(self)

