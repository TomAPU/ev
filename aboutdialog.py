# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'aboutdialog.ui'
#
# Created by: PyQt5 UI code generator 5.15.4
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_aboutdialog(object):
    def setupUi(self, aboutdialog):
        aboutdialog.setObjectName("aboutdialog")
        aboutdialog.resize(548, 588)
        self.label = QtWidgets.QLabel(aboutdialog)
        self.label.setGeometry(QtCore.QRect(220, 10, 91, 61))
        font = QtGui.QFont()
        font.setPointSize(20)
        self.label.setFont(font)
        self.label.setTextInteractionFlags(QtCore.Qt.LinksAccessibleByMouse|QtCore.Qt.TextSelectableByMouse)
        self.label.setObjectName("label")
        self.label_2 = QtWidgets.QLabel(aboutdialog)
        self.label_2.setGeometry(QtCore.QRect(30, 80, 511, 341))
        self.label_2.setTextInteractionFlags(QtCore.Qt.LinksAccessibleByMouse|QtCore.Qt.TextSelectableByMouse)
        self.label_2.setObjectName("label_2")
        self.label_3 = QtWidgets.QLabel(aboutdialog)
        self.label_3.setGeometry(QtCore.QRect(70, 420, 441, 101))
        font = QtGui.QFont()
        font.setPointSize(10)
        self.label_3.setFont(font)
        self.label_3.setTextInteractionFlags(QtCore.Qt.LinksAccessibleByMouse|QtCore.Qt.TextSelectableByMouse)
        self.label_3.setObjectName("label_3")

        self.retranslateUi(aboutdialog)
        QtCore.QMetaObject.connectSlotsByName(aboutdialog)

    def retranslateUi(self, aboutdialog):
        _translate = QtCore.QCoreApplication.translate
        aboutdialog.setWindowTitle(_translate("aboutdialog", "Dialog"))
        self.label.setText(_translate("aboutdialog", "About"))
        self.label_2.setText(_translate("aboutdialog", "<html><head/><body><p>In 1998, a famous article <span style=\" font-style:italic;\">Insertion, Evasion, and Denial of </span></p><p><span style=\" font-style:italic;\">Service</span> was published. It introduced techniques of evading</p><p>IDS devices by packet manipulation in network and transport</p><p>layer.</p><p>Now it\'s 2022, hackers now keen on playing around data in</p><p>application layer to defeat WAFs and few of them still remember</p><p>such techniques. However, Recently I\'ve found that such</p><p>old-school techniques can still circumvent some IDSes and I </p><p>believe they deserve more attention.</p><p>So I built this tool, it allows users building their own TCP</p><p>packet and leveraging these techniques easily.</p><p>Happy Hacking!</p></body></html>"))
        self.label_3.setText(_translate("aboutdialog", "<html><head/><body><p>Author: <a href=\"https://twitter.com/drivertomtt\"><span style=\" text-decoration: underline; color:#0000ff;\">drivertomtt@twitter.com</span></a> in <a href=\"https://www.0x401.com/\"><span style=\" text-decoration: underline; color:#0000ff;\">0x401 Team</span></a></p><p>My blog: <a href=\"https://drivertom.blogspot.com/\"><span style=\" text-decoration: underline; color:#0000ff;\">https://drivertom.blogspot.com/</span></a></p><p>My Github: <a href=\"https://github.com/TomAPU/\"><span style=\" text-decoration: underline; color:#0000ff;\">https://github.com/TomAPU/</span></a></p></body></html>"))
