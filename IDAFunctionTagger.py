import os
import json
import webbrowser

from collections import defaultdict

import idc
from idautils import *
from idaapi import *
from idaapi import PluginForm

from PyQt5 import QtGui, QtCore, QtWidgets


class visitor(idaapi.ctree_visitor_t):
    def __init__(self, cfunc, results):
        idaapi.ctree_visitor_t.__init__(self, idaapi.CV_FAST)
        self.cfunc = cfunc
        self.results = results

    def visit_expr(self, i):
        """
        From FLARE article
        Search for dw1234 = GetProcAddress("LoadLibrary")
        """
        if i.op == idaapi.cot_call:
            # look for calls to GetProcAddress
            if idc.Name(i.x.obj_ea) == "GetProcAddress":

                # ASCSTR_C == 0
                # Check to see if the second argument is a C string
                if idc.GetStringType(i.a[1].obj_ea) == 0:
                    targetName = idc.GetString(i.a[1].obj_ea, -1, 0)

                    # Found function name
                    # Look for global assignment
                    parent = self.cfunc.body.find_parent_of(i)
                    if parent.op == idaapi.cot_cast:
                        # Ignore casts and look for the parent
                        parent = self.cfunc.body.find_parent_of(parent)

                    if parent.op == idaapi.cot_asg:
                        # We want to find the left hand side (x)
                        self.results[targetName] = parent.cexpr.x.obj_ea
                        idc.MakeName(parent.cexpr.x.obj_ea, targetName)

        return 0

class TagManager(object):
    open_tag = "[TagList:"
    close_tag = "]"
    tag_separator = ", "

    def __init__(self):
        self.has_decompiler = False
        self.sneaky_functions = {}

        self.clear()
        self._init_decompiler()

    def _init_decompiler(self):
        if not idaapi.init_hexrays_plugin():
            self.has_decompiler = False
        else:
            print("Hex-rays version {} detected".format(idaapi.get_hexrays_version()))
            self.has_decompiler = True

        return

    def _get_sneaky_functions(self):
        """
        Populates the dictionary of sneaky functions,
        containing {'func_name': dw_abc, ...}
        """
        sneaky = {}

        for f_ea in Functions():
            try:
                cf = decompile(f_ea)
            except DecompilationFailure as e:
                continue

            results = {} # Scope is a function
            v = visitor(cf, results)
            v.apply_to(cf.body, None)

            if results:
                sneaky.update(results)

        self.sneaky_functions = sneaky

    def _addTagToFunction(self, function_name, tag_name):
        """
        This is the meat and potatoes of this plugin
        """
        function_address = LocByName(function_name)
        function_comment = GetFunctionCmt(function_address, 0)

        tag_list_start = function_comment.find(self.open_tag)
        if tag_list_start == -1:
            SetFunctionCmt(function_address, function_comment + self.open_tag + tag_name + self.close_tag, 0)
            return

        tag_list_end = function_comment.find(self.close_tag, tag_list_start)
        if tag_list_end == -1:
            print("Malformed tag list found at address 0x%X" % function_address)
            return

        tag_list = function_comment[tag_list_start : tag_list_end + 1]
        function_comment = function_comment.replace(tag_list, "")

        tag_list = tag_list[len(self.open_tag) : len(tag_list) - len(self.close_tag)]
        tag_list = tag_list.split(self.tag_separator)

        if tag_name not in tag_list:
            tag_list.append(tag_name)
        tag_list.sort()

        function_comment = function_comment + self.open_tag
        for tag in tag_list:
            function_comment = function_comment + tag + self.tag_separator
        function_comment = function_comment[ : -1] + self.close_tag

        SetFunctionCmt(function_address, function_comment, 0)

    def scanDatabase(self, json_configuration, use_decompiler=False):
        """
        This loads a JSON file with data belonging 
        to specific APIs
        """
        configuration = ""

        try:
            configuration = json.loads(json_configuration)
        except:
            print("Invalid configuration file")
            return

        print("Loading configuration: %s" % configuration["name"])
        print("Configuration comment: %s" % configuration["comment"])

        for tag in configuration["tag_list"]:
            print("1. pass - Scanning for tag '%s'..." % tag["name"])
            for imported_function in tag["import_list"]:
                function_address = LocByName(str(imported_function))
                if function_address == BADADDR:
                    continue

                cross_reference_list = CodeRefsTo(function_address, 0)
                for xref in cross_reference_list:
                    function_name = GetFunctionName(xref)
                    self._addTagToFunction(function_name, str(tag["name"]))

        # Bro, do you even hexrays?
        if not self.has_decompiler or not use_decompiler:
            return

        # Find sneaky "imported" functions
        self._get_sneaky_functions()

        if not self.sneaky_functions:
            # Didn't find any :(
            return

        # Second pass
        # Go over it again finding dynamically imported APIs
        for tag in configuration["tag_list"]:
            print("2. pass - Scanning for tag '%s'..." % tag["name"])
            for imported_function in tag["import_list"]:
                if imported_function in self.sneaky_functions:
                    dw_addr = self.sneaky_functions[imported_function]

                    # Now find the "cross references" to this Dword
                    pseudo_cross_reference_list = XrefsTo(dw_addr, 0)
                    for xref in pseudo_cross_reference_list:
                        ty = xref.type
                        if XrefTypeName(ty) == 'Data_Read':
                            # In my tests the calls are always "data reads"
                            # Double check anyway...
                            if GetMnem(xref.frm) == 'call':
                                function_name = GetFunctionName(xref.frm)
                                print "[DEBUG] Found sneaky: {} ({:x})".format(function_name, xref.frm)
                                self._addTagToFunction(function_name, str(tag["name"]))



    def removeAllTags(self):

        entry_point = BeginEA()
        function_list = Functions(SegStart(entry_point), SegEnd(entry_point))

        for function_address in function_list:
            function_comment = GetFunctionCmt(function_address, 0)

            tag_list_start = function_comment.find(self.open_tag)
            if tag_list_start == -1:
                continue

            tag_list_end = function_comment.find(self.close_tag, tag_list_start)
            if tag_list_end == -1:
                continue

            SetFunctionCmt(function_address, function_comment.replace(function_comment[tag_list_start : tag_list_end + 1], ""), 0)

    def clear(self):
        """
        Poor choice of variable names :D
        """
        self._tag_list = defaultdict(list)
        self._function_list = {}

    def update(self):

        self.clear()

        entry_point = BeginEA()
        function_list = Functions(SegStart(entry_point), SegEnd(entry_point))

        for function_address in function_list:
            function_comment = GetFunctionCmt(function_address, 0)

            tag_list_start = function_comment.find(self.open_tag)
            if tag_list_start == -1:
                continue

            tag_list_end = function_comment.find(self.close_tag, tag_list_start)
            if tag_list_end == -1:
                continue

            tag_list = function_comment[tag_list_start + len(self.open_tag) : tag_list_end]
            if len(tag_list) == 0:
                continue

            self._function_list[GetFunctionName(function_address)] = tag_list.split(self.tag_separator)

            tag_list = tag_list.split(self.tag_separator)
            for tag_name in tag_list:
                self._tag_list[tag_name].append(GetFunctionName(function_address))

    def tagList(self):
        return self._tag_list

    def functionList(self):
        return self._function_list

class TagViewer_t(PluginForm):
    use_decompiler = False
    root_dir = os.path.dirname(os.path.abspath(__file__))
    default_config = os.path.join(root_dir, "cfg", "WindowsCommon.json")

    def Update(self):
        """
        This is merely graphical stuff
        The logic is in `self._tag_manager`
        """
        self._tag_list_model.clear();
        self._function_list_model.clear();

        self._tag_list_model.setHorizontalHeaderLabels(["Tag", "Function", "Address"])
        self._function_list_model.setHorizontalHeaderLabels(["Function", "Address", "Tags"])

        for tag_name in self._tag_manager.tagList().iterkeys():
            tag = self._tag_manager.tagList()[tag_name]

            tag_item = QtGui.QStandardItem(tag_name)
            self._tag_list_model.appendRow([tag_item])

            for function_name in tag:
                function_name_item = QtGui.QStandardItem(function_name)

                address = LocByName(function_name)
                address_item = QtGui.QStandardItem("0x%X" % address)

                tag_item.appendRow([QtGui.QStandardItem(), function_name_item, address_item])

        for function_name in self._tag_manager.functionList().iterkeys():
            tag_list = self._tag_manager.functionList()[function_name]

            function_name_item = QtGui.QStandardItem(function_name)
            address_item = QtGui.QStandardItem("0x%X" % LocByName(function_name))

            tag_list_string = ""
            for tag in tag_list:
                tag_list_string = tag_list_string + " " + tag

            tag_list_item = QtGui.QStandardItem(tag_list_string)

            self._function_list_model.appendRow([function_name_item, address_item, tag_list_item])

        self._function_list_view.expandAll()
        self._tag_list_view.expandAll()

        for i in range(0, 2):
            self._function_list_view.resizeColumnToContents(i)
            self._tag_list_view.resizeColumnToContents(i)

    def _apply_config(self, filename):
        with open(filename, "r") as input_file:
            file_buffer = input_file.read()

        self._tag_manager.scanDatabase(file_buffer, self.use_decompiler)
        self._tag_manager.update()
        self.Update()

    def _onTagClick(self, model_index):
        function_address = BADADDR

        if model_index.column() == 2:
            try:
                function_address = int(model_index.data(), 16)
            except:
                pass

        elif model_index.column() == 1:
            function_address = LocByName(str(model_index.data()))

        else:
            return

        Jump(function_address)

    def _onFunctionClick(self, model_index):
        function_address = BADADDR

        if model_index.column() == 1:
            try:
                function_address = int(model_index.data(), 16)
            except:
                pass

        elif model_index.column() == 0:
            function_address = LocByName(str(model_index.data()))

        else:
            return

        Jump(function_address)

    def _onUpdateClick(self):
        self._tag_manager.update()
        self.Update()

    def _onScanDatabaseClick(self):
        file_path = QtWidgets.QFileDialog.getOpenFileName(self._parent_widget, 'Open configuration file', os.curdir, "*.json")
        if len(file_path[0]) == 0:
            return

        self._apply_config(file_path[0])

    def _onRemoveAllTagsClick(self):
        self._tag_manager.removeAllTags()
        self._tag_manager.update()
        self.Update()

    def _onHomepageClick(self):
        webbrowser.open("https://alessandrogar.io", new = 2, autoraise = True)

    def _onClearFilterClick(self):
        self._filter_box.clear()

    def _onFilterTextChanged(self, text):
        filter = QtCore.QRegExp(text, QtCore.Qt.CaseInsensitive, QtCore.QRegExp.Wildcard)

        self._function_list_model_filter.setFilterRegExp(filter)

        self._function_list_view.expandAll()
        self._tag_list_view.expandAll()

    def _use_decompiler(self, state):
        """ Reads checked state from the GUI """
        self.use_decompiler = (state == QtCore.Qt.Checked)

    def OnCreate(self, parent_form):
        self._tag_manager = TagManager()
        self._tag_manager.update()

        self._tag_list_model = QtGui.QStandardItemModel()

        self._function_list_model = QtGui.QStandardItemModel()
        self._function_list_model_filter = QtCore.QSortFilterProxyModel()
        self._function_list_model_filter.setSourceModel(self._function_list_model)
        self._function_list_model_filter.setFilterKeyColumn(2)

        layout = QtWidgets.QVBoxLayout()
        filter_layout = QtWidgets.QHBoxLayout()

        text_label = QtWidgets.QLabel()
        text_label.setText("Filter: ")
        filter_layout.addWidget(text_label)

        self._filter_box = QtWidgets.QLineEdit()
        self._filter_box.textChanged.connect(self._onFilterTextChanged)
        filter_layout.addWidget(self._filter_box)

        button = QtWidgets.QPushButton()
        button.setText("Clear")
        button.clicked.connect(self._onClearFilterClick)
        filter_layout.addWidget(button)

        layout.addLayout(filter_layout)

        self._parent_widget = self.FormToPyQtWidget(parent_form)
        splitter = QtWidgets.QSplitter()
        layout.addWidget(splitter)

        self._tag_list_view = QtWidgets.QTreeView()
        self._tag_list_view.setAlternatingRowColors(True)
        self._tag_list_view.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self._tag_list_view.setModel(self._tag_list_model)
        self._tag_list_view.setUniformRowHeights(True)
        self._tag_list_view.doubleClicked.connect(self._onTagClick)
        self._tag_list_view.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        splitter.addWidget(self._tag_list_view)

        self._function_list_view = QtWidgets.QTreeView()
        self._function_list_view.setAlternatingRowColors(True)
        self._function_list_view.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self._function_list_view.setModel(self._function_list_model_filter)
        self._function_list_view.setUniformRowHeights(True)
        self._function_list_view.doubleClicked.connect(self._onFunctionClick)
        self._function_list_view.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        splitter.addWidget(self._function_list_view)

        controls_layout = QtWidgets.QHBoxLayout()

        button = QtWidgets.QPushButton()
        button.setText("Homepage")
        button.clicked.connect(self._onHomepageClick)
        controls_layout.addWidget(button)

        controls_layout.insertStretch(1, -1)

        # Checkbox: decompiler opt-in
        cb = QtWidgets.QCheckBox('Use decompiler')
        cb.setCheckState(QtCore.Qt.Unchecked)
        cb.stateChanged.connect(self._use_decompiler)
        controls_layout.addWidget(cb)

        button = QtWidgets.QPushButton()
        button.setText("Update")
        button.clicked.connect(self._onUpdateClick)
        controls_layout.addWidget(button)

        button = QtWidgets.QPushButton()
        button.setText("Scan database")
        button.clicked.connect(self._onScanDatabaseClick)
        controls_layout.addWidget(button)

        button = QtWidgets.QPushButton()
        button.setText("Remove all tags")
        button.clicked.connect(self._onRemoveAllTagsClick)
        controls_layout.addWidget(button)

        layout.addLayout(controls_layout)        

        self._apply_config(self.default_config)
        #self.Update()

        self._parent_widget.setLayout(layout)

    def OnClose(self, parent_form):
        return

    def Show(self):
        return PluginForm.Show(self, "Function Tags", options = PluginForm.FORM_TAB)

def unloadScript():
    TagViewer.Close(0)

    if not uninstallMenus():
        print("Failed to uninstall the menus")

    del TagViewer

def openTagViewer():
    TagViewer.Show()

TagViewer = TagViewer_t()
TagViewer.Show()
