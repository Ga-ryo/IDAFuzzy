from idaapi import Form
from idaapi import Choose
import idaapi
from ida_kernwin import *
from fuzzywuzzy import process
from idautils import *

"""
Fuzzy Search v1.0
Goal
1. Search and execute IDA Pro's feature by name(ex: file,next code, run, attach to process ... )
2. Search and goto Function, string, struct,...
3. Automatically update. (when user rename function, hook and refresh)

Choose.CH_QFTYP_FUZZY is not so usable.
1. Not so fuzzy.
2. In the first place, fuzzy choose isn't applied to Functions Window or other embedded chooser.

@TODO
1. Installation
 - install idapython
 - C:\Users\Ga_ryo_\AppData\Roaming\Hex-Rays\IDA Pro\idapythonrc.py and import
 - C:\Users\Ga_ryo_\AppData\Roaming\Hex-Rays\IDA Pro\ida_fuzzy.py
 - fuzzywuzzy

2. Usage
3. Implement
 - All feature
 - Functions (hook rename and reload automatically)
 - Strings (symbol and Contents)
 - Structures
 - etc...
 
4. Show hint?
 - Name = "strings windows", Hint = "Open strings subview in current context."
  -- but add column affects number of pushing tab.
"""

class Commands(object):
    """
    Command execution proxy.
    """

    def __init__(self,**kwargs):
        self.kwargs = kwargs
        assert(callable(kwargs['fptr']))
        #assert(kwargs.get('description') != None)

    @property
    def description(self):
        return self.kwargs.get('description')


    def execute(self):
        #ea = get_screen_ea()
        #open_strings_window(ea)
        if self.kwargs.get('args') is not None:
            self.kwargs.get('fptr')(*self.kwargs.get('args'))
        else:
            self.kwargs.get('fptr')()

    def get_icon(self):
        print(self.kwargs)
        if self.kwargs.get('icon') is None:
            return 0
        return self.kwargs.get('icon')


# TODO read from config or DB or ...
choices = {}
# func ptr and icon id
registered_actions = get_registered_actions()
for action in registered_actions:
    #IDA's bug? tilde exists many times in label. ex) Abort -> ~A~bort
    #So fix it.
    label = get_action_label(action).replace('~','')
    icon = get_action_icon(action)[1]
    desctription = get_action_tooltip(action)
    choices[label] = Commands(fptr=process_ui_action, args=[action], description=desctription, icon=icon)

#Structs()
#Functions()
#Heads()
for n in Names():
    #jump to addr
    choices[n[1]] = Commands(fptr=jumpto, args=[n[0]], description="Jump to " + n[1], icon=124)

names = []
for k,v in choices.items():
    names.append([k,v.description])


class EmbeddedChooserClass(Choose):
    """
    A simple chooser to be used as an embedded chooser
    """

    def __init__(self, title, nb=5, flags=0):
        Choose.__init__(self,
                        title,
                        [["Action", 30 | Choose.CHCOL_PLAIN], ["Description", 30 | Choose.CHCOL_PLAIN]],
                        embedded=True, flags=flags)
        # embedded=True, width=30, height=20, flags=flags)

        self.n = 0
        self.items = []
        self.icon = 0

    def OnGetIcon(self, n):
        # print("get icon %d" % n)
        return choices[self.items[n][0]].get_icon()

    def OnSelectionChange(self,n):
        pass
        #print("selection change %d" % n)

    def OnClose(self):
        pass

    def OnGetLine(self, n):
        #print("getline %d" % n)
        return self.items[n]

    def OnGetSize(self):
        n = len(self.items)
        #print("getsize -> %d" % n)
        return n


# --------------------------------------------------------------------------
class FuzzySearchForm(Form):
    def __init__(self):
        self.invert = False
        self.EChooser = EmbeddedChooserClass("Title", flags=Choose.CH_MODAL|Choose.CH_NOIDB)
        self.selected_id = 0
        # self.EChooser = EmbeddedChooserClass("Title", flags=Choose.CH_CAN_REFRESH)
        Form.__init__(self, r"""STARTITEM 
        IDA Fuzzy Search
        {FormChangeCb}
        <:{iStr1}>

        <Results:{cEChooser}>
""", {
            'iStr1': Form.StringInput(),
            'cEChooser': Form.EmbeddedChooserControl(self.EChooser),
            'FormChangeCb': Form.FormChangeCb(self.OnFormChange),
        })
        # self.modal = False

    def OnFormChange(self, fid):
        if fid == -1:
            #initialize
            pass
        elif fid == -2:
            #terminate
            pass
        elif fid == self.cEChooser.id:
            self.selected_id = self.GetControlValue(self.cEChooser)[0]
        elif fid == self.iStr1.id:
            s = self.GetControlValue(self.iStr1)
            if s == '':
                return 1
            extracts = process.extract(s, names, limit=5)  # f.iStr1.value won't change until Form.Execute() returns.
            self.EChooser.items = []
            for ex in extracts:
                self.EChooser.items.append(ex[0])
            self.RefreshField(self.cEChooser)
            #print("Extract : " + str(extracts))
        else:
            pass
        return 1

    def get_selected_item(self):
        if self.selected_id == -1:
            return None
        item_name = self.EChooser.items[self.selected_id][0]
        return choices[item_name]


# --------------------------------------------------------------------------
def fuzzy_search_main():
    # Create form
    global f
    f = FuzzySearchForm()

    # Compile (in order to populate the controls)
    f.Compile()
    f.iStr1.value = ""
    # Execute the form
    ok = f.Execute()

    if ok == 1:
        #print("f.str1=%s" % f.iStr1.value)
        #print("Selection : " + str(f.get_selected_item()))
        f.get_selected_item().execute()
    # Dispose the form
    f.Free()

class SayHi(idaapi.action_handler_t):
    def __init__(self, message):
        idaapi.action_handler_t.__init__(self)
        self.message = message

    def activate(self, ctx):
        print "Hi, %s" % (self.message)
        return 1

    # You can implement update(), to inform IDA when:
    #  * your action is enabled
    #  * update() should queried again
    # E.g., returning 'idaapi.AST_ENABLE_FOR_FORM' will
    # tell IDA that this action is available while the
    # user is in the current widget, and that update()
    # must be queried again once the user gives focus
    # to another widget.
    #
    # For example, the following update() implementation
    # will let IDA know that the action is available in
    # "IDA View-*" views, and that it's not even worth
    # querying update() anymore until the user has moved
    # to another view..
    def update(self, ctx):
        return idaapi.AST_ENABLE_FOR_FORM if ctx.form_type == idaapi.BWN_DISASM else idaapi.AST_DISABLE_FOR_FORM

# idaapi.CompileLine('static ida_fuzzy() { RunPythonStatement("fuzzy_search_main()"); }')
# AddHotkey("CTRL+SPACE", 'ida_fuzzy')
#add_hotkey("Z", fuzzy_search_main) # Can't use at structure,Enum,... window when using add_hotkey
"""
idaapi.register_action(idaapi.action_desc_t(
        "FuzzySearch",           # Name. Acts as an ID. Must be unique.
        "IDA Fuzzy Search",          # Label. That's what users see.
        SayHi("developer"), # Handler. Called when activated, and for updating
        "SHIFT+Q",         # Shortcut (optional)
        "IDA Fuzzy Search",  # Tooltip (optional)
        -1)           # Icon ID (optional)
)
"""
# fuzzy_search_main()
