from idaapi import Form
from idaapi import Choose
import idaapi
from ida_kernwin import *
from fuzzywuzzy import process, fuzz
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
 - pip install fuzzywuzzy
 - put this file to plugins directory.

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

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        assert (callable(kwargs['fptr']))
        # assert(kwargs.get('description') != None)

    @property
    def description(self):
        return self.kwargs.get('description')

    @property
    def type(self):
        if self.kwargs.get('fptr') == process_ui_action:
            return "ACTION"
        else:
            return "ELSE"

    @property
    def action(self):
        return self.kwargs.get('action')

    def execute(self):
        # ea = get_screen_ea()
        # open_strings_window(ea)
        if self.kwargs.get('args') is not None:
            self.kwargs.get('fptr')(*self.kwargs.get('args'))
        else:
            self.kwargs.get('fptr')()

    def get_icon(self):
        if self.kwargs.get('icon') is None:
            return 0
        return self.kwargs.get('icon')


# TODO read from config or DB or ...
choices = {}
# func ptr and icon id
registered_actions = get_registered_actions()
for action in registered_actions:
    # IDA's bug? tilde exists many times in label. ex) Abort -> ~A~bort
    # So fix it.
    label = get_action_label(action).replace('~', '')
    icon = get_action_icon(action)[1]
    desctription = get_action_tooltip(action)
    choices[label] = Commands(fptr=process_ui_action, args=[action], description=desctription, icon=icon, action=action)

# Functions()
# Heads()
for n in Names():
    # jump to addr
    choices[n[1]] = Commands(fptr=jumpto, args=[n[0]], description="Jump to " + n[1], icon=-1)

for n in Structs():
    choices[n[2]] = Commands(fptr=open_structs_window, args=[n[1]], description="Jump to Structure definition of " + n[2], icon=52)


names = []
for k, v in choices.items():
    names.append(k)


class EmbeddedChooserClass(Choose):
    """
    A simple chooser to be used as an embedded chooser
    """

    def __init__(self, title, nb=5, flags=0):
        Choose.__init__(self,
                        title,
                        [["Action", 30 | Choose.CHCOL_PLAIN]],
                        embedded=True, height=10, flags=flags)
        # embedded=True, width=30, height=20, flags=flags)

        self.n = 0
        self.items = []
        self.icon = 0

    def OnGetIcon(self, n):
        # print("get icon %d" % n)
        return choices[self.items[n][0]].get_icon()

    def OnSelectionChange(self, n):
        pass
        # print("selection change %d" % n)

    def OnClose(self):
        pass

    def OnGetLine(self, n):
        # print("getline %d" % n)
        return self.items[n]

    def OnGetSize(self):
        n = len(self.items)
        # print("getsize -> %d" % n)
        return n


# --------------------------------------------------------------------------
class FuzzySearchForm(Form):
    def __init__(self):
        self.invert = False
        self.EChooser = EmbeddedChooserClass("Title", flags=Choose.CH_MODAL)
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
            # initialize
            pass
        elif fid == -2:
            # terminate
            pass
        elif fid == self.cEChooser.id:
            self.selected_id = self.GetControlValue(self.cEChooser)[0]
        elif fid == self.iStr1.id:
            s = self.GetControlValue(self.iStr1)
            self.EChooser.items = []
            if s == '':
                self.RefreshField(self.cEChooser)
                return 1
            extracts = process.extract(s, names, limit=10)  # f.iStr1.value won't change until Form.Execute() returns.
            for ex in extracts:
                print(choices[ex[0]].action)
                print(get_action_state(choices[ex[0]].action))
                if choices[ex[0]].type == "ACTION" and get_action_state(choices[ex[0]].action)[1] > idaapi.AST_ENABLE:
                    continue
                self.EChooser.items.append([ex[0], choices[ex[0]].description])
            self.RefreshField(self.cEChooser)
            # print("Extract : " + str(extracts))
            self.SetControlValue(self.cEChooser,[0])
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

    if ok == 1 and len(f.EChooser.items) > 0:
        f.get_selected_item().execute()
    # Dispose the form
    f.Free()

class fuzzy_search_handler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        action = fuzzy_search_main()

        if action:
            idaapi.process_ui_action(action)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class FuzzySearchPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_FIX | idaapi.PLUGIN_HIDE
    comment = "Fuzzy search everything for IDA"
    help = "Fuzzy search everything"
    wanted_name = "fuzzy search"
    wanted_hotkey = ""

    def init(self):
        print("Fuzzy Search Plugin loaded.")
        idaapi.register_action(idaapi.action_desc_t("fz:fuzzysearch", "Fuzzy Search", fuzzy_search_handler(), "Shift+SPACE", "", -1))

        return idaapi.PLUGIN_KEEP

    def term(self):
        idaapi.unregister_action("fz:fuzzysearch")
        pass

    def run(self, arg):
        pass


def PLUGIN_ENTRY():
    return FuzzySearchPlugin()
