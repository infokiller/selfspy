# Copyright 2012 Bjarte Johansen

# This file is part of Selfspy

# Selfspy is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# Selfspy is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with Selfspy.  If not, see <http://www.gnu.org/licenses/>.

from Foundation import NSObject
from AppKit import NSApplication, NSApp, NSWorkspace
from Cocoa import (
    NSEvent, NSFlagsChanged,
    NSKeyDown, NSKeyUp, NSKeyDownMask, NSKeyUpMask,
    NSLeftMouseDown, NSLeftMouseUpMask, NSLeftMouseDownMask,
    NSRightMouseDown, NSRightMouseUpMask, NSRightMouseDownMask,
    NSMouseMoved, NSMouseMovedMask,
    NSScrollWheel, NSScrollWheelMask,
    NSFlagsChangedMask,
    NSAlternateKeyMask, NSCommandKeyMask, NSControlKeyMask,
    NSShiftKeyMask, NSAlphaShiftKeyMask,
    NSApplicationActivationPolicyProhibited
)
from Quartz import (
    CGWindowListCopyWindowInfo,
    kCGWindowListExcludeDesktopElements,
    kCGWindowListOptionOnScreenOnly,
    kCGNullWindowID
)
from PyObjCTools import AppHelper
from . import config as cfg
import signal
import time

FORCE_SCREEN_CHANGE = 10
WAIT_ANIMATION = 1

class Sniffer:
    def __init__(self):
        self.key_hook = lambda x: True
        self.mouse_button_hook = lambda x: True
        self.mouse_move_hook = lambda x: True
        self.screen_hook = lambda x: True
        self.last_check_windows = time.time()

    def createAppDelegate(self):
        sc = self

        class AppDelegate(NSObject):

            def applicationDidFinishLaunching_(self, notification):
                mask = (NSKeyDownMask
                        | NSKeyUpMask
                        | NSLeftMouseDownMask
                        | NSLeftMouseUpMask
                        | NSRightMouseDownMask
                        | NSRightMouseUpMask
                        | NSMouseMovedMask
                        | NSScrollWheelMask
                        | NSFlagsChangedMask)
                NSEvent.addGlobalMonitorForEventsMatchingMask_handler_(mask, sc.handler)

            def applicationWillResignActive(self, notification):
                self.applicationWillTerminate_(notification)
                return True

            def applicationShouldTerminate_(self, notification):
                self.applicationWillTerminate_(notification)
                return True

            def applicationWillTerminate_(self, notification):
                # need to release the lock here as when the
                # application terminates it does not run the rest the
                # original main, only the code that has crossed the
                # pyobc bridge.
                if cfg.LOCK.is_locked():
                    cfg.LOCK.release()
                print("Exiting")
                return None

        return AppDelegate

    def run(self):
        NSApplication.sharedApplication()
        delegate = self.createAppDelegate().alloc().init()
        NSApp().setDelegate_(delegate)
        NSApp().setActivationPolicy_(NSApplicationActivationPolicyProhibited)
        self.workspace = NSWorkspace.sharedWorkspace()

        def handler(signal, frame):
            AppHelper.stopEventLoop()
        signal.signal(signal.SIGINT, handler)
        AppHelper.runEventLoop()

    def cancel(self):
        AppHelper.stopEventLoop()

    def handler(self, event):
        try:
            check_windows = False
            event_type = event.type()
            todo = lambda: None
            if (
                time.time() - self.last_check_windows > FORCE_SCREEN_CHANGE and
                event_type != NSKeyUp
            ):
                self.last_check_windows = time.time()
                check_windows = True
            loc = NSEvent.mouseLocation()
            if event_type == NSLeftMouseDown:
                check_windows = True
                todo = lambda: self.mouse_button_hook(1, loc.x, loc.y)
            elif event_type == NSRightMouseDown:
                check_windows = True
                todo = lambda: self.mouse_button_hook(3, loc.x, loc.y)
            elif event_type == NSScrollWheel:
                if event.deltaY() > 0:
                    todo = lambda: self.mouse_button_hook(4, loc.x, loc.y)
                elif event.deltaY() < 0:
                    todo = lambda: self.mouse_button_hook(5, loc.x, loc.y)
                if event.deltaX() > 0:
                    todo = lambda: self.mouse_button_hook(6, loc.x, loc.y)
                elif event.deltaX() < 0:
                    todo = lambda: self.mouse_button_hook(7, loc.x, loc.y)
            elif event_type == NSKeyDown:
                flags = event.modifierFlags()
                modifiers = []  # OS X api doesn't care it if is left or right
                if flags & NSControlKeyMask:
                    modifiers.append('Ctrl')
                if flags & NSAlternateKeyMask:
                    modifiers.append('Alt')
                if flags & NSCommandKeyMask:
                    modifiers.append('Cmd')
                if flags & (NSShiftKeyMask | NSAlphaShiftKeyMask):
                    modifiers.append('Shift')
                character = event.charactersIgnoringModifiers()
                # these two get a special case because I am unsure of
                # their unicode value
                if event.keyCode() == 36:
                    character = "Enter"
                elif event.keyCode() == 51:
                    character = "Backspace"
                todo = lambda: self.key_hook(event.keyCode(),
                              modifiers,
                              keycodes.get(character,
                                           character),
                              event.isARepeat())
            elif event_type == NSMouseMoved:
                todo = lambda: self.mouse_move_hook(loc.x, loc.y)
            elif event_type == NSFlagsChanged:
                # Register leaving this window after animations are done
                # approx (1 second)
                self.last_check_windows = (time.time() - FORCE_SCREEN_CHANGE +
                                           WAIT_ANIMATION)
                check_windows = True
            if check_windows:
                activeApps = self.workspace.runningApplications()
                for app in activeApps:
                    if app.isActive():
                        app_name = app.localizedName()
                        options = kCGWindowListOptionOnScreenOnly | kCGWindowListExcludeDesktopElements
                        windowList = CGWindowListCopyWindowInfo(options,
                                                                kCGNullWindowID)
                        windowListLowPrio = [
                            w for w in windowList
                            if w['kCGWindowLayer'] or not w.get('kCGWindowName', '')
                        ]
                        windowList = [
                            w for w in windowList
                            if not w['kCGWindowLayer'] and w.get('kCGWindowName', '')
                        ]
                        windowList = windowList + windowListLowPrio
                        for window in windowList:
                            if window['kCGWindowOwnerName'] == app_name:
                                geometry = window['kCGWindowBounds']
                                self.screen_hook(window['kCGWindowOwnerName'],
                                                 window.get('kCGWindowName', ''),
                                                 geometry['X'],
                                                 geometry['Y'],
                                                 geometry['Width'],
                                                 geometry['Height'])
                                break
                        break
            todo()
        except (SystemExit, KeyboardInterrupt):
            AppHelper.stopEventLoop()
            return
        except:
            AppHelper.stopEventLoop()
            raise

# Cocoa does not provide a good api to get the keycodes, therefore we
# have to provide our own.
keycodes = {
    "\u0009": "Tab",
    "\u001b": "Escape",
    "\uf700": "Up",
    "\uF701": "Down",
    "\uF702": "Left",
    "\uF703": "Right",
    "\uF704": "F1",
    "\uF705": "F2",
    "\uF706": "F3",
    "\uF707": "F4",
    "\uF708": "F5",
    "\uF709": "F6",
    "\uF70A": "F7",
    "\uF70B": "F8",
    "\uF70C": "F9",
    "\uF70D": "F10",
    "\uF70E": "F11",
    "\uF70F": "F12",
    "\uF710": "F13",
    "\uF711": "F14",
    "\uF712": "F15",
    "\uF713": "F16",
    "\uF714": "F17",
    "\uF715": "F18",
    "\uF716": "F19",
    "\uF717": "F20",
    "\uF718": "F21",
    "\uF719": "F22",
    "\uF71A": "F23",
    "\uF71B": "F24",
    "\uF71C": "F25",
    "\uF71D": "F26",
    "\uF71E": "F27",
    "\uF71F": "F28",
    "\uF720": "F29",
    "\uF721": "F30",
    "\uF722": "F31",
    "\uF723": "F32",
    "\uF724": "F33",
    "\uF725": "F34",
    "\uF726": "F35",
    "\uF727": "Insert",
    "\uF728": "Delete",
    "\uF729": "Home",
    "\uF72A": "Begin",
    "\uF72B": "End",
    "\uF72C": "PageUp",
    "\uF72D": "PageDown",
    "\uF72E": "PrintScreen",
    "\uF72F": "ScrollLock",
    "\uF730": "Pause",
    "\uF731": "SysReq",
    "\uF732": "Break",
    "\uF733": "Reset",
    "\uF734": "Stop",
    "\uF735": "Menu",
    "\uF736": "User",
    "\uF737": "System",
    "\uF738": "Print",
    "\uF739": "ClearLine",
    "\uF73A": "ClearDisplay",
    "\uF73B": "InsertLine",
    "\uF73C": "DeleteLine",
    "\uF73D": "InsertChar",
    "\uF73E": "DeleteChar",
    "\uF73F": "Prev",
    "\uF740": "Next",
    "\uF741": "Select",
    "\uF742": "Execute",
    "\uF743": "Undo",
    "\uF744": "Redo",
    "\uF745": "Find",
    "\uF746": "Help",
    "\uF747": "ModeSwitch"
}
